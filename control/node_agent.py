#!/usr/bin/python3
"""On-demand node probes. The SSH key can invoke only this bounded protocol."""
import argparse
import fcntl
import base64
import hashlib
import concurrent.futures
import json
import os
import re
import secrets
import shlex
import shutil
import socket
import ssl
import struct
import subprocess
import tempfile
import sys
import time
import urllib.request
import urllib.error
from urllib.parse import urlsplit
from pathlib import Path


DISCOVERY_SERVICES = ('rvkomi-telegram-control', 'ssh', 'nginx', 'docker', 'x-ui', '3x-ui', 'xray', 'AdGuardHome')


def discover_services():
    services = []
    for service in DISCOVERY_SERVICES:
        probe = run(['systemctl', 'show', '-p', 'LoadState', '--value', service], 8)
        if probe.returncode == 0 and probe.stdout.strip() == 'loaded':
            services.append(service)
    return services


def validate_profile(profile):
    if not isinstance(profile, dict): raise ValueError('Invalid profile')
    from portable_admin import validate_policy
    validate_policy(profile.get('ai_admin', {}))
    if type(profile.get('scheduled_status_only', False)) is not bool:
        raise ValueError('Invalid scheduled checker mode')
    for field in ('services', 'allowed_restarts'):
        items = profile.get(field, [])
        if not isinstance(items, list) or len(items) > 32 or any(not isinstance(s, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.@-]{0,100}', s) for s in items):
            raise ValueError('Invalid service list')
    if not set(profile.get('allowed_restarts', [])) <= set(profile.get('services', [])):
        raise ValueError('Restart must refer to a monitored service')
    for service in profile.get('allowed_restarts', []):
        name = re.sub(r'\.(?:service|target)$', '', service.lower())
        name = name.removeprefix('systemd-')
        if name in {'reboot', 'poweroff', 'halt', 'shutdown', 'kexec', 'suspend', 'hibernate',
                    'hybrid-sleep', 'suspend-then-hibernate'}:
            raise ValueError('OS power operations are not allowed as service repairs')
    for field in ('urls', 'tls', 'dns_routes'):
        if not isinstance(profile.get(field, []), list) or len(profile.get(field, [])) > 32: raise ValueError('Too many probes')
    if len(profile.get('urls', [])) + len(profile.get('tls', [])) > 24: raise ValueError('Limit: 24 HTTP/TLS probes')
    if sum(item.get('count', 1) for item in profile.get('dns_routes', []) if isinstance(item, dict) and isinstance(item.get('count', 1), int)) > 128:
        raise ValueError('Limit: 128 DNS queries per check')
    for item in profile.get('urls', []) + profile.get('tls', []) + profile.get('dns_routes', []):
        if not isinstance(item, dict) or not isinstance(item.get('label'), str) or not 1 <= len(item['label']) <= 80:
            raise ValueError('Invalid probe label')
        if 'url' in item or 'endpoint' in item:
            parsed = urlsplit(item.get('url', item.get('endpoint')))
            if parsed.scheme not in ('https', 'http') or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
                raise ValueError('Invalid URL')
        if 'host' in item and (not isinstance(item['host'], str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,253}', item['host'])):
            raise ValueError('Invalid host')
        if 'port' in item and (not isinstance(item['port'], int) or not 1 <= item['port'] <= 65535): raise ValueError('Invalid port')
    for item in profile.get('dns_routes', []):
        if item.get('transport') not in ('doh', 'dot', 'udp') or not re.fullmatch(r'[a-z0-9_]{1,24}', item.get('id', '')):
            raise ValueError('Invalid DNS route')
        if not isinstance(item.get('count', 1), int) or not 1 <= item.get('count', 1) <= 64: raise ValueError('Invalid DNS count')
        if item['transport'] == 'doh' and urlsplit(item.get('endpoint', '')).scheme != 'https': raise ValueError('DoH requires HTTPS')
        if item['transport'] != 'doh' and not item.get('host'): raise ValueError('DNS host is required')
        if not isinstance(item.get('log_wait_seconds', 25), int) or not 0 <= item.get('log_wait_seconds', 25) <= 120:
            raise ValueError('Invalid querylog wait')
    if 'querylog_path' in profile:
        path = Path(profile['querylog_path'])
        if not path.is_absolute() or '..' in path.parts or path.suffix not in ('.json', '.jsonl'):
            raise ValueError('Querylog must be an absolute JSON/JSONL path')
    if not isinstance(profile.get('disk_min_gb', 1), (int, float)) or not 0 <= profile.get('disk_min_gb', 1) <= 10000:
        raise ValueError('Invalid disk threshold')
    return profile


def run(args, timeout=12):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)


def service_states(profile):
    def one(service):
        try: return service, run(['systemctl', 'is-active', '--quiet', service], 3).returncode == 0
        except Exception: return service, False
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        return dict(pool.map(one, profile.get('services', [])))


def resources(profile):
    memory = {}
    try:
        for line in Path('/proc/meminfo').read_text().splitlines():
            key, value = line.split(':', 1)
            memory[key] = int(value.strip().split()[0]) // 1024
    except (OSError, ValueError): pass
    disk = shutil.disk_usage('/')
    return {'services': service_states(profile), 'load': list(os.getloadavg()), 'cpu_count': os.cpu_count() or 1,
            'disk_free_gb': round(disk.free / 1024**3, 2), 'disk_used_percent': round(disk.used / disk.total * 100, 1),
            'memory_available_mb': memory.get('MemAvailable', memory.get('MemFree', 0)),
            'memory_total_mb': memory.get('MemTotal', 0),
            'swap_used_mb': memory.get('SwapTotal', 0) - memory.get('SwapFree', 0)}


def tls_probe(item):
    context = ssl.create_default_context()
    context.set_alpn_protocols(['h2', 'http/1.1'])
    with socket.create_connection((item['host'], int(item.get('port', 443))), timeout=8) as connection:
        with context.wrap_socket(connection, server_hostname=item.get('server_name') or item['host']) as secure:
            cert = secure.getpeercert()
            days = (ssl.cert_time_to_seconds(cert['notAfter']) - time.time()) / 86400
            return {'ok': days > 0, 'tls': secure.version(), 'alpn': secure.selected_alpn_protocol(),
                    'fingerprint': hashlib.sha256(secure.getpeercert(binary_form=True)).hexdigest(),
                    'cert_days_remaining': round(days, 1), 'host': item['host'], 'port': int(item.get('port', 443)),
                    'label': item['label']}


def http_probe(item):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(urllib.request.Request(item['url'], headers={'User-Agent': 'RVKOMI-monitor/1'}), timeout=10) as response:
            response.read(1024)
            return {'ok': response.status in item.get('codes', [200]), 'http_status': response.status}
    except urllib.error.HTTPError as error:
        return {'ok': error.code in item.get('codes', [200]), 'http_status': error.code}


def packet(name):
    identifier = secrets.randbelow(65536)
    wire = b''.join(bytes([len(part)]) + part.encode('ascii') for part in name.split('.')) + b'\0'
    return identifier, struct.pack('!HHHHHH', identifier, 0x0100, 1, 0, 0, 0) + wire + struct.pack('!HH', 1, 1)


def receive_exact(sock, count):
    out = b''
    while len(out) < count:
        chunk = sock.recv(count - len(out))
        if not chunk: raise RuntimeError('DNS response ended early')
        out += chunk
    return out


def dns_question(wire):
    cursor, labels, seen = 12, [], set()
    question_end = None
    while True:
        if cursor >= len(wire) or cursor in seen or len(seen) > 128: raise ValueError('Invalid DNS question')
        seen.add(cursor)
        size = wire[cursor]
        cursor += 1
        if size & 0xC0 == 0xC0:
            if cursor >= len(wire): raise ValueError('Invalid DNS pointer')
            if question_end is None: question_end = cursor + 1
            cursor = ((size & 0x3F) << 8) | wire[cursor]
            continue
        if size > 63: raise ValueError('Invalid DNS label')
        if size == 0:
            if question_end is None: question_end = cursor
            break
        if cursor + size > len(wire): raise ValueError('Truncated DNS label')
        labels.append(wire[cursor:cursor + size].decode('ascii').lower())
        cursor += size
    if question_end + 4 > len(wire): raise ValueError('Truncated DNS question')
    kind, category = struct.unpack('!HH', wire[question_end:question_end + 4])
    return '.'.join(labels), kind, category


def dns_probe(route, name):
    identifier, request = packet(name)
    if route['transport'] == 'doh':
        req = urllib.request.Request(route['endpoint'], data=request,
            headers={'Content-Type': 'application/dns-message', 'Accept': 'application/dns-message'})
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(req, timeout=8) as response:
            if response.status != 200: return False
            reply = response.read(65536)
    elif route['transport'] == 'dot':
        with socket.create_connection((route['host'], int(route.get('port', 853))), timeout=8) as raw:
            with ssl.create_default_context().wrap_socket(raw, server_hostname=route.get('server_name') or route['host']) as secure:
                secure.sendall(struct.pack('!H', len(request)) + request)
                count = struct.unpack('!H', receive_exact(secure, 2))[0]
                reply = receive_exact(secure, count)
    else:
        infos = socket.getaddrinfo(route['host'], int(route.get('port', 53)), type=socket.SOCK_DGRAM)
        family, kind, proto, _, address = infos[0]
        with socket.socket(family, kind, proto) as sock:
            sock.settimeout(8)
            sock.connect(address)
            sock.send(request)
            reply = sock.recv(65536)
    if len(reply) < 12: return False
    rid, flags, questions = struct.unpack('!HHH', reply[:6])
    # Unique monitoring names can legitimately return NXDOMAIN.
    if rid != identifier or not flags & 0x8000 or flags & 0x7800 or flags & 15 not in (0, 3) or questions != 1:
        return False
    try: return dns_question(reply) == (name.lower(), 1, 1)
    except ValueError: return False


def querylog(profile, token):
    path = profile.get('querylog_path')
    if not path: raise RuntimeError('AdGuard querylog path is not configured')
    with open(path, 'rb') as source:
        source.seek(0, 2)
        source.seek(max(0, source.tell() - 2 * 1024 * 1024))
        text = source.read().decode('utf-8', 'replace')
    pattern = r'rvkomi-' + re.escape(token) + r'-[0-9]+\.example\.com'
    records = []
    try:
        parsed = json.loads(text)
        if isinstance(parsed, list): records = parsed
        elif isinstance(parsed, dict): records = parsed.get('data', [parsed])
    except ValueError:
        for line in text.splitlines():
            try: records.append(json.loads(line))
            except ValueError: pass
    names = set()
    for record in records:
        if not isinstance(record, dict): continue
        question = record.get('question', {})
        name = record.get('QH') or (question.get('name', '') if isinstance(question, dict) else '')
        if isinstance(name, str) and re.fullmatch(pattern, name.rstrip('.').lower()): names.add(name.rstrip('.').lower())
    # Only query domains for this nonce leave the node, never unrelated client queries.
    return {'names': sorted(names)}


def check(profile):
    # The SNI executor updates a separate, root-provisioned postcheck domain list.
    sni = profile.get('ai_admin', {}).get('sni')
    if sni:
        probe_file = Path(profile.get('_profile_path', '')).with_name('ai-sni-probes.json')
        values = json.loads(probe_file.read_text())['sni_relay_checks']['domains']
        if len(values) > 30 or any(not re.fullmatch(r'(?:[a-z0-9-]+\.)+[a-z0-9-]+', d) for d in values):
            raise ValueError('Invalid SNI postcheck domain list')
        profile = json.loads(json.dumps(profile))
        for domain in values:
            profile.setdefault('tls', []).append({'label': 'SNI ' + domain, 'host': sni['relay_ip'],
                'port': sni.get('port', 443), 'server_name': domain})
    metrics = resources(profile)
    services = metrics['services']
    failures = [name for name, ok in services.items() if not ok]
    report = {'services': services, 'basics': {'disk': {'ok': metrics['disk_free_gb'] >= profile.get('disk_min_gb', 1),
              'free_mb': int(metrics['disk_free_gb'] * 1024)}}, 'groups': {}, 'cdn_tls': {}, 'notes': []}
    if not report['basics']['disk']['ok']: failures.append('disk-space-low')
    def network_probe(task):
        kind, item = task
        try: outcome = http_probe(item) if kind == 'http' else tls_probe(item)
        except Exception as exc:
            import history_diagnostics
            outcome = {'ok': False, 'label': item['label'], 'host': item.get('host', ''),
                       'error': type(exc).__name__, 'error_detail': history_diagnostics.text(str(exc))}
            if isinstance(exc, urllib.error.HTTPError): outcome['http_status'] = exc.code
            if isinstance(exc, OSError) and exc.errno is not None: outcome['exit_code'] = exc.errno
        return kind, item, outcome
    tasks = [('http', item) for item in profile.get('urls', [])] + [('tls', item) for item in profile.get('tls', [])]
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        for kind, item, outcome in pool.map(network_probe, tasks):
            if kind == 'http': report['groups'].setdefault('HTTP(S)', {})[item['label']] = outcome
            else: report['cdn_tls'][item['label']] = outcome
            if not outcome['ok']: failures.append(kind + ':' + item['label'])
    dns_results = {}
    def dns_route(route):
        token = secrets.token_hex(8)
        names = ['rvkomi-' + token + '-' + str(i) + '.example.com' for i in range(route.get('count', 1))]
        def one(name):
            try: return dns_probe(route, name)
            except Exception: return False
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            outcomes = list(pool.map(one, names))
        replies = sum(outcomes)
        item = {'responses': replies, 'expected': len(names), 'ok': replies == len(names),
                'probe_token': token, 'probe_names': names}
        return route, item, outcomes
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        for route, item, outcomes in pool.map(dns_route, profile.get('dns_routes', [])):
            dns_results[route['id']] = item
            report['groups'][route['label']] = {str(i): {'ok': ok} for i, ok in enumerate(outcomes)}
            if not item['ok']: failures.append(route['label'])
            if not route.get('querylog_node'):
                report['notes'].append(route['label'] + ': ответы ' + str(item['responses']) + '/' + str(item['expected']) +
                    '; подтверждение прихода в журнал AdGuard не настроено.')
    return {'last_check': time.time(), 'services': services, 'failures': failures, 'read_only': True,
            'report': report, 'resources': metrics, 'dns_results': dns_results}


def atomic_result(path, result):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name, dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            os.fchmod(handle.fileno(), 0o600)
            json.dump(result, handle, ensure_ascii=False)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)


def completed_check(profile, profile_path, cache):
    snapshot = profile_path.with_name('read-only-check.json')
    with profile_path.with_name('check.lock').open('a+') as lock:
        try: fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError: return {'skipped': 'running', 'read_only': True}
        try:
            result = check(profile)
        except Exception as exc:
            result = {'last_check': time.time(), 'read_only': True, 'services': {},
                      'failures': ['check-exception'], 'error_type': type(exc).__name__,
                      'error': 'The configured check could not complete'}
        if result.get('skipped'): return result
        result.setdefault('last_check', time.time())
        atomic_result(snapshot, result)
        if snapshot != cache: atomic_result(cache, result)
        history = profile_path.with_name('read-only-check.jsonl')
        cut = time.time() - 72 * 3600
        rows = []
        if history.exists():
            for line in history.read_text().splitlines():
                try:
                    old = json.loads(line)
                    if isinstance(old.get('last_check'), (int, float)) and old['last_check'] >= cut:
                        rows.append(old)
                except ValueError: pass
        rows.append(result)
        # Snapshots keep the entire last completed result; timestamped history expires at 72h.
        fd, temporary = tempfile.mkstemp(prefix='.read-only-check.', dir=profile_path.parent)
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as handle:
                os.fchmod(handle.fileno(), 0o600)
                for row in rows[-5000:]: handle.write(json.dumps(row, ensure_ascii=False) + '\n')
            os.replace(temporary, history)
        finally:
            if os.path.exists(temporary): os.unlink(temporary)
        return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--profile', default=str(Path(__file__).with_name('profile.json')))
    parser.add_argument('operation', nargs='*')
    args = parser.parse_args()
    profile_path = Path(args.profile)
    profile = validate_profile(json.loads(profile_path.read_text(encoding='utf-8')))
    profile['_profile_path'] = str(profile_path)
    words = shlex.split(os.environ['SSH_ORIGINAL_COMMAND']) if 'SSH_ORIGINAL_COMMAND' in os.environ else args.operation
    action = words[0] if words else ''
    cache = Path(profile.get('state_path', str(profile_path.with_name('last-check.json'))))
    if words == ['admin']:
        from portable_admin import handle
        raw = sys.stdin.buffer.read(16001)
        if len(raw) > 16000: raise ValueError('Admin request too large')
        result = handle(json.loads(raw), profile, profile_path)
    elif words == ['discover']:
        result = {'services': discover_services()}
    elif words == ['status']:
        candidates = []
        for path in (cache, profile_path.with_name('read-only-check.json')):
            try:
                previous = json.loads(path.read_text(encoding='utf-8'))
                if previous.get('last_check') and not previous.get('skipped'): candidates.append(previous)
            except (OSError, ValueError): pass
        result = max(candidates, key=lambda item: item['last_check']) if candidates else {
            'last_check': None, 'services': service_states(profile), 'failures': [], 'read_only': True}
    elif words == ['check']:
        result = completed_check(profile, profile_path, cache)
    elif words == ['extras']:
        result = resources(profile)
    elif words == ['certs']:
        items = []
        for item in profile.get('tls', []):
            try:
                outcome = tls_probe(item)
                items.append({'subject': item['label'], 'days': outcome['cert_days_remaining'], 'fingerprint': outcome['fingerprint']})
            except Exception: items.append({'subject': item['label'], 'days': 0, 'error': 'TLS unavailable'})
        result = {'certificates': items}
    elif words == ['logs']:
        logs = []
        for name in profile.get('services', []):
            try: logs.append({'service': name, 'text': run(['journalctl', '--no-pager', '-n', '40', '-u', name], 8).stdout[-12000:]})
            except Exception: logs.append({'service': name, 'text': 'Journal unavailable'})
        files = []
        if {'x-ui', 'xray'} & set(profile.get('services', [])):
            files += ['/var/log/xray/access.log', '/var/log/xray/error.log']
        if 'xray' in profile.get('services', []):
            files += ['/var/log/xray-standalone/access.log', '/var/log/xray-standalone/error.log']
        if 'nginx' in profile.get('services', []):
            files += ['/var/log/nginx/rvkomi-http.log', '/var/log/nginx/rvkomi-sni.log']
        for filename in files:
            if not Path(filename).is_file(): continue
            try: logs.append({'service': filename, 'text': run(['tail', '-n', '40', filename], 8).stdout[-12000:]})
            except Exception: logs.append({'service': filename, 'text': 'Diagnostic file unavailable'})
        result = {'logs': logs}
    elif len(words) == 2 and action == 'querylog' and re.fullmatch(r'[0-9a-f]{16}', words[1]):
        result = querylog(profile, words[1])
    elif len(words) == 2 and action == 'restart' and words[1] in profile.get('allowed_restarts', []):
        restart = run(['systemctl', 'restart', words[1]], 30)
        result = {'restarted': restart.returncode == 0, 'service': words[1]}
    elif len(words) == 2 and action == 'configure' and len(words[1]) <= 48000 and re.fullmatch(r'[A-Za-z0-9_=-]+', words[1]):
        updated = validate_profile(json.loads(base64.urlsafe_b64decode(words[1])))
        if updated.get('ai_admin', {}) != profile.get('ai_admin', {}):
            raise ValueError('AI capabilities must be provisioned through administrative SSH setup')
        if 'state_path' in profile: updated['state_path'] = profile['state_path']
        else: updated.pop('state_path', None)
        temporary = profile_path.with_suffix('.json.tmp')
        temporary.write_text(json.dumps(updated, ensure_ascii=False), encoding='utf-8')
        temporary.chmod(0o600)
        temporary.replace(profile_path)
        result = {'configured': True}
    else:
        raise ValueError('Action is not allowed')
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    try: main()
    except Exception as exc:
        print(json.dumps({'error': type(exc).__name__}))
        raise SystemExit(1)
