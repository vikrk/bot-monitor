#!/usr/bin/python3
"""Dynamic inventory and bounded RPC for the installable control bot."""
import json
import base64
import fcntl
import os
import re
import subprocess
import time
from pathlib import Path

ROOT = Path('/etc/rvkomi-watchdog')
BASE = Path('/usr/local/lib/rvkomi-watchdog')
STATE = Path('/var/lib/rvkomi-watchdog')
CONFIG = ROOT / 'fleet.json'
ID = re.compile(r'^[a-z][a-z0-9_]{0,23}$')
ACTIONS = {'status', 'check', 'extras', 'certs', 'logs'}


def enabled():
    return CONFIG.is_file()


def load():
    data = json.loads(CONFIG.read_text(encoding='utf-8'))
    if data.get('version') != 1 or not isinstance(data.get('nodes'), dict):
        raise ValueError('Неверный формат fleet.json')
    for identifier, node in data['nodes'].items():
        if not ID.fullmatch(identifier) or not isinstance(node, dict):
            raise ValueError('Неверная запись узла')
    return data


def save(data):
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    temp = CONFIG.with_suffix('.json.tmp')
    with temp.open('w', encoding='utf-8') as out:
        os.chmod(temp, 0o600)
        json.dump(data, out, ensure_ascii=False, indent=2)
        out.write('\n')
        out.flush()
        os.fsync(out.fileno())
    os.replace(temp, CONFIG)


def nodes():
    return {key: node for key, node in load()['nodes'].items() if node.get('enabled', True)}


def label(identifier):
    return nodes().get(identifier, {}).get('name', identifier)


def allowed_action(node, action):
    if action == 'discover':
        return node.get('transport') in ('local', 'ssh-agent')
    if action == 'admin':
        return node.get('transport') in ('local', 'ssh-agent')
    if action in ACTIONS:
        return True
    if action.startswith('querylog ') and re.fullmatch(r'[0-9a-f]{16}', action[9:]):
        return node.get('transport') != 'ssh-shell'
    if action.startswith('restart '):
        return action[8:] in node.get('profile', {}).get('allowed_restarts', [])
    if action.startswith('configure ') and len(action) <= 48010 and re.fullmatch(r'[A-Za-z0-9_=-]+', action[10:]):
        return node.get('transport') in ('local', 'ssh-agent')
    return False


def rpc(identifier, action, payload=None):
    node = nodes()[identifier]
    if not allowed_action(node, action):
        raise ValueError('Действие не разрешено профилем узла')
    transport = node['transport']
    if transport == 'local':
        argv = ['/usr/bin/python3', str(BASE / 'node_agent.py'), '--profile', str(ROOT / 'main-profile.json'), *action.split()]
    else:
        argv = ['ssh', '-4', '-T', '-F', '/dev/null', '-p', str(node.get('port', 22)),
                '-i', node['key'], '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
                '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + node['known_hosts'],
                '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'PasswordAuthentication=no',
                '-o', 'ConnectTimeout=8', '-o', 'ServerAliveInterval=10', '-o', 'ServerAliveCountMax=2',
                node['user'] + '@' + node['address'], action]
    if action == 'admin':
        if not isinstance(payload, dict) or (payload != {'op': 'describe'} and
                (set(payload) != {'op', 'plan'} or payload.get('op') != 'apply')):
            raise ValueError('Invalid admin RPC request')
        encoded = json.dumps(payload)
        if len(encoded.encode('utf-8')) > 16000: raise ValueError('Admin request too large')
        result = subprocess.run(argv, input=encoded, capture_output=True, text=True, timeout=450)
    else:
        if payload is not None: raise ValueError('Unexpected RPC payload')
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=180)
    if result.returncode:
        raise RuntimeError('SSH/RPC не ответил корректно')
    if transport == 'ssh-shell':
        return shell_result(result.stdout, action)
    data = json.loads(result.stdout)
    if not isinstance(data, dict) or (action != 'admin' and data.get('error') and not data.get('last_check')):
        raise RuntimeError('Агент отклонил запрос')
    return data


def rescan(identifier):
    """Add installed services without changing routes or administration permissions."""
    from node_agent import validate_profile, DISCOVERY_SERVICES
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (STATE / 'fleet-rescan.lock').open('a+') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        data = load()
        node = data['nodes'][identifier]
        if not node.get('enabled', True) or node['transport'] not in ('local', 'ssh-agent'):
            raise ValueError('Пересканирование доступно только для Linux-узлов с актуальным агентом')
        discovery = rpc(identifier, 'discover')
        discovered = discovery.get('services')
        if not isinstance(discovered, list) or any(s not in DISCOVERY_SERVICES for s in discovered):
            raise ValueError('Неверный ответ обнаружения служб')
        profile = json.loads(json.dumps(node.get('profile', {})))
        old = profile.get('services', [])
        added = [s for s in dict.fromkeys(discovered) if s not in old]
        profile['services'] = old + added
        added_probes = 0
        for field in ('tls', 'urls', 'dns_routes'):
            for item in discovery.get(field, []):
                if not isinstance(item, dict) or not str(item.get('discovery_id', '')).startswith('auto:'):
                    raise ValueError('Invalid discovered probe')
                current = profile.setdefault(field, [])
                index = next((i for i, old_item in enumerate(current) if old_item.get('discovery_id') == item['discovery_id']), None)
                if index is not None: current[index] = item
                elif (field == 'dns_routes' and len(current) < 32) or (field != 'dns_routes' and len(profile.get('urls', [])) + len(profile.get('tls', [])) < 24):
                    current.append(item); added_probes += 1
        profile['discovered_components'] = discovery.get('components', [])
        profile['discovered_domains'] = discovery.get('domains', [])
        profile['discovery_notes'] = discovery.get('notes', [])
        validate_profile(profile)
        if profile != node.get('profile', {}):
            encoded = base64.urlsafe_b64encode(json.dumps(profile).encode()).decode()
            if not rpc(identifier, 'configure ' + encoded).get('configured'):
                raise RuntimeError('Агент не сохранил профиль')
            node['profile'] = profile
            save(data)
        return {'services': profile['services'], 'added': added, 'added_probes': added_probes,
                'components': profile['discovered_components'], 'notes': profile['discovery_notes']}


def shell_result(text, action):
    if not text.startswith('RVK_ROUTER_V1\n'):
        raise RuntimeError('Неверный ответ POSIX-роутера')
    parts = text.split('\nSECTION:')
    sections = {}
    for part in parts[1:]:
        name, _, value = part.partition('\n')
        sections[name.strip()] = value.strip()
    memory = {}
    for line in sections.get('memory', '').splitlines():
        key, _, value = line.partition(':')
        try: memory[key] = int(value.strip().split()[0]) // 1024
        except (ValueError, IndexError): pass
    disk = sections.get('disk', '').splitlines()
    try:
        row = disk[-1].split()
        free = int(row[3]) / 1048576
        used = float(row[4].rstrip('%'))
    except (ValueError, IndexError):
        free, used = None, None
    try: loadavg = [float(n) for n in sections.get('load', '').split()[:3]]
    except ValueError: loadavg = []
    metrics = {'services': {}, 'disk_free_gb': free, 'disk_used_percent': used,
               'memory_available_mb': memory.get('MemAvailable', memory.get('MemFree')),
               'memory_total_mb': memory.get('MemTotal'), 'load': loadavg, 'cpu_count': None}
    if action == 'extras': return metrics
    failures = []
    if free is not None and free < 0.25: failures.append('disk-space-low')
    return {'last_check': time.time(), 'failures': failures, 'services': {}, 'read_only': True,
            'report': {'services': {}, 'basics': {'ssh': {'ok': True}}, 'notes': [
                'POSIX SSH-роутер: проверены доступ, ресурсы и диск. Python-профили маршрутов на нём не включены.']},
            'resources': metrics}


def check(identifier):
    try:
        result = rpc(identifier, 'check')
    except Exception as exc:
        result = {'last_check': time.time(), 'read_only': True, 'services': {},
                  'failures': ['ssh-or-check-unavailable'], 'error_type': type(exc).__name__,
                  'error': 'SSH/RPC check unavailable'}
    if result.get('skipped'):
        return result
    profile = nodes()[identifier].get('profile', {})
    routes = profile.get('dns_routes', [])
    results = result.get('dns_results', {})
    for route in routes:
        item = results.get(route['id'])
        if not item or not route.get('querylog_node'): continue
        names = set(item.get('probe_names', []))
        arrived = set()
        for attempt in range(route.get('log_wait_seconds', 25) + 1):
            try:
                target = identifier if route['querylog_node'] == 'self' else route['querylog_node']
                arrived = set(rpc(target, 'querylog ' + item['probe_token']).get('names', [])) & names
            except Exception:
                item['log_error'] = 'Журнал AdGuard недоступен'
                break
            if len(arrived) == len(names): break
            if attempt < route.get('log_wait_seconds', 25): time.sleep(1)
        item['arrived'] = len(arrived)
        item['ok'] = item.get('responses', 0) == len(names) and len(arrived) == len(names)
        group = result.setdefault('report', {}).setdefault('groups', {})
        group[route['label']] = {str(i): {'ok': name in arrived} for i, name in enumerate(item.get('probe_names', []))}
        if not item['ok'] and route['label'] not in result.setdefault('failures', []):
            result['failures'].append(route['label'])
        result['report'].setdefault('notes', []).append(route['label'] + ': ответы ' + str(item.get('responses', 0)) +
            '/' + str(len(names)) + '; дошли до AdGuard по журналу ' + str(len(arrived)) + '/' + str(len(names)))
    directory = STATE / 'fleet-results'
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    destination = directory / (identifier + '.json')
    temporary = directory / (identifier + '.' + str(os.getpid()) + '.' + str(time.time_ns()) + '.tmp')
    with (directory / (identifier + '.lock')).open('a+') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try: previous = json.loads(destination.read_text(encoding='utf-8'))
        except (OSError, ValueError): previous = {}
        if (result.get('last_check') or 0) >= (previous.get('last_check') or 0):
            temporary.write_text(json.dumps(result, ensure_ascii=False), encoding='utf-8')
            temporary.chmod(0o600)
            temporary.replace(destination)
    return result


def status(identifier):
    # Cached checks supplement a reachable agent; they cannot prove connectivity.
    response = rpc(identifier, 'status')
    try:
        previous = json.loads((STATE / 'fleet-results' / (identifier + '.json')).read_text(encoding='utf-8'))
        if previous.get('last_check', 0) > (response.get('last_check') or 0):
            return previous
    except (OSError, ValueError): pass
    return response
