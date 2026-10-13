"""Read configured endpoints, returning no credentials, client lists or private keys."""
import hashlib
from contextlib import closing
import ipaddress
import json
from pathlib import Path
import re
import socket
import sqlite3
import ssl
import subprocess
import tempfile
import time
from urllib.parse import urlsplit


def domain(value):
    return isinstance(value, str) and bool(re.fullmatch(r'(?:[A-Za-z0-9-]+\.)+[A-Za-z0-9-]+', value))


def certificate(filename=None, pem=None):
    if pem:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as output:
            output.write('\n'.join(pem) if isinstance(pem, list) else pem)
            filename = output.name
        try: return certificate(filename)
        finally: Path(filename).unlink()
    if not filename or not Path(filename).is_file(): return {}
    cert = ssl._ssl._test_decode_cert(str(filename))
    names = [name for kind, name in cert.get('subjectAltName', []) if kind == 'DNS' and domain(name)]
    if not names:
        names = [v for row in cert.get('subject', []) for k, v in row if k == 'commonName' and domain(v)]
    return {'domains': list(dict.fromkeys(names))[:16], 'expires': cert.get('notAfter', '')}


def loopback(listen):
    if listen in ('', '0.0.0.0', None): return '127.0.0.1'
    if listen == '::': return '::1'
    return str(ipaddress.ip_address(listen))


def server_blocks(text):
    text = re.sub(r'(?m)#.*$', '', text)
    for match in re.finditer(r'\bserver\s*\{', text):
        start = match.end(); depth = 1
        for end in range(start, len(text)):
            depth += (text[end] == '{') - (text[end] == '}')
            if depth == 0:
                yield text[start:end]
                break


def discover():
    result = {'urls': [], 'tls': [], 'dns_routes': [], 'components': [], 'domains': [], 'notes': []}
    def endpoint(identity, label, listen, port, security, cert=None, server_name=None, path=None):
        port = int(port)
        if not 1 <= port <= 65535: raise ValueError('Invalid port')
        host = loopback(listen)
        cert = cert or {}
        names = cert.get('domains', [])
        name = server_name if domain(server_name) else next(iter(names), None)
        result['domains'].extend(names)
        if name: result['domains'].append(name)
        component = {'label': label[:80], 'host': host, 'port': port, 'security': security,
                     'server_name': name or '', 'expires': cert.get('expires', '')}
        result['components'].append(component)
        if security == 'tls' and name:
            result['tls'].append({'discovery_id': identity + ':tls', 'label': label[:65] + ' TLS',
                                  'host': host, 'port': port, 'server_name': name})
        elif security == 'tls':
            result['notes'].append(label + ': TLS настроен, имя сертификата не найдено; SNI задайте вручную.')
        if path is not None and (name or security == 'none'):
            if not isinstance(path, str) or not path.startswith('/') or any(c in path for c in '\r\n?#'):
                raise ValueError('Invalid HTTP path')
            target = name or host
            if ':' in target: target = '[' + target + ']'
            result['urls'].append({'discovery_id': identity + ':http', 'label': label[:65] + ' HTTP(S)',
                'url': ('https' if security == 'tls' else 'http') + '://' + target + ':' + str(port) + path,
                'codes': [200, 301, 302, 401, 403]})

    db = Path('/etc/x-ui/x-ui.db')
    if db.is_file():
        try:
            with closing(sqlite3.connect(db.resolve().as_uri() + '?mode=ro', uri=True, timeout=3)) as connection:
                allowed = ('webPort', 'webListen', 'webDomain', 'webCertFile', 'webKeyFile', 'webBasePath')
                values = dict(connection.execute('SELECT key,value FROM settings WHERE key IN (' + ','.join('?' for _ in allowed) + ')', allowed))
            cert = certificate(values.get('webCertFile'))
            # Respect the documented runtime port override without exposing other environment values.
            pid = subprocess.run(['systemctl', 'show', '-p', 'MainPID', '--value', 'x-ui'], capture_output=True, text=True, timeout=5).stdout.strip()
            if pid.isdigit() and pid != '0':
                try:
                    for value in Path('/proc', pid, 'environ').read_bytes().split(b'\0'):
                        if value.startswith(b'XUI_PORT='): values['webPort'] = value[9:].decode()
                except OSError: pass
            endpoint('auto:panel', '3x-ui панель', values.get('webListen'), values.get('webPort', 2053),
                'tls' if values.get('webCertFile') and values.get('webKeyFile') else 'none', cert,
                values.get('webDomain'), values.get('webBasePath', '/'))
        except Exception:
            result['notes'].append('3x-ui: настройки HTTPS/порта прочитать не удалось; профиль задайте вручную.')

    config = Path('/usr/local/x-ui/bin/config.json')
    if not config.is_file(): config = Path('/usr/local/etc/xray/config.json')
    if config.is_file():
        try:
            if config.stat().st_size > 2 * 1024 * 1024: raise ValueError('Config too large')
            data = json.loads(config.read_text())
            for index, inbound in enumerate(data.get('inbounds', [])[:32]):
                stream = inbound.get('streamSettings', {})
                security = stream.get('security', 'none')
                if security not in ('tls', 'reality'): continue
                try:
                    settings = stream.get('tlsSettings', {})
                    certificates = settings.get('certificates', [])
                    cert = certificate(certificates[0].get('certificateFile'), certificates[0].get('certificate')) if certificates else {}
                    endpoint('auto:xray:' + str(index), 'Xray вход ' + str(inbound['port']),
                        inbound.get('listen'), inbound['port'], security, cert, settings.get('serverName'))
                    if security == 'reality': result['notes'].append('Xray REALITY: обычная HTTPS-проверка и срок локального сертификата неприменимы.')
                except Exception: result['notes'].append('Xray: один TLS/REALITY-вход требует ручной настройки.')
            for index, server in enumerate(data.get('dns', {}).get('servers', [])[:16]):
                address = server.get('address') if isinstance(server, dict) else server
                add_dns(result, 'auto:xray-dns:' + str(index), address, server.get('port', 53) if isinstance(server, dict) else 53)
        except Exception: result['notes'].append('Xray: TLS/DNS-конфигурация не прочитана.')

    if Path('/usr/sbin/nginx').is_file():
        try:
            output = subprocess.run(['/usr/sbin/nginx', '-T'], capture_output=True, text=True, timeout=8)
            if output.returncode: raise ValueError('nginx config unavailable')
            for index, block in enumerate(server_blocks(output.stdout[:2 * 1024 * 1024])):
                names = re.search(r'\bserver_name\s+([^;]+);', block)
                name = next((n for n in names[1].split() if domain(n)), None) if names else None
                if not name: continue
                for listen in re.findall(r'\blisten\s+([^;]+);', block):
                    if 'ssl' not in listen.split(): continue
                    address = listen.split()[0]
                    port = int(address.rsplit(':', 1)[-1])
                    certpath = re.search(r'\bssl_certificate\s+([^;]+);', block)
                    cert = certificate(certpath[1].strip().strip('"\'')) if certpath else {}
                    host = address.rsplit(':', 1)[0].strip('[]') if ':' in address else '127.0.0.1'
                    endpoint('auto:nginx:' + str(index) + ':' + str(port), 'nginx ' + name,
                             host, port, 'tls', cert, name)
        except Exception: result['notes'].append('nginx: HTTPS-конфигурация требует ручной проверки.')

    for filename in ('/opt/AdGuardHome/AdGuardHome.yaml', '/etc/AdGuardHome.yaml', '/usr/local/AdGuardHome/AdGuardHome.yaml'):
        if not Path(filename).is_file(): continue
        try:
            import yaml
            if Path(filename).stat().st_size > 2 * 1024 * 1024: raise ValueError('Config too large')
            data = yaml.safe_load(Path(filename).read_text())
            dns = data.get('dns', {})
            for index, host in enumerate(dns.get('bind_hosts', ['127.0.0.1'])[:4]):
                add_dns(result, 'auto:adguard:' + str(index), loopback(host), dns.get('port', 53))
            for index, upstream in enumerate(dns.get('upstream_dns', [])[:12]):
                add_dns(result, 'auto:adguard-upstream:' + str(index), upstream)
            tls = data.get('tls', {})
            cert = {}
            if tls.get('enabled'):
                try: cert = certificate(tls.get('certificate_path'), tls.get('certificate_chain'))
                except Exception: result['notes'].append('AdGuard: файл сертификата не прочитан; TLS-имя взято из конфигурации, если задано.')
            tls_name = tls.get('server_name') or next(iter(cert.get('domains', [])), None)
            bind = loopback(next(iter(dns.get('bind_hosts') or ['127.0.0.1'])))
            if tls.get('enabled') and tls.get('port_https') and domain(tls_name):
                name = tls_name
                port = int(tls['port_https'])
                endpoint('auto:adguard-https', 'AdGuard HTTPS', bind, port, 'tls', cert, name)
                add_dns(result, 'auto:adguard-doh', 'https://' + name + ':' + str(port) + '/dns-query')
            if tls.get('enabled') and tls.get('port_dns_over_tls') and domain(tls_name):
                result['dns_routes'].append({'id': 'd_' + hashlib.sha256(filename.encode()).hexdigest()[:16],
                    'discovery_id': 'auto:adguard-dot', 'label': 'AdGuard DoT', 'transport': 'dot',
                    'host': bind, 'port': int(tls['port_dns_over_tls']), 'server_name': tls_name, 'count': 1})
                result['domains'].append(tls_name)
        except Exception: result['notes'].append('AdGuard: DNS-конфигурация требует ручной настройки.')
        break
    result['domains'] = list(dict.fromkeys(n for n in result['domains'] if domain(n)))[:24]
    for field in ('urls', 'tls', 'dns_routes', 'components', 'notes'): result[field] = result[field][:24]
    return result


def add_dns(result, identity, address, port=53):
    if not isinstance(address, str): return
    route = {'id': 'd_' + hashlib.sha256(identity.encode()).hexdigest()[:16], 'discovery_id': identity,
             'label': 'DNS ' + identity.removeprefix('auto:')[:65], 'count': 1}
    if identity == 'auto:adguard-doh': route['label'] = 'AdGuard DoH'
    if address.startswith(('https://', 'https+local://')):
        address = address.replace('https+local://', 'https://', 1)
        parsed = urlsplit(address)
        if not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment: return
        route.update(transport='doh', endpoint=address)
        if domain(parsed.hostname): result['domains'].append(parsed.hostname)
    elif address.startswith('tls://'):
        parsed = urlsplit(address)
        if not parsed.hostname or parsed.username or parsed.password: return
        route.update(transport='dot', host=parsed.hostname, port=parsed.port or 853, server_name=parsed.hostname)
        if domain(parsed.hostname): result['domains'].append(parsed.hostname)
    else:
        try:
            ipaddress.ip_address(address)
            if not 1 <= int(port) <= 65535: return
            route.update(transport='udp', host=address, port=int(port))
        except ValueError: return
    result['dns_routes'].append(route)


def domain_status(name):
    addresses = sorted({item[4][0] for item in socket.getaddrinfo(name, None, type=socket.SOCK_STREAM)})
    try:
        output = subprocess.run(['dig', '+short', '+time=2', '+tries=1', name, 'CNAME'], capture_output=True, text=True, timeout=4)
        cnames = [n.rstrip('.') for n in output.stdout.splitlines() if domain(n.rstrip('.'))][:8]
    except (OSError, subprocess.TimeoutExpired): cnames = []
    return {'ok': bool(addresses), 'addresses': addresses[:16], 'cnames': cnames,
            'cdn': 'не подтверждён (A/AAAA и CNAME сами по себе не доказывают CDN)'}
