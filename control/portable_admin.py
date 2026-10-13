"""Provisioned capabilities for the production AI executor, used by the node RPC."""
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil


def validate_policy(value):
    if not isinstance(value, dict) or set(value) - {
        'routing', 'adguard_filters', 'dns_rewrites', 'adguard_config',
        'adguard_binary', 'sni', 'router_init_scripts'}:
        raise ValueError('Unknown AI policy fields')
    for field in ('routing', 'adguard_filters'):
        if field in value and type(value[field]) is not bool:
            raise ValueError('AI enable flag must be boolean')
    for field in ('adguard_config', 'adguard_binary'):
        if field in value:
            path = Path(value[field])
            if not path.is_absolute() or '..' in path.parts or '\n' in str(path) or '\0' in str(path):
                raise ValueError('AI config paths must be absolute')
    if value.get('adguard_filters') or value.get('dns_rewrites'):
        if not value.get('adguard_config') or not value.get('adguard_binary'):
            raise ValueError('AdGuard config and binary paths are required')
    dns = value.get('dns_rewrites', {})
    if not isinstance(dns, dict) or set(dns) - {'enabled', 'target_ipv4'}:
        raise ValueError('Invalid DNS rewrite policy')
    if dns:
        if dns.get('enabled') is not True or not ipaddress.IPv4Address(dns.get('target_ipv4', '')).is_global:
            raise ValueError('DNS relay target must be an explicitly configured public IPv4')
    sni = value.get('sni', {})
    if not isinstance(sni, dict) or set(sni) - {'enabled', 'file', 'map_variable', 'relay_ip', 'port', 'probe_domains'}:
        raise ValueError('Invalid SNI policy')
    if sni:
        if sni.get('enabled') is not True or not ipaddress.IPv4Address(sni.get('relay_ip', '')).is_global:
            raise ValueError('SNI relay address must be configured')
        path = Path(sni.get('file', ''))
        if not path.is_absolute() or '..' in path.parts or path.suffix != '.conf':
            raise ValueError('SNI map must be an absolute .conf path')
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,63}', sni.get('map_variable', '')):
            raise ValueError('Invalid SNI backend map variable')
        if type(sni.get('port', 443)) is not int or not 1 <= sni.get('port', 443) <= 65535:
            raise ValueError('Invalid SNI relay port')
        domains = sni.get('probe_domains', [])
        if not isinstance(domains, list) or not 1 <= len(domains) <= 30 or any(
                not isinstance(d, str) or not re.fullmatch(r'(?:[a-z0-9-]+\.)+[a-z0-9-]+', d) for d in domains):
            raise ValueError('SNI needs explicit TLS postcheck domains')
    scripts = value.get('router_init_scripts', {})
    if not isinstance(scripts, dict) or len(scripts) > 16:
        raise ValueError('Invalid router init script policy')
    for name, path in scripts.items():
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', name) or not re.fullmatch(
                r'/opt/etc/init\.d/[A-Za-z0-9_.-]+', path):
            raise ValueError('Only explicitly named Entware init scripts are supported')
    return value


def provision_profile(profile, profile_path):
    policy = validate_policy(profile.get('ai_admin', {}))
    path = Path(profile_path).with_name('ai-sni-probes.json')
    if policy.get('sni') and not path.exists():
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as handle:
            json.dump({'sni_relay_checks': {'domains': policy['sni']['probe_domains']}}, handle)


def handle(request, profile, profile_path):
    if os.geteuid() != 0:
        raise ValueError('AI changes require UID 0')
    if not isinstance(request, dict) or request not in ({'op': 'describe'},) and (
            set(request) != {'op', 'plan'} or request.get('op') != 'apply'):
        raise ValueError('Invalid admin request')
    settings = validate_policy(profile.get('ai_admin', {}))
    state = Path(profile_path).parent / 'ai-admin-state'
    if settings.get('router_init_scripts'):
        import router_admin_executor as router
        router.SERVICES = settings['router_init_scripts']
        router.ROOT = state
        if request['op'] == 'describe':
            return router.describe()
        state.mkdir(mode=0o700, parents=True, exist_ok=True)
        return router.apply(request['plan'])
    import admin_executor as executor
    policy = {'services': profile.get('allowed_restarts', []),
              'routing': settings.get('routing', False),
              'adguard_filters': {'enabled': settings.get('adguard_filters', False)},
              'dns_rewrites': settings.get('dns_rewrites', {}),
              'sni': settings.get('sni', {}), 'preflight': {}}
    executor.policy = lambda: policy
    executor.ROOT = state
    executor.XRAY = str(next((p for p in Path('/usr/local/x-ui/bin').glob('xray-linux-*')
                             if p.is_file() and os.access(p, os.X_OK)), Path('/usr/local/x-ui/bin/xray-linux-amd64')))
    if settings.get('adguard_config'):
        import dns_admin as dns
        dns.FILE = Path(settings['adguard_config'])
        dns.BIN = settings['adguard_binary']
        dns.policy = lambda: policy
        policy['preflight']['AdGuardHome'] = [dns.BIN, '--check-config', '-c', str(dns.FILE), '-w', str(dns.FILE.parent)]
    if settings.get('sni'):
        import sni_admin as sni
        values = settings['sni']
        sni.FILE = Path(values['file'])
        sni.PROBE = Path(profile_path).with_name('ai-sni-probes.json')
        sni.RELAY_IP = values['relay_ip']
        sni.RELAY_PORT = values.get('port', 443)
        sni.MAP_VARIABLE = values['map_variable']
    if request['op'] == 'describe':
        return executor.describe()
    # Each executor validates its own capability, plan fields and state digest again.
    return executor.apply(request['plan'])
