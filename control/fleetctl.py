#!/usr/bin/python3
"""Interactive setup: credentials provision a node, profiles define its checks."""
import base64
import getpass
import hashlib
import ipaddress
import json
import os
import re
import shlex
import socket
import subprocess
import sys
import time
import urllib.request
import uuid
from pathlib import Path
import fleet
from node_agent import validate_profile

ROUTER_AGENT = '''#!/bin/sh
case "$SSH_ORIGINAL_COMMAND" in status|check|extras) ;; *) exit 2 ;; esac
printf 'RVK_ROUTER_V1\\nSECTION:memory\\n'
cat /proc/meminfo 2>/dev/null
printf '\\nSECTION:disk\\n'
df -Pk / 2>/dev/null
printf '\\nSECTION:load\\n'
cat /proc/loadavg 2>/dev/null
'''


def command(args):
    subprocess.run(args, check=True)


def default_profile(services=None):
    return {'services': services or [], 'allowed_restarts': [], 'urls': [], 'tls': [], 'dns_routes': [], 'disk_min_gb': 1}


def register_main(name):
    if not name or len(name) > 48 or any(ord(c) < 32 for c in name): raise ValueError('Имя: 1–48 символов')
    data = fleet.load() if fleet.enabled() else {'version': 1, 'nodes': {}}
    if 'main' not in data['nodes']:
        services = []
        for name_ in ('rvkomi-telegram-control', 'ssh', 'nginx', 'docker', 'x-ui', 'xray', 'AdGuardHome'):
            probe = subprocess.run(['systemctl', 'show', '-p', 'LoadState', '--value', name_], capture_output=True, text=True)
            if probe.stdout.strip() == 'loaded': services.append(name_)
        profile = default_profile(services)
        profile['state_path'] = str(fleet.STATE / 'main-last-check.json')
        data['nodes']['main'] = {'name': name, 'address': socket.getfqdn(), 'user': 'local',
                                 'kind': 'server', 'transport': 'local', 'profile': profile}
    else:
        data['nodes']['main']['name'] = name
        data['nodes']['main']['address'] = socket.getfqdn()
    fleet.save(data)
    save_local_profile(data['nodes']['main']['profile'])
    print('Основной сервер «' + name + '» добавлен в мониторинг локально.')


def save_local_profile(profile):
    path = fleet.ROOT / 'main-profile.json'
    temp = path.with_suffix('.tmp')
    temp.write_text(json.dumps(profile, ensure_ascii=False, indent=2), encoding='utf-8')
    temp.chmod(0o600)
    temp.replace(path)


def choose_node():
    nodes = fleet.nodes()
    choices = list(nodes)
    for i, identifier in enumerate(choices, 1):
        item = nodes[identifier]
        print(str(i) + '. ' + item['name'] + ' — ' + item['address'] + ' (' + item['transport'] + ')')
    value = input('Номер узла (Enter — отмена): ').strip()
    if not value: return None
    if not value.isdigit() or not 1 <= int(value) <= len(choices): raise ValueError('Неверный номер')
    return choices[int(value) - 1]


def number(prompt, default, low, high):
    raw = input(prompt + ' [' + str(default) + ']: ').strip() or str(default)
    if not raw.isdigit() or not low <= int(raw) <= high: raise ValueError('Число вне допустимого диапазона')
    return int(raw)


def profile_wizard(profile):
    profile = json.loads(json.dumps(profile))
    while True:
        print('\nПрофиль: службы=' + ', '.join(profile.get('services', [])) +
              '; HTTP=' + str(len(profile.get('urls', []))) + '; TLS=' + str(len(profile.get('tls', []))) +
              '; DNS=' + str(len(profile.get('dns_routes', []))))
        print('1. Список контролируемых служб\n2. Добавить HTTP(S)-проверку\n3. Добавить TLS/CDN/origin\n4. Добавить DNS/DoH/DoT-маршрут\n5. Путь querylog AdGuard\n6. Разрешённые перезапуски\n7. Удалить проверку\n0. Сохранить профиль')
        choice = input('Выбор: ').strip()
        if choice == '0': return validate_profile(profile)
        if choice == '1':
            profile['services'] = input('Имена systemd-служб через запятую: ').replace(' ', '').split(',')
            profile['services'] = [s for s in profile['services'] if s]
            profile['allowed_restarts'] = [s for s in profile.get('allowed_restarts', []) if s in profile['services']]
        elif choice == '2':
            profile.setdefault('urls', []).append({'label': input('Название проверки: ').strip(),
                'url': input('URL HTTP(S): ').strip(), 'codes': [number('Ожидаемый HTTP-код', 200, 100, 599)]})
        elif choice == '3':
            host = input('Адрес подключения: ').strip()
            profile.setdefault('tls', []).append({'label': input('Название (CDN/origin и т.д.): ').strip(),
                'host': host, 'port': number('TLS-порт', 443, 1, 65535),
                'server_name': input('Имя сертификата/SNI [адрес подключения]: ').strip() or host})
        elif choice == '4':
            label = input('Название (DoH-origin, DNS-relay-DoH и т.д.): ').strip()
            transport = input('Транспорт doh / dot / udp: ').strip().lower()
            route = {'id': 'r_' + uuid.uuid4().hex[:10], 'label': label, 'transport': transport,
                     'count': number('Количество уникальных DNS-запросов', 16, 1, 64)}
            if transport == 'doh': route['endpoint'] = input('HTTPS URL DNS-маршрута: ').strip()
            elif transport in ('dot', 'udp'):
                route['host'] = input('Адрес DNS-сервера: ').strip()
                route['port'] = number('Порт', 853 if transport == 'dot' else 53, 1, 65535)
                if transport == 'dot': route['server_name'] = input('SNI [адрес сервера]: ').strip() or route['host']
            else: raise ValueError('Транспорт: doh, dot или udp')
            if input('Подтверждать приход каждого запроса по журналу AdGuard? [y/N]: ').strip().lower() == 'y':
                print('Выберите узел, на котором находится querylog AdGuard (настройте путь пунктом 5 его профиля).')
                mode = input('Журнал на этом же узле? [Y/n]: ').strip().lower()
                route['querylog_node'] = choose_node() if mode == 'n' else 'self'
                if not route['querylog_node']: raise ValueError('Узел журнала не выбран')
                route['log_wait_seconds'] = number('Ожидание записи в журнале (секунд)', 25, 0, 120)
            profile.setdefault('dns_routes', []).append(route)
        elif choice == '5': profile['querylog_path'] = input('Абсолютный путь к querylog.json/jsonl: ').strip()
        elif choice == '6':
            print('Перезапуск возможен только кнопкой после подтверждения владельца. Доступные службы: ' + ', '.join(profile.get('services', [])))
            profile['allowed_restarts'] = [s.strip() for s in input('Разрешить перезапуск служб (через запятую; пусто — запретить все): ').split(',') if s.strip()]
        elif choice == '7':
            entries = [(field, i, item) for field in ('urls', 'tls', 'dns_routes') for i, item in enumerate(profile.get(field, []))]
            for i, (_, _, item) in enumerate(entries, 1): print(str(i) + '. ' + item['label'])
            if entries:
                selected = number('Номер удаляемой проверки', 1, 1, len(entries)) - 1
                field, index, _ = entries[selected]
                del profile[field][index]
        else: print('Выберите пункт меню.'); continue
        validate_profile(profile)


def public_ip():
    try:
        with urllib.request.urlopen('https://api.ipify.org', timeout=8) as response:
            value = response.read(80).decode().strip()
    except Exception: value = input('Публичный IPv4 управляющего сервера: ').strip()
    address = ipaddress.IPv4Address(value)
    if not address.is_global: raise ValueError('Нужен публичный исходящий IPv4 управляющего сервера')
    return str(address)


def remote_exec(transport, text, allow_failure=False):
    channel = transport.open_session(timeout=10)
    channel.settimeout(300)
    channel.exec_command(text)
    out = channel.makefile('rb').read().decode('utf-8', 'replace')
    err = channel.makefile_stderr('rb').read().decode('utf-8', 'replace')
    code = channel.recv_exit_status()
    channel.close()
    if code and not allow_failure: raise RuntimeError('Удалённая команда подготовки не завершилась успешно: ' + err[-250:])
    return out.strip()


def add_node(kind, existing=None):
    import paramiko
    old_node = fleet.nodes().get(existing, {})
    name = input('Название узла' + (' [' + old_node['name'] + ']' if existing else '') + ': ').strip() or old_node.get('name', '')
    if not name or len(name) > 48 or any(ord(c) < 32 for c in name): raise ValueError('Некорректное имя')
    if any(key != existing and node['name'].casefold() == name.casefold() for key, node in fleet.nodes().items()): raise ValueError('Имя уже занято; используйте изменение подключения')
    host = input('IP или DNS-имя' + (' [' + old_node['address'] + ']' if existing else '') + ': ').strip() or old_node.get('address', '')
    user = input('SSH-логин [' + old_node.get('user', 'root') + ']: ').strip() or old_node.get('user', 'root')
    port = number('SSH-порт', old_node.get('port', 22), 1, 65535)
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,253}', host) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,31}', user):
        raise ValueError('Неверный адрес или логин (поддерживается IPv4/DNS)')
    source = public_ip()
    transport = paramiko.Transport((host, port))
    identifier = 'n_' + uuid.uuid4().hex[:12]
    try:
        transport.start_client(timeout=12)
        key = transport.get_remote_server_key()
        fingerprint = 'SHA256:' + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')
        print('Fingerprint SSH: ' + fingerprint)
        if input('Сверьте fingerprint и подтвердите [yes]: ').strip() != 'yes': return
        password = getpass.getpass('SSH-пароль (только для установки ключа, не сохраняется): ')
        try: transport.auth_password(user, password)
        finally: password = ''
        if not transport.is_authenticated(): raise RuntimeError('SSH не подтвердил пароль')
        home = remote_exec(transport, 'printf "%s" "$HOME"')
        if not home.startswith('/') or not re.fullmatch(r'/[A-Za-z0-9_./-]+', home) or '..' in Path(home).parts:
            raise RuntimeError('Не удалось определить POSIX home; этот SSH CLI требует отдельного способа установки ключей')
        python = remote_exec(transport, 'command -v python3 || true')
        if not python and kind == 'server':
            if user != 'root': raise RuntimeError('На сервере нет Python3; установите его и повторите подключение')
            remote_exec(transport, 'command -v apt-get >/dev/null && apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3')
            python = remote_exec(transport, 'command -v python3')
        agent_dir = home.rstrip('/') + '/.local/lib/rvkomi-control/' + identifier
        remote_exec(transport, 'umask 077; mkdir -p ' + shlex.quote(agent_dir) + ' ' + shlex.quote(home + '/.ssh'))
        sftp = paramiko.SFTPClient.from_transport(transport)
        profile = old_node.get('profile', default_profile())
        if python:
            discovered = remote_exec(transport, "for s in ssh nginx docker x-ui xray AdGuardHome; do [ \"$(systemctl show -p LoadState --value \"$s\" 2>/dev/null)\" = loaded ] && printf '%s\\n' \"$s\"; done; true")
            if not existing: profile['services'] = discovered.splitlines()
            print('Обнаруженные службы: ' + ', '.join(profile['services']))
            if input('Настроить проверки URL/TLS/DNS и разрешённые действия сейчас? [y/N]: ').strip().lower() == 'y':
                profile = profile_wizard(profile)
            agent_path = agent_dir + '/node_agent.py'
            profile_path = agent_dir + '/profile.json'
            sftp.put(str(fleet.BASE / 'node_agent.py'), agent_path)
            with sftp.open(profile_path, 'w') as out: out.write(json.dumps(profile, ensure_ascii=False).encode('utf-8'))
            sftp.chmod(profile_path, 0o600)
            logging_setup = {'configured': False, 'reason': 'router logging is configured separately'}
            if kind == 'server':
                if remote_exec(transport, 'id -u') == '0':
                    # The authenticated setup session provisions logging before installing a restricted RPC key.
                    logging_source = fleet.BASE / 'configure_logging.py'
                    logging_remote = agent_dir + '/configure_logging.py'
                    sftp.put(str(logging_source), logging_remote)
                    sftp.chmod(logging_remote, 0o600)
                    remote_exec(transport, 'command -v logrotate >/dev/null && ' + shlex.quote(python) +
                        ' -c "import yaml" 2>/dev/null || { command -v apt-get >/dev/null && '
                        'apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq logrotate python3-yaml; }')
                    remote_exec(transport, 'install -d -m 0755 /usr/local/lib/rvkomi-watchdog && install -m 0755 ' +
                        shlex.quote(logging_remote) + ' /usr/local/lib/rvkomi-watchdog/configure_logging.py')
                    configured = remote_exec(transport, shlex.quote(python) +
                        ' /usr/local/lib/rvkomi-watchdog/configure_logging.py install --agent-dir ' + shlex.quote(agent_dir),
                        allow_failure=True)
                    logging_result = json.loads(configured)
                    if logging_result.get('errors'):
                        raise RuntimeError('Не удалось настроить журналы: ' + ', '.join(logging_result['errors']) +
                            '. Причины: /var/lib/rvkomi-watchdog/diagnostic-logging-status.json на подключаемом сервере.')
                    logging_setup = {'configured': True, 'result': logging_result}
                    print('Журналы включены: journald/Xray/nginx 72h, AdGuard 6h; почасовая очистка активна.')
                else:
                    logging_setup = {'configured': False, 'reason': 'root is required for system diagnostic logging'}
                    print('Системное журналирование не настроено: этот SSH-пользователь не root. '
                          'Для полного подключения серверных журналов используйте root.')
            forced = shlex.quote(python) + ' ' + shlex.quote(agent_path) + ' --profile ' + shlex.quote(profile_path)
            mode = 'ssh-agent'
        else:
            agent_path = agent_dir + '/router-agent.sh'
            with sftp.open(agent_path, 'w') as out: out.write(ROUTER_AGENT.encode())
            forced = '/bin/sh ' + shlex.quote(agent_path)
            mode = 'ssh-shell'
            print('POSIX-роутер без Python: SSH-доступ, RAM, нагрузка и диск. Расширенный профиль требует Python.')
        sftp.chmod(agent_path, 0o600)
        local_dir = fleet.ROOT / 'keys'
        known_dir = fleet.ROOT / 'known_hosts'
        local_dir.mkdir(mode=0o700, exist_ok=True)
        known_dir.mkdir(mode=0o700, exist_ok=True)
        private = local_dir / (identifier + '_ed25519')
        command(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'rvkomi-' + identifier, '-f', str(private)])
        private.chmod(0o600)
        public = private.with_suffix('.pub').read_text().strip()
        known = known_dir / identifier
        alias = host if port == 22 else '[' + host + ']:' + str(port)
        known.write_text(alias + ' ' + key.get_name() + ' ' + key.get_base64() + '\n')
        known.chmod(0o600)
        auth = home + '/.ssh/authorized_keys'
        try:
            with sftp.open(auth, 'r') as inp: old = inp.read().decode('utf-8', 'strict')
        except FileNotFoundError: old = ''
        backup_path = auth + '.rvkomi-backup-' + str(int(time.time()))
        with sftp.open(backup_path, 'w') as backup: backup.write(old.encode())
        sftp.chmod(backup_path, 0o600)
        escaped = forced.replace('\\', '\\\\').replace('"', '\\"')
        line = 'from="' + source + '",restrict,command="' + escaped + '" ' + public + '\n'
        with sftp.open(auth + '.rvkomi-new', 'w') as out: out.write((old.rstrip('\n') + '\n' + line).lstrip('\n').encode())
        sftp.chmod(auth + '.rvkomi-new', 0o600)
        sftp.posix_rename(auth + '.rvkomi-new', auth)
        sftp.chmod(home + '/.ssh', 0o700)
        node = {'name': name, 'kind': kind, 'address': host, 'user': user, 'port': port, 'key': str(private),
                'known_hosts': str(known), 'fingerprint': fingerprint, 'source_ip': source,
                'transport': mode, 'profile': profile,
                'diagnostic_logging': logging_setup if python else {'configured': False, 'reason': 'POSIX router'}}
        data = fleet.load()
        data['nodes'][identifier] = node
        fleet.save(data)
        try:
            result = fleet.check(identifier)
            if 'ssh-or-check-unavailable' in result.get('failures', []):
                raise RuntimeError('Ключевой SSH/RPC-доступ не прошёл')
        except Exception:
            del data['nodes'][identifier]
            fleet.save(data)
            with sftp.open(auth + '.rvkomi-new', 'w') as out: out.write(old.encode())
            sftp.chmod(auth + '.rvkomi-new', 0o600)
            sftp.posix_rename(auth + '.rvkomi-new', auth)
            raise RuntimeError('Ключевой SSH/RPC-доступ не прошёл; предыдущий authorized_keys восстановлен') from None
        if existing:
            data['nodes'][existing]['enabled'] = False
            for item in data['nodes'].values():
                for route in item.get('profile', {}).get('dns_routes', []):
                    if route.get('querylog_node') == existing: route['querylog_node'] = identifier
            fleet.save(data)
        print('Узел «' + name + '» подключён. Ключ разрешён только с ' + source + '. Проверка: ' +
              ('ошибки ' + ', '.join(result.get('failures', [])) if result.get('failures') else 'успешна') + '. Узел уже доступен в меню бота.')
        sftp.close()
    finally:
        transport.close()


def edit_profile():
    identifier = choose_node()
    if not identifier: return
    node = fleet.nodes()[identifier]
    if node['transport'] not in ('local', 'ssh-agent'): raise ValueError('Расширенный профиль требует стандартного Python-агента')
    profile = profile_wizard(node.get('profile', default_profile()))
    encoded = base64.urlsafe_b64encode(json.dumps(profile, ensure_ascii=False).encode()).decode()
    fleet.rpc(identifier, 'configure ' + encoded)
    data = fleet.load()
    data['nodes'][identifier]['profile'] = profile
    fleet.save(data)
    print('Профиль сохранён на узле и контроллере.')


def run_checks():
    for identifier, node in fleet.nodes().items():
        try:
            result = fleet.check(identifier)
            import advanced
            advanced.journal(identifier, result, 'check')
            print(node['name'] + ': ' + (', '.join(result.get('failures', [])) or 'все настроенные проверки прошли'))
        except Exception as exc: print(node['name'] + ': ' + str(exc))


def adopt_legacy():
    data = fleet.load() if fleet.enabled() else {'version': 1, 'nodes': {}}
    for filename in ('control-nodes.json', 'extra-nodes.json'):
        path = fleet.ROOT / filename
        if not path.is_file(): continue
        for identifier, cfg in json.loads(path.read_text()).items():
            if not fleet.ID.fullmatch(identifier): raise ValueError('Неверное legacy-имя')
            if identifier in data['nodes']: raise ValueError('Имя legacy-узла уже существует')
            data['nodes'][identifier] = {**cfg, 'name': identifier.upper(), 'user': cfg.get('user', 'root'),
                'kind': 'server', 'transport': 'legacy', 'profile': default_profile()}
    fleet.save(data)
    print('Списки из резервной копии добавлены как существующие агенты. Их проверки сохранены.')


def main():
    if os.geteuid() != 0: raise SystemExit('Запустите: sudo fleetctl')
    if len(sys.argv) == 3 and sys.argv[1] == '--init': register_main(sys.argv[2]); return
    if len(sys.argv) == 2 and sys.argv[1] == '--adopt-legacy': adopt_legacy(); return
    if not fleet.enabled(): register_main(input('Название управляющего сервера: ').strip())
    while True:
        print('\nRVKOMI — ' + fleet.load()['nodes'].get('main', {}).get('name', 'контроллер'))
        print('1. Подключить сервер\n2. Подключить SSH-роутер\n3. Список узлов\n4. Настроить проверки и разрешённые действия узла\n5. Проверить все узлы\n6. Настроить Telegram-бота/администратора\n7. Интервал мониторинга\n8. Настроить ИИ\n9. Переименовать узел\n10. Отключить узел из мониторинга\n11. Статус службы\n12. Экспорт зашифрованной копии\n13. Восстановление копии\n14. Изменить IP/логин/порт и переподключить узел\n0. Выход')
        choice = input('Выбор: ').strip()
        try:
            if choice == '0': return
            if choice == '1': add_node('server')
            elif choice == '2': add_node('router')
            elif choice == '3':
                for key, node in fleet.nodes().items(): print(node['name'] + ': ' + node['user'] + '@' + node['address'] + '; ' + node['transport'])
            elif choice == '4': edit_profile()
            elif choice == '5': run_checks()
            elif choice == '6':
                command(['/usr/local/bin/rvkomi-control-setup'])
                command(['systemctl', 'restart', 'rvkomi-telegram-control.service'])
            elif choice == '7': command(['/usr/local/bin/rvkomi-monitor-interval'])
            elif choice == '8': command(['/usr/local/bin/rvkomi-ai-setup'])
            elif choice == '9':
                key = choose_node()
                if key:
                    name = input('Новое имя: ').strip()
                    if not name or len(name) > 48 or any(ord(c) < 32 for c in name): raise ValueError('Неверное имя')
                    data = fleet.load(); data['nodes'][key]['name'] = name; fleet.save(data)
            elif choice == '10':
                key = choose_node()
                if key and key != 'main' and input('Отключить мониторинг узла? [yes]: ').strip() == 'yes':
                    data = fleet.load(); data['nodes'][key]['enabled'] = False; fleet.save(data)
                    print('Мониторинг отключён. Для удаления ключа используйте authorized_keys на узле.')
            elif choice == '11': subprocess.run(['systemctl', 'status', '--no-pager', 'rvkomi-telegram-control.service', 'rvkomi-extra-monitor.timer'])
            elif choice == '12': command(['/usr/local/bin/rvkomi-control-runtime', 'export'])
            elif choice == '13':
                command(['/usr/local/bin/rvkomi-control-runtime', 'import', input('Путь к .enc: ').strip()])
                if not fleet.enabled() or not any(n.get('transport') == 'legacy' for n in fleet.load()['nodes'].values()):
                    if input('Добавить legacy-списки узлов из этой копии? [y/N]: ').lower() == 'y': adopt_legacy()
                command(['systemctl', 'restart', 'rvkomi-telegram-control.service'])
            elif choice == '14':
                identifier = choose_node()
                if identifier and identifier != 'main': add_node(fleet.nodes()[identifier]['kind'], identifier)
            else: print('Неизвестный пункт')
        except (Exception, KeyboardInterrupt) as exc: print('Действие не завершено: ' + str(exc))


if __name__ == '__main__': main()
