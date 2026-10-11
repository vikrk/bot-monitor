#!/usr/bin/python3
"""Authorize the current controller egress IP for already trusted node keys."""
import getpass
import ipaddress
import json
import os
import re
import subprocess
import urllib.request
from pathlib import Path

ROOT = Path('/etc/rvkomi-watchdog')


def source_ipv4():
    try:
        with urllib.request.urlopen('https://api.ipify.org', timeout=8) as response:
            return str(ipaddress.IPv4Address(response.read(80).decode().strip()))
    except Exception:
        value = input('Публичный IPv4 управляющего сервера: ').strip()
        return str(ipaddress.IPv4Address(value))


def ssh_status(host, cfg):
    argv = ['/usr/bin/ssh', '-4', '-T', '-F', '/dev/null', '-p', str(cfg['port']),
            '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'StrictHostKeyChecking=yes',
            '-o', 'UserKnownHostsFile=' + cfg['known_hosts'], '-o', 'GlobalKnownHostsFile=/dev/null',
            '-o', 'HostKeyAlgorithms=ssh-ed25519', '-o', 'PasswordAuthentication=no',
            '-o', 'ConnectTimeout=7', '-i', cfg['key'], 'root@' + cfg['address'], 'status']
    try:
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, timeout=20)
        if result.returncode == 0:
            json.loads(result.stdout.decode('utf-8'))
            return True
    except Exception:
        pass
    return False


def split_options(text):
    parts, current = [], []
    quoted = escaped = False
    for char in text:
        if escaped:
            current.append(char)
            escaped = False
        elif char == '\\' and quoted:
            current.append(char)
            escaped = True
        elif char == '"':
            current.append(char)
            quoted = not quoted
        elif char == ',' and not quoted:
            parts.append(''.join(current))
            current = []
        else:
            current.append(char)
    if quoted:
        raise ValueError('invalid authorized_keys option quoting')
    if current:
        parts.append(''.join(current))
    return parts


def update_key_line(line, public_key, source_ip):
    key_type, key_data = public_key
    match = re.search(r'(?P<prefix>.*?)(?P<key>' + re.escape(key_type) + r'\s+' + re.escape(key_data) + r'(?:\s|$))', line)
    if not match:
        return line, False
    options_text = match.group('prefix').strip()
    options = split_options(options_text) if options_text else []
    found_from = False
    for index, option in enumerate(options):
        name, sep, value = option.partition('=')
        if name == 'from' and sep:
            found_from = True
            if len(value) < 2 or value[0] != '"' or value[-1] != '"':
                raise ValueError('unsupported unquoted from= option')
            addresses = value[1:-1].split(',')
            if source_ip not in addresses:
                addresses.append(source_ip)
            options[index] = 'from="' + ','.join(addresses) + '"'
            break
    if not found_from:
        options.append('from="' + source_ip + '"')
    if not any(option == 'restrict' for option in options):
        options.append('restrict')
    prefix = ','.join(options) + ' '
    return prefix + match.group('key') + line[match.end('key'):], True


def authorize(host, cfg, source_ip):
    try:
        import paramiko
    except ImportError:
        raise RuntimeError('paramiko is not installed') from None
    private_key = paramiko.Ed25519Key.from_private_key_file(cfg['key'])
    public_key = (private_key.get_name(), private_key.get_base64())
    password = getpass.getpass(f'{host.upper()} root SSH password (not saved): ')
    client = paramiko.SSHClient()
    client.load_host_keys(cfg['known_hosts'])
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.connect(cfg['address'], port=int(cfg['port']), username='root', password=password,
                       timeout=12, banner_timeout=12, auth_timeout=12,
                       look_for_keys=False, allow_agent=False)
        sftp = client.open_sftp()
        auth = '/root/.ssh/authorized_keys'
        try:
            sftp.chmod('/root/.ssh', 0o700)
            with sftp.open(auth, 'r') as source:
                old = source.read().decode('utf-8', 'strict')
        except Exception:
            raise RuntimeError('не удалось прочитать /root/.ssh/authorized_keys; ничего не изменено') from None
        lines = old.splitlines()
        matching = [i for i, line in enumerate(lines) if public_key[1] in line.split()]
        if not matching:
            raise RuntimeError('текущий закрытый ключ не найден в authorized_keys; новый ключ автоматически не добавлялся')
        changed = False
        for index in matching:
            lines[index], did_change = update_key_line(lines[index], public_key, source_ip)
            changed = changed or did_change
        if not changed:
            raise RuntimeError('не удалось безопасно обновить параметры текущего ключа')
        temporary = auth + '.rvkomi-new'
        with sftp.open(temporary, 'w') as target:
            target.write(('\n'.join(lines) + '\n').encode())
        sftp.chmod(temporary, 0o600)
        sftp.posix_rename(temporary, auth)
        sftp.close()
    finally:
        password = ''
        client.close()
    if not ssh_status(host, cfg):
        raise RuntimeError('source-IP добавлен, но SSH/RPC status пока не ответил')


def main():
    if os.geteuid() != 0:
        raise SystemExit('Запустите от root: sudo rvkomi-control-authorize')
    try:
        source_ip = source_ipv4()
    except ValueError:
        raise SystemExit('Нужен корректный публичный IPv4-адрес.') from None
    print('Новый публичный IP контрольного сервера: ' + source_ip)
    if input('Добавить этот IP к ограничениям существующих ключей для недоступных узлов? [yes/no]: ').strip() != 'yes':
        raise SystemExit('Отменено; узлы не изменены.')
    failed = []
    for filename in ('control-nodes.json', 'extra-nodes.json'):
        try:
            inventory = json.loads((ROOT / filename).read_text(encoding='utf-8'))
        except Exception:
            raise SystemExit(f'Не удалось прочитать {filename}.') from None
        for host, cfg in inventory.items():
            if ssh_status(host, cfg):
                print(host.upper() + ': SSH/RPC уже доступен')
                continue
            try:
                authorize(host, cfg, source_ip)
                print(host.upper() + ': SSH/RPC доступен с нового IP')
            except Exception as exc:
                failed.append(host)
                print(host.upper() + ': не подключён (' + str(exc) + ')')
    if failed:
        raise SystemExit('Не удалось подключить: ' + ', '.join(failed))
    print('Ограничения ключей обновлены; старые разрешённые адреса сохранены.')


if __name__ == '__main__':
    main()
