#!/usr/bin/env python3
"""Optional MTU workaround, applied without restarting the network."""
import argparse
import datetime
import os
from pathlib import Path
import re
import shutil
import subprocess


def update_interfaces(text, interface, mtu):
    lines = text.splitlines(keepends=True)
    headers = [i for i, line in enumerate(lines) if re.match(r'^\s*iface\s+', line)]
    found = False
    for start in reversed(headers):
        if not re.match(r'^\s*iface\s+' + re.escape(interface) + r'\s+inet6?\s+', lines[start]):
            continue
        end = next((i for i in range(start + 1, len(lines))
                    if re.match(r'^\s*(?:iface|auto|allow-\S+|mapping|source|source-directory)\s+', lines[i])), len(lines))
        body = [line for line in lines[start + 1:end] if not re.match(r'^\s*mtu\s+', line)]
        lines[start:end] = [lines[start].rstrip('\n') + '\n', f'    mtu {mtu}\n', *body]
        found = True
    return ''.join(lines), found


def apply(interface, mtu):
    if os.geteuid() != 0:
        raise SystemExit('Запустите от root.')
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,15}', interface) or not Path('/sys/class/net', interface).exists():
        raise SystemExit('Сетевой интерфейс не найден или имя некорректно.')
    if not 1280 <= mtu <= 1500:
        raise SystemExit('MTU должен быть от 1280 до 1500.')
    ip = shutil.which('ip')
    if not ip:
        raise SystemExit('Не найдена команда ip.')
    config = Path('/etc/network/interfaces')
    updated, found = update_interfaces(config.read_text(), interface, mtu) if config.is_file() else ('', False)
    if found and updated != config.read_text():
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
        backup = config.with_name(config.name + '.rvkomi-backup-' + stamp)
        shutil.copy2(config, backup)
        temporary = config.with_name('.interfaces.rvkomi-tmp')
        temporary.write_text(updated)
        shutil.copystat(config, temporary)
        os.replace(temporary, config)
        print('Копия сетевого конфига:', backup)
    # Also covers netplan/networkd and interfaces sourced from other files.
    unit = Path('/etc/systemd/system/rvkomi-network-mtu.service')
    unit.write_text('[Unit]\nDescription=RVKOMI interface MTU\nAfter=network-online.target\nWants=network-online.target\nBefore=rvkomi-telegram-control.service rvkomi-extra-monitor.service\n\n'
                    '[Service]\nType=oneshot\nRemainAfterExit=yes\n'
                    f'ExecStart={ip} link set dev {interface} mtu {mtu}\n\n[Install]\nWantedBy=multi-user.target\n')
    unit.chmod(0o644)
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    subprocess.run(['systemctl', 'enable', 'rvkomi-network-mtu.service'], check=True)
    subprocess.run([ip, 'link', 'set', 'dev', interface, 'mtu', str(mtu)], check=True)
    subprocess.run(['systemctl', 'restart', 'rvkomi-network-mtu.service'], check=True)
    print(f'MTU {interface}: {mtu}; сохранено для следующей загрузки. Сеть не перезапускалась.')
    if not found:
        print('Интерфейс не описан в /etc/network/interfaces; постоянное применение настроено через systemd.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--interface', required=True)
    parser.add_argument('--mtu', type=int, default=1452)
    args = parser.parse_args()
    apply(args.interface, args.mtu)
