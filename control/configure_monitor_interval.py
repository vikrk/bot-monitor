#!/usr/bin/python3
"""Configure the existing fleet monitoring timer without changing bot code."""
import os
import re
import subprocess
import sys
from pathlib import Path

DROPIN = Path('/etc/systemd/system/rvkomi-extra-monitor.timer.d/override.conf')


def main():
    if os.geteuid() != 0:
        raise SystemExit('Запустите от root: sudo rvkomi-monitor-interval')
    raw = input('Интервал мониторинга в минутах (2–1440) [120]: ').strip() or '120'
    if not re.fullmatch(r'\d{1,4}', raw) or not 2 <= int(raw) <= 1440:
        raise SystemExit('Введите целое число от 2 до 1440 минут.')
    minutes = int(raw)
    DROPIN.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    temporary = DROPIN.with_suffix('.conf.tmp')
    temporary.write_text('[Timer]\nOnUnitInactiveSec=\nOnUnitInactiveSec=' + str(minutes) + 'min\n', encoding='utf-8')
    os.chmod(temporary, 0o644)
    os.replace(temporary, DROPIN)
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    if '--configure-only' not in sys.argv:
        subprocess.run(['systemctl', 'enable', '--now', 'rvkomi-extra-monitor.timer'], check=True)
        subprocess.run(['systemctl', 'restart', 'rvkomi-extra-monitor.timer'], check=True)
    print(f'Периодический мониторинг настроен: раз в {minutes} минут.')


if __name__ == '__main__':
    main()
