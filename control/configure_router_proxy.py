#!/usr/bin/python3
"""Expose only the router's authenticated task/report endpoints over HTTPS."""
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path('/etc/rvkomi-watchdog')
NGINX_SITE = Path('/etc/nginx/sites-available/rvkomi-router-receiver')
NGINX_LINK = Path('/etc/nginx/sites-enabled/rvkomi-router-receiver')


def main():
    if os.geteuid() != 0:
        raise SystemExit('Запустите от root: sudo rvkomi-router-proxy-setup')
    try:
        config = json.loads((ROOT / 'router-agent.json').read_text(encoding='utf-8'))
        domain = (urlsplit(config['url']).hostname or '').encode('idna').decode('ascii').lower()
    except Exception:
        raise SystemExit('В router-agent.json нет корректного HTTPS URL агента.') from None
    if not re.fullmatch(r'[a-z0-9.-]{1,253}', domain):
        raise SystemExit('Недопустимое имя домена роутера.')
    cert = ROOT / 'router-tls' / domain / 'fullchain.pem'
    key = ROOT / 'router-tls' / domain / 'privkey.pem'
    if not cert.is_file() or not key.is_file():
        raise SystemExit('В зашифрованной runtime-копии нет TLS-сертификата и ключа для ' + domain + '.')
    if key.stat().st_mode & 0o077:
        raise SystemExit('Закрытый TLS-ключ должен иметь права 0600.')

    if not shutil.which('nginx'):
        raise SystemExit('На управляющем сервере не установлен Nginx; обратный прокси не настроен.')
    current = subprocess.run(['/usr/sbin/nginx', '-T'], capture_output=True, text=True, timeout=20)
    config_text = current.stdout + '\n' + current.stderr
    if domain in config_text:
        if 'proxy_pass http://127.0.0.1:19891' in config_text and '/task' in config_text and '/report' in config_text:
            print('HTTPS-прокси роутера уже настроен для ' + domain + '; существующие Nginx-файлы не менялись.')
            return
        raise SystemExit('В Nginx уже есть виртуальный хост ' + domain + ', но proxy для роутера не найден. '
                         'Существующий vhost оставлен без изменений, чтобы не затронуть другие службы.')

    if not NGINX_SITE.parent.is_dir() or not NGINX_LINK.parent.is_dir():
        raise SystemExit('Не найдены стандартные каталоги Nginx sites-available/sites-enabled.')
    if NGINX_SITE.exists() or NGINX_LINK.exists():
        raise SystemExit('Файл настройки router receiver уже существует; повторная запись отменена.')
    site = f'''server {{
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name {domain};
    ssl_certificate {cert};
    ssl_certificate_key {key};
    ssl_protocols TLSv1.2 TLSv1.3;
    client_max_body_size 64k;
    location = /task {{
        proxy_pass http://127.0.0.1:19891/task;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }}
    location = /report {{
        proxy_pass http://127.0.0.1:19891/report;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }}
    location / {{ return 404; }}
}}
'''
    NGINX_SITE.write_text(site, encoding='utf-8')
    os.chmod(NGINX_SITE, 0o644)
    try:
        NGINX_LINK.symlink_to(NGINX_SITE)
        test = subprocess.run(['/usr/sbin/nginx', '-t'], capture_output=True, text=True, timeout=20)
        if test.returncode:
            raise RuntimeError('nginx -t не прошёл')
        subprocess.run(['systemctl', 'enable', '--now', 'nginx.service'], check=True, timeout=30)
        subprocess.run(['systemctl', 'reload', 'nginx.service'], check=True, timeout=20)
    except Exception:
        try:
            NGINX_LINK.unlink()
        except FileNotFoundError:
            pass
        try:
            NGINX_SITE.unlink()
        except FileNotFoundError:
            pass
        raise SystemExit('Не удалось безопасно включить Nginx proxy; созданный файл удалён, существующие сайты не менялись.') from None
    print('Создан HTTPS proxy только для /task и /report: ' + domain + '.')
    print('Агент роутера начнёт подключаться после того, как DNS ' + domain + ' будет указывать на этот сервер.')


if __name__ == '__main__':
    main()
