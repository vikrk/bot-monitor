#!/usr/bin/python3
"""Authenticated encrypted export/import of the control bot's runtime config."""
import base64
import datetime
import getpass
import hashlib
import io
import json
import os
import re
import secrets
import stat
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ROOT = Path('/etc/rvkomi-watchdog')
STATE = Path('/var/lib/rvkomi-watchdog')
TIMER_DROPIN = Path('/etc/systemd/system/rvkomi-extra-monitor.timer.d/override.conf')
MAGIC = b'RVKCTRL1'
ITERATIONS = 600_000
MAX_BUNDLE = 256 * 1024 * 1024
CONFIG_FILES = (
    'telegram.json', 'ai.json', 'control-nodes.json', 'extra-nodes.json',
    'router-agent.json', 'backup-webdav.json', 'backup-recovery.key',
    'fleet.json', 'main-profile.json',
)
STATE_FILES = (
    'history.jsonl', 'telegram-control-state.json', 'extra-monitor-state.json',
    'router-state.json', 'router-settings.json', 'router-task.json',
    'router-baseline.json', 'router-alert-state.json', 'backup-state.json',
    'certificate-alert-state.json', 'maintenance-central.json',
    'generic-control-state.json', 'generic-monitor-state.json', 'main-last-check.json',
)
HOSTS = {'spb', 'nl', 'dns', 'www', 'space', 'latvia', 'fin', 'telegramm'}
EXPECTED_INVENTORIES = {
    'control-nodes.json': {'spb', 'nl'},
    'extra-nodes.json': {'dns', 'www', 'space', 'latvia', 'fin', 'telegramm'},
}


def fail(message):
    raise SystemExit(message)


def check_root():
    if os.geteuid() != 0:
        fail('Запустите команду от root: sudo rvkomi-control-runtime export или import')


def derive(passphrase, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITERATIONS)
    return Fernet(base64.urlsafe_b64encode(kdf.derive(passphrase.encode('utf-8'))))


def relative_runtime_path(path):
    p = Path(path)
    if not p.is_absolute() or not p.is_file() or p.is_symlink():
        fail('Не найден обычный файл конфигурации SSH; экспорт отменён.')
    return p


def export_bundle(destination):
    check_root()
    password = getpass.getpass('Пароль шифрования резервной копии (не менее 14 символов): ')
    if len(password) < 14:
        fail('Пароль должен содержать не менее 14 символов.')
    if getpass.getpass('Повторите пароль: ') != password:
        fail('Пароли не совпадают.')

    destination = Path(destination).expanduser()
    if destination.exists():
        fail('Файл назначения уже существует; выберите другое имя.')
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    files = {}
    metadata = {'version': 1, 'created_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                'hosts': [], 'files': {}, 'monitor_interval_minutes': 2}
    interval_dropin = TIMER_DROPIN
    if interval_dropin.is_file() and not interval_dropin.is_symlink():
        match = re.search(r'(?m)^OnUnitInactiveSec=(\d+)min\s*$', interval_dropin.read_text(encoding='utf-8'))
        if match and 2 <= int(match.group(1)) <= 1440:
            metadata['monitor_interval_minutes'] = int(match.group(1))
    for name in CONFIG_FILES:
        source = ROOT / name
        if source.is_file() and not source.is_symlink():
            files['etc/rvkomi-watchdog/' + name] = source.read_bytes()

    router_config = files.get('etc/rvkomi-watchdog/router-agent.json')
    if router_config:
        try:
            router_url = json.loads(router_config.decode('utf-8')).get('url', '')
            router_domain = (urlsplit(router_url).hostname or '').encode('idna').decode('ascii').lower()
        except Exception:
            router_domain = ''
        if router_domain and re.fullmatch(r'[a-z0-9.-]{1,253}', router_domain):
            metadata['router_domain'] = router_domain
            for label, path in (('fullchain.pem', Path('/etc/letsencrypt/live') / router_domain / 'fullchain.pem'),
                                ('privkey.pem', Path('/etc/letsencrypt/live') / router_domain / 'privkey.pem')):
                try:
                    resolved = path.resolve(strict=True)
                    if not resolved.is_file():
                        continue
                    files[f'etc/rvkomi-watchdog/router-tls/{router_domain}/{label}'] = resolved.read_bytes()
                except OSError:
                    pass

    # Normalize key paths in the copied JSON and include only keys named by the
    # two explicit node inventories; arbitrary files under /root are excluded.
    portable = files.get('etc/rvkomi-watchdog/fleet.json')
    if portable:
        inventory = json.loads(portable)
        if inventory.get('version') != 1 or not isinstance(inventory.get('nodes'), dict):
            fail('Неверный fleet.json; экспорт отменён.')
        for host, cfg in inventory['nodes'].items():
            if not re.fullmatch(r'[a-z][a-z0-9_]{0,23}', host) or not isinstance(cfg, dict):
                fail('Неверная запись fleet.json; экспорт отменён.')
            metadata['hosts'].append(host)
            if cfg.get('transport') == 'local': continue
            key = relative_runtime_path(cfg.get('key', ''))
            known = relative_runtime_path(cfg.get('known_hosts', ''))
            files[f'etc/rvkomi-watchdog/keys/{host}_ed25519'] = key.read_bytes()
            files[f'etc/rvkomi-watchdog/known_hosts/{host}'] = known.read_bytes()
            cfg['key'] = f'/etc/rvkomi-watchdog/keys/{host}_ed25519'
            cfg['known_hosts'] = f'/etc/rvkomi-watchdog/known_hosts/{host}'
        files['etc/rvkomi-watchdog/fleet.json'] = (json.dumps(inventory, ensure_ascii=False, indent=2) + '\n').encode()
    for filename in ('control-nodes.json', 'extra-nodes.json'):
        raw = files.get('etc/rvkomi-watchdog/' + filename)
        if raw is None:
            continue
        try:
            inventory = json.loads(raw)
        except ValueError:
            fail('Файл конфигурации узлов повреждён; экспорт отменён.')
        if not isinstance(inventory, dict) or set(inventory) - HOSTS:
            fail('Список узлов содержит неизвестные имена; экспорт отменён.')
        for host, cfg in inventory.items():
            if not isinstance(cfg, dict):
                fail('Неверный формат конфигурации узла; экспорт отменён.')
            key = relative_runtime_path(cfg.get('key', ''))
            known = relative_runtime_path(cfg.get('known_hosts', ''))
            key_name = f'etc/rvkomi-watchdog/keys/{host}_ed25519'
            known_name = f'etc/rvkomi-watchdog/known_hosts/{host}'
            files[key_name] = key.read_bytes()
            files[known_name] = known.read_bytes()
            cfg['key'] = '/etc/rvkomi-watchdog/keys/' + host + '_ed25519'
            cfg['known_hosts'] = '/etc/rvkomi-watchdog/known_hosts/' + host
            metadata['hosts'].append(host)
        files['etc/rvkomi-watchdog/' + filename] = (json.dumps(inventory, ensure_ascii=False, indent=2) + '\n').encode()
        if set(inventory) != EXPECTED_INVENTORIES[filename]:
            fail(f'{filename}: ожидаются узлы {", ".join(sorted(EXPECTED_INVENTORIES[filename]))}; экспорт отменён.')

    if 'etc/rvkomi-watchdog/telegram.json' not in files:
        fail('Нет telegram.json. Сначала настройте контрольного Telegram-бота.')
    if not portable and not {'control-nodes.json', 'extra-nodes.json'} <= {
            p.rsplit('/', 1)[-1] for p in files if p.startswith('etc/rvkomi-watchdog/') and '/keys/' not in p and '/known_hosts/' not in p}:
        fail('Не найдены оба списка SSH-узлов; экспорт отменён.')

    for name in STATE_FILES:
        source = STATE / name
        if source.is_file() and not source.is_symlink():
            files['var/lib/rvkomi-watchdog/' + name] = source.read_bytes()
    metadata['hosts'] = sorted(set(metadata['hosts']))
    metadata['files'] = {name: hashlib.sha256(data).hexdigest() for name, data in sorted(files.items())}
    files['manifest.json'] = (json.dumps(metadata, ensure_ascii=False, indent=2) + '\n').encode()

    with tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024) as raw:
        with tarfile.open(fileobj=raw, mode='w:gz') as archive:
            for name, data in sorted(files.items()):
                info = tarfile.TarInfo(name)
                info.size = len(data)
                info.mode = 0o600
                info.mtime = 0
                archive.addfile(info, io.BytesIO(data))
        raw.seek(0)
        plaintext = raw.read(MAX_BUNDLE + 1)
    if len(plaintext) > MAX_BUNDLE:
        fail('Резервная копия больше допустимого размера 256 МБ.')
    salt = secrets.token_bytes(16)
    encrypted = MAGIC + salt + derive(password, salt).encrypt(plaintext)
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as out:
        out.write(encrypted)
        out.flush()
        os.fsync(out.fileno())
    print(f'Зашифрованная копия создана: {destination}; подключений: {len(metadata["hosts"])}.')
    print('Передайте файл на новый управляющий сервер защищённым способом. Пароль передавайте отдельно.')


def safe_member_name(name):
    if name == 'manifest.json':
        return True
    p = PurePosixPath(name)
    if p.is_absolute() or not p.parts or any(part in ('', '.', '..') for part in p.parts):
        return False
    if p.parts[0:2] == ('var', 'lib'):
        return len(p.parts) == 4 and p.parts[0:3] == ('var', 'lib', 'rvkomi-watchdog') and p.name in STATE_FILES
    if p.parts[0:2] != ('etc', 'rvkomi-watchdog') or len(p.parts) < 3:
        return False
    if len(p.parts) == 3:
        return p.parts[2] in CONFIG_FILES
    if len(p.parts) == 4 and p.parts[2] == 'keys':
        return bool(re.fullmatch(r'[a-z][a-z0-9_]{0,23}_ed25519', p.name))
    if len(p.parts) == 4 and p.parts[2] == 'known_hosts':
        return bool(re.fullmatch(r'[a-z][a-z0-9_]{0,23}', p.name))
    if len(p.parts) == 5 and p.parts[2] == 'router-tls':
        return bool(re.fullmatch(r'[a-z0-9.-]{1,253}', p.parts[3])) and p.name in ('fullchain.pem', 'privkey.pem')
    return False


def import_bundle(source):
    check_root()
    source = Path(source).expanduser()
    try:
        encrypted = source.read_bytes()
    except OSError:
        fail('Не удалось прочитать файл зашифрованной копии.')
    if len(encrypted) > (MAX_BUNDLE + 2) * 4 // 3 + 1024 or not encrypted.startswith(MAGIC) or len(encrypted) < 25:
        fail('Файл не похож на резервную копию RVKOMI или превышает допустимый размер.')
    salt, payload = encrypted[len(MAGIC):len(MAGIC) + 16], encrypted[len(MAGIC) + 16:]
    password = getpass.getpass('Пароль резервной копии: ')
    try:
        plaintext = derive(password, salt).decrypt(payload)
    except (InvalidToken, ValueError):
        fail('Неверный пароль или повреждённая резервная копия.')
    if len(plaintext) > MAX_BUNDLE:
        fail('Распакованный архив превышает допустимый размер.')

    staged = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(plaintext), mode='r:gz') as archive:
            members = archive.getmembers()
            if len(members) > 2000:
                fail('В архиве слишком много файлов.')
            total = 0
            for member in members:
                if not member.isfile() or not safe_member_name(member.name) or member.size > MAX_BUNDLE:
                    fail('Архив содержит недопустимый путь или тип файла.')
                total += member.size
                if total > MAX_BUNDLE:
                    fail('Суммарный размер архива превышает допустимый предел.')
                stream = archive.extractfile(member)
                if stream is None:
                    fail('Не удалось проверить содержимое архива.')
                staged[member.name] = stream.read(member.size + 1)
    except (tarfile.TarError, OSError):
        fail('Архив повреждён.')
    try:
        manifest = json.loads(staged.pop('manifest.json').decode('utf-8'))
    except (KeyError, UnicodeError, ValueError):
        fail('В архиве отсутствует корректный манифест.')
    if manifest.get('version') != 1 or manifest.get('files') != {
            name: hashlib.sha256(data).hexdigest() for name, data in sorted(staged.items())}:
        fail('Проверка целостности архива не пройдена.')
    if 'etc/rvkomi-watchdog/telegram.json' not in staged:
        fail('В копии нет настроек контрольного бота.')

    target_exists = any((ROOT / name).exists() for name in CONFIG_FILES)
    if target_exists and input('На сервере уже есть конфигурация. Заменить её импортируемой копией? [yes/no]: ').strip() != 'yes':
        fail('Импорт отменён; существующие настройки не изменены.')
    # Refuse symlinked destination roots and write every file with owner-only permissions.
    for top in (ROOT, STATE):
        if top.is_symlink():
            fail('Каталог состояния является символической ссылкой; импорт отменён.')
        top.mkdir(mode=0o700, parents=True, exist_ok=True)
    for name, data in staged.items():
        if name.startswith('etc/rvkomi-watchdog/'):
            dest = ROOT.joinpath(*PurePosixPath(name).parts[2:])
            base = ROOT
        else:
            dest = STATE.joinpath(*PurePosixPath(name).parts[3:])
            base = STATE
        dest.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if base not in dest.parent.resolve().parents and dest.parent.resolve() != base.resolve():
            fail('Путь назначения выходит за пределы каталога настройки.')
        if any(p.is_symlink() for p in [dest.parent, *dest.parent.parents] if p != base.parent):
            fail('Обнаружена символическая ссылка в пути назначения; импорт остановлен.')
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        with os.fdopen(fd, 'wb') as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.chmod(dest, 0o600)
    minutes = manifest.get('monitor_interval_minutes', 2)
    if isinstance(minutes, int) and 2 <= minutes <= 1440:
        dropin = TIMER_DROPIN
        dropin.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        temporary = dropin.with_suffix('.conf.tmp')
        temporary.write_text('[Timer]\nOnUnitInactiveSec=' + str(minutes) + 'min\n', encoding='utf-8')
        os.chmod(temporary, 0o644)
        os.replace(temporary, dropin)
    print('Конфигурация и ключи восстановлены с правами 0600.')
    if isinstance(minutes, int) and 2 <= minutes <= 1440:
        print('Сохранён интервал мониторинга: ' + str(minutes) + ' минут.')
    print('Перед запуском проверьте SSH-доступ: если внешний IP нового управляющего сервера изменился, узлы могут отклонять ключи, ограниченные прежним IP.')
    print('Один Telegram-токен не должен одновременно опрашиваться на старом и новом серверах.')


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in ('export', 'import'):
        fail('Использование: sudo rvkomi-control-runtime export [файл.enc] | import <файл.enc>')
    if sys.argv[1] == 'export':
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        destination = sys.argv[2] if len(sys.argv) > 2 else f'/root/rvkomi-control-{stamp}.enc'
        export_bundle(destination)
    else:
        if len(sys.argv) != 3:
            fail('Укажите путь к .enc: sudo rvkomi-control-runtime import /root/rvkomi-control-....enc')
        import_bundle(sys.argv[2])


if __name__ == '__main__':
    main()
