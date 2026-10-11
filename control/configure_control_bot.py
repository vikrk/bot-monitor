#!/usr/bin/python3
"""BotFather token + /start enrollment with explicit private-owner selection."""
import getpass
import json
import os
import re
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

CONFIG = Path('/etc/rvkomi-watchdog/telegram.json')


def api(token, method, payload=None):
    request = urllib.request.Request('https://api.telegram.org/bot' + token + '/' + method,
        data=json.dumps(payload or {}).encode(), headers={'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(request, timeout=20) as response: result = json.load(response)
    except urllib.error.HTTPError as exc: raise RuntimeError('Telegram HTTP ' + str(exc.code)) from None
    except Exception: raise RuntimeError('Telegram недоступен') from None
    if not result.get('ok'): raise RuntimeError('Telegram отклонил запрос')
    return result['result']


def main():
    if os.geteuid() != 0: raise SystemExit('Запустите: sudo rvkomi-control-setup')
    try: old = json.loads(CONFIG.read_text())
    except (OSError, ValueError): old = {}
    print('Создайте своего бота у @BotFather. Поддерживается любой действующий Telegram bot token.')
    token = getpass.getpass('Токен бота (скрыто; Enter — сохранить прежний): ').strip() or old.get('bot_token', '')
    if not re.fullmatch(r'\d{5,20}:[A-Za-z0-9_-]{20,}', token): raise SystemExit('Неверный формат токена')
    me = api(token, 'getMe')
    if api(token, 'getWebhookInfo').get('url'): raise SystemExit('Для polling требуется бот без активного webhook')
    print('Бот: @' + me['username'])
    print('1. Получить ID по /start\n2. Ввести ID личного чата вручную' + ('\n3. Оставить текущего администратора' if old.get('chat_id') else ''))
    mode = input('Выбор [1]: ').strip() or '1'
    was_active = False
    try:
        if mode == '1':
            was_active = subprocess.run(['systemctl', 'is-active', '--quiet', 'rvkomi-telegram-control.service']).returncode == 0
            if was_active: subprocess.run(['systemctl', 'stop', 'rvkomi-telegram-control.service'], check=True)
            started = time.time() - 120
            input('Откройте @' + me['username'] + ', отправьте /start и нажмите Enter здесь: ')
            candidates = {}
            for update in api(token, 'getUpdates', {'timeout': 0, 'allowed_updates': ['message']}):
                message = update.get('message', {})
                chat = message.get('chat', {})
                sender = message.get('from', {})
                if (chat.get('type') == 'private' and chat.get('id') == sender.get('id') and not sender.get('is_bot')
                    and not message.get('forward_origin') and not message.get('forward_from')
                    and message.get('date', 0) >= started and message.get('text', '').split()[:1] == ['/start']):
                    candidates[chat['id']] = sender.get('username') or sender.get('first_name') or str(chat['id'])
            if not candidates: raise RuntimeError('Свежий /start не найден. Повторите или введите ID вручную.')
            choices = list(candidates)
            for index, identifier in enumerate(choices, 1): print(str(index) + '. ID ' + str(identifier) + ' (' + str(candidates[identifier]) + ')')
            selected = input('Номер вашего аккаунта [1]: ').strip() or '1'
            if not selected.isdigit() or not 1 <= int(selected) <= len(choices): raise RuntimeError('Неверный номер аккаунта')
            owner = choices[int(selected) - 1]
        elif mode == '2': owner = int(input('ID личного чата администратора: ').strip())
        elif mode == '3' and old.get('chat_id'): owner = int(old['chat_id'])
        else: raise RuntimeError('Неверный пункт')
        if owner <= 0 or api(token, 'getChat', {'chat_id': owner}).get('type') != 'private':
            raise RuntimeError('Нужен положительный ID личного чата владельца')
        if input('Назначить администратора ID ' + str(owner) + '? [yes]: ').strip() != 'yes': return
        CONFIG.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix='.telegram.', dir=str(CONFIG.parent))
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, 'w', encoding='utf-8') as target:
                json.dump({'bot_token': token, 'chat_id': owner}, target)
            os.replace(temporary, CONFIG)
        finally:
            try: os.unlink(temporary)
            except FileNotFoundError: pass
        print('Бот и администратор настроены. Файл telegram.json — 0600.')
    finally:
        if was_active: subprocess.run(['systemctl', 'start', 'rvkomi-telegram-control.service'], check=False)


if __name__ == '__main__': main()
