Attempting to perform the InitializeDefaultDrives operation on the 'FileSystem' provider failed.
#!/usr/bin/python3
"""Create Telegram credentials without echoing the bot token."""
import getpass
import json
import os
import re
import tempfile
from pathlib import Path

CONFIG = Path("/etc/rvkomi-watchdog/telegram.json")


def main():
    if os.geteuid() != 0:
        raise SystemExit("Запустите от root: sudo rvkomi-control-setup")
    try:
        old = json.loads(CONFIG.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        old = {}
    token = getpass.getpass("Токен существующего управляющего Telegram-бота (ввод скрыт; Enter оставить прежний): ").strip()
    if not token:
        token = str(old.get("bot_token", ""))
    chat_id = input("ID личного чата администратора: ").strip() or str(old.get("chat_id", ""))
    if not re.fullmatch(r"\d{5,15}:[A-Za-z0-9_-]{20,}", token):
        raise SystemExit("Формат токена Telegram не распознан.")
    if not re.fullmatch(r"[1-9]\d{4,14}", chat_id):
        raise SystemExit("Нужен положительный числовой ID личного чата.")
    CONFIG.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".telegram.", dir=str(CONFIG.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as target:
            json.dump({"bot_token": token, "chat_id": int(chat_id)}, target)
            target.write("\n")
        os.replace(temporary, CONFIG)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
    print("Настройки бота сохранены в /etc/rvkomi-watchdog/telegram.json (права 0600).")


if __name__ == "__main__":
    main()

