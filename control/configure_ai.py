#!/usr/bin/python3
"""Securely configure the optional AI provider for the RVKOMI control bot."""
import getpass
import json
import os
import re
import tempfile
from pathlib import Path
from urllib.parse import urlparse

CONFIG = Path("/etc/rvkomi-watchdog/ai.json")


def main():
    if os.geteuid() != 0:
        raise SystemExit("Запустите от root: sudo rvkomi-ai-setup")
    old = {}
    try:
        old = json.loads(CONFIG.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        pass
    base = input("HTTPS URL API [https://api.openai.com/v1]: ").strip() or "https://api.openai.com/v1"
    model = input("Модель: ").strip()
    key = getpass.getpass("API-ключ (ввод скрыт; Enter оставить прежний): ").strip()
    if not key:
        key = str(old.get("api_key", ""))
    parsed = urlparse(base)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise SystemExit("Нужен корректный HTTPS URL без логина, пароля, query или fragment.")
    if not re.fullmatch(r"[A-Za-z0-9_.:/-]{1,160}", model):
        raise SystemExit("Некорректное имя модели.")
    if not key:
        raise SystemExit("API-ключ обязателен.")
    CONFIG.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".ai.", dir=str(CONFIG.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as target:
            json.dump({"base_url": base.rstrip("/"), "model": model, "api_key": key}, target)
            target.write("\n")
        os.replace(temporary, CONFIG)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
    print("Настройки ИИ сохранены в /etc/rvkomi-watchdog/ai.json (права 0600).")


if __name__ == "__main__":
    main()

