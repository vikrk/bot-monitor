#!/usr/bin/env bash
set -euo pipefail

echo "Установочный комплект RVKOMI"
echo "1. Установить Telegram-контроль и настроить свои серверы/роутеры"
echo "2. Установить отдельный Server Manager (другая Telegram-служба)"
read -r -p "Выбор [1]: " choice
choice=${choice:-1}
case "$choice" in
    1) exec bash "$(dirname "$0")/install-control.sh" ;;
    2) exec bash "$(dirname "$0")/install-server-manager.sh" ;;
    *) echo "Выберите 1 или 2." >&2; exit 2 ;;
esac

