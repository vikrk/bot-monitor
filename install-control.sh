Attempting to perform the InitializeDefaultDrives operation on the 'FileSystem' provider failed.
#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then echo "Run as root: sudo bash install-control.sh" >&2; exit 1; fi
if ! grep -qiE 'ubuntu|debian' /etc/os-release; then echo "Ubuntu/Debian required" >&2; exit 1; fi

SOURCE_DIR="$(cd "$(dirname "$0")" && pwd)/control"
BASE=/usr/local/lib/rvkomi-watchdog
ROOT=/etc/rvkomi-watchdog

if [ ! -f "$SOURCE_DIR/telegram-control.py" ] || [ ! -f "$SOURCE_DIR/advanced.py" ]; then
    echo "Control bot sources are missing from $SOURCE_DIR" >&2
    exit 1
fi

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y python3 openssh-client ca-certificates
install -d -o root -g root -m 0755 "$BASE"
install -d -o root -g root -m 0700 "$ROOT"
install -d -o root -g root -m 0700 /var/lib/rvkomi-watchdog
install -m 0644 "$SOURCE_DIR"/*.py "$BASE/"
chmod 0755 "$BASE/telegram-control.py" "$BASE/advanced.py" "$BASE/extra-monitor.py"
chmod 0755 "$BASE/configure_control_bot.py" "$BASE/configure_ai.py"
for unit in "$SOURCE_DIR"/systemd/*.service "$SOURCE_DIR"/systemd/*.timer; do
    [ -f "$unit" ] || continue
    install -o root -g root -m 0644 "$unit" "/etc/systemd/system/$(basename "$unit")"
done
ln -sf "$BASE/configure_control_bot.py" /usr/local/bin/rvkomi-control-setup
ln -sf "$BASE/configure_ai.py" /usr/local/bin/rvkomi-ai-setup
systemctl daemon-reload

echo "Код rvkomi-telegram-control установлен. Конфигурация и история сохранены отдельно от исходников."
echo "Настройте бота: sudo rvkomi-control-setup"
echo "Настройте ИИ позже, когда будет API-ключ: sudo rvkomi-ai-setup"
echo "До запуска убедитесь, что этот bot_token не опрашивается одновременно на другом сервере."
echo "Подключите защищённые node-конфигурации в $ROOT; установщик не переносит ключи и секреты из GitHub."
echo "После подготовки настроек: sudo systemctl enable --now rvkomi-telegram-control.service"

