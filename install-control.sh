#!/usr/bin/env bash
set -euo pipefail
if [ "$(id -u)" -ne 0 ]; then echo "Запустите: sudo bash install.sh" >&2; exit 1; fi
if ! grep -qiE 'ubuntu|debian' /etc/os-release; then echo "Требуется Ubuntu/Debian" >&2; exit 1; fi
SOURCE_DIR="$(cd "$(dirname "$0")" && pwd)/control"
BASE=/usr/local/lib/rvkomi-watchdog
ROOT=/etc/rvkomi-watchdog
for file in telegram-control.py fleet.py fleetctl.py node_agent.py generic_control.py configure_logging.py ai_admin.py portable_admin.py admin_executor.py history_diagnostics.py dns_admin.py adguard_filters.py sni_admin.py; do
    [ -f "$SOURCE_DIR/$file" ] || { echo "Не найден $SOURCE_DIR/$file" >&2; exit 1; }
done
echo "Будут установлены: Telegram-контрольный бот, локальный мониторинг, SSH-агент для подключаемых узлов и планировщики."
echo "Серверы, службы и маршруты настраиваются по вашим подключениям через fleetctl."
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/configure-mtu.sh"
read -r -p "Название управляющего сервера [$(hostname -s)]: " MANAGER_NAME
MANAGER_NAME=${MANAGER_NAME:-$(hostname -s)}
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y python3 python3-cryptography python3-paramiko python3-yaml logrotate dnsutils openssh-client ca-certificates iputils-ping
if [ -d "$BASE" ]; then
    BACKUP_DIR="/var/backups/rvkomi-control/$(date -u +%Y%m%dT%H%M%SZ)"
    install -d -m 0700 "$BACKUP_DIR"
    cp -a "$BASE" "$BACKUP_DIR/code"
    echo "Предыдущий код сохранён: $BACKUP_DIR/code"
fi
install -d -o root -g root -m 0755 "$BASE"
install -d -o root -g root -m 0700 "$ROOT" /var/lib/rvkomi-watchdog
install -m 0755 "$SOURCE_DIR"/*.py "$BASE/"
for unit in "$SOURCE_DIR"/systemd/*.service "$SOURCE_DIR"/systemd/*.timer; do
    install -o root -g root -m 0644 "$unit" "/etc/systemd/system/$(basename "$unit")"
done
ln -sf "$BASE/fleetctl.py" /usr/local/bin/fleetctl
ln -sf "$BASE/configure_control_bot.py" /usr/local/bin/rvkomi-control-setup
ln -sf "$BASE/configure_ai.py" /usr/local/bin/rvkomi-ai-setup
ln -sf "$BASE/runtime_bundle.py" /usr/local/bin/rvkomi-control-runtime
ln -sf "$BASE/verify_install.py" /usr/local/bin/rvkomi-control-verify
ln -sf "$BASE/configure_monitor_interval.py" /usr/local/bin/rvkomi-monitor-interval
ln -sf "$BASE/reauthorize_nodes.py" /usr/local/bin/rvkomi-control-authorize
ln -sf "$BASE/configure_router_proxy.py" /usr/local/bin/rvkomi-router-proxy-setup
ln -sf "$BASE/configure_logging.py" /usr/local/bin/rvkomi-logging-setup
systemctl daemon-reload
echo "Настройка журналов: journald/Xray/nginx — 72h, AdGuard — 6h."
python3 "$BASE/configure_logging.py" install --agent-dir "$ROOT"
HAD_FLEET=0
[ ! -f "$ROOT/fleet.json" ] || HAD_FLEET=1
fleetctl --init "$MANAGER_NAME"
if [ "$HAD_FLEET" -eq 0 ] && { [ -f "$ROOT/control-nodes.json" ] || [ -f "$ROOT/extra-nodes.json" ]; }; then
    read -r -p "Найдены прежние списки узлов. Добавить их как существующие агенты? [y/N]: " ADOPT_LEGACY
    case "$ADOPT_LEGACY" in y|Y) fleetctl --adopt-legacy ;; esac
fi
if [ ! -f "$ROOT/telegram.json" ]; then
    rvkomi-control-setup
else
    read -r -p "Использовать сохранённые настройки Telegram-бота? [Y/n]: " KEEP_BOT
    case "$KEEP_BOT" in n|N) rvkomi-control-setup ;; esac
fi
if [ ! -f "$ROOT/ai.json" ]; then
    read -r -p "Настроить ИИ сейчас? [y/N]: " SETUP_AI
    case "$SETUP_AI" in y|Y) rvkomi-ai-setup ;; esac
fi
echo "Полномочия ИИ задаются отдельно: разрешённые службы, Xray, AdGuard, адрес relay/FIN и SNI."
fleetctl --configure-main
rvkomi-monitor-interval --configure-only
rvkomi-control-verify
python3 "$BASE/telegram-control.py" register
systemctl enable --now rvkomi-telegram-control.service rvkomi-extra-monitor.timer rvkomi-certificates.timer
systemctl restart rvkomi-telegram-control.service
systemctl start --no-block rvkomi-extra-monitor.service
echo "Бот и мониторинг управляющего сервера запущены. Узлы добавляются командой sudo fleetctl."
echo "Зашифрованная копия — отдельный пункт восстановления, для обычной установки не требуется."
fleetctl
