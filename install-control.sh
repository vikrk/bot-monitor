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
DEBIAN_FRONTEND=noninteractive apt-get install -y python3 python3-cryptography python3-paramiko openssh-client ca-certificates
install -d -o root -g root -m 0755 "$BASE"
install -d -o root -g root -m 0700 "$ROOT"
install -d -o root -g root -m 0700 /var/lib/rvkomi-watchdog
install -m 0644 "$SOURCE_DIR"/*.py "$BASE/"
chmod 0755 "$BASE/telegram-control.py" "$BASE/advanced.py" "$BASE/extra-monitor.py"
chmod 0755 "$BASE/configure_control_bot.py" "$BASE/configure_ai.py" "$BASE/runtime_bundle.py" "$BASE/verify_install.py" "$BASE/configure_monitor_interval.py" "$BASE/reauthorize_nodes.py" "$BASE/configure_router_proxy.py"
for unit in "$SOURCE_DIR"/systemd/*.service "$SOURCE_DIR"/systemd/*.timer; do
    [ -f "$unit" ] || continue
    install -o root -g root -m 0644 "$unit" "/etc/systemd/system/$(basename "$unit")"
done
ln -sf "$BASE/configure_control_bot.py" /usr/local/bin/rvkomi-control-setup
ln -sf "$BASE/configure_ai.py" /usr/local/bin/rvkomi-ai-setup
ln -sf "$BASE/runtime_bundle.py" /usr/local/bin/rvkomi-control-runtime
ln -sf "$BASE/verify_install.py" /usr/local/bin/rvkomi-control-verify
ln -sf "$BASE/reauthorize_nodes.py" /usr/local/bin/rvkomi-control-authorize
ln -sf "$BASE/configure_monitor_interval.py" /usr/local/bin/rvkomi-monitor-interval
ln -sf "$BASE/configure_router_proxy.py" /usr/local/bin/rvkomi-router-proxy-setup
systemctl daemon-reload

if [ ! -f "$ROOT/control-nodes.json" ] || [ ! -f "$ROOT/extra-nodes.json" ]; then
    echo "Для полной установки нужны SSH-конфигурации восьми узлов из действующего управляющего сервера."
    echo "На старом сервере выполните: sudo rvkomi-control-runtime export"
    read -r -p "Путь к зашифрованной копии на этом сервере (пусто — выйти без запуска): " RUNTIME_BUNDLE
    if [ -z "$RUNTIME_BUNDLE" ]; then
        echo "Установка кода завершена; мониторинг не запущен, конфигурация узлов отсутствует." >&2
        exit 3
    fi
    rvkomi-control-runtime import "$RUNTIME_BUNDLE"
fi

if [ ! -f "$ROOT/telegram.json" ]; then
    echo "Настройка существующего контрольного Telegram-бота. Токен вводится скрыто."
    rvkomi-control-setup
fi

echo "Проверяю SSH/RPC-доступность всех настроенных узлов. Изменений на узлах не выполняется."
if ! rvkomi-control-verify; then
    echo "Если сменился публичный IP управляющего сервера, существующие SSH-ключи могли быть ограничены старым IP."
    read -r -p "Обновить разрешённый IP на узлах через проверенный SSH fingerprint и root-пароли? [yes/no]: " AUTHORIZE_NODES
    if [ "$AUTHORIZE_NODES" = "yes" ]; then
        rvkomi-control-authorize
        rvkomi-control-verify
    else
        echo "Установка остановлена до восстановления SSH-доступа. Службы мониторинга не запускались." >&2
        exit 5
    fi
fi

if [ ! -f "$ROOT/ai.json" ]; then
    read -r -p "Настроить OpenAI API для ИИ-диагностики сейчас? [y/N] " SETUP_AI
    case "$SETUP_AI" in y|Y|yes|YES) rvkomi-ai-setup ;; esac
fi

read -r -p "Интервал проверок в минутах (2–1440) [2]: " MONITOR_INTERVAL
if [ -n "$MONITOR_INTERVAL" ]; then
    printf '%s\n' "$MONITOR_INTERVAL" | grep -qE '^[0-9]{1,4}$' || { echo "Неверный интервал." >&2; exit 2; }
    [ "$MONITOR_INTERVAL" -ge 2 ] && [ "$MONITOR_INTERVAL" -le 1440 ] || { echo "Интервал должен быть от 2 до 1440 минут." >&2; exit 2; }
    install -d -o root -g root -m 0755 /etc/systemd/system/rvkomi-extra-monitor.timer.d
    printf '[Timer]\nOnUnitInactiveSec=%smin\n' "$MONITOR_INTERVAL" > /etc/systemd/system/rvkomi-extra-monitor.timer.d/override.conf
    chmod 0644 /etc/systemd/system/rvkomi-extra-monitor.timer.d/override.conf
fi

echo "Остановите polling этого же Telegram-бота на старом управляющем сервере, затем подтвердите запуск здесь."
read -r -p "Старый polling остановлен или это первичная установка? [yes/no]: " START_CONTROL
[ "$START_CONTROL" = "yes" ] || { echo "Службы не запускались. Повторите установку после остановки старого polling." >&2; exit 4; }

python3 "$BASE/telegram-control.py" register
systemctl daemon-reload
systemctl enable --now rvkomi-telegram-control.service rvkomi-extra-monitor.timer rvkomi-certificates.timer
systemctl restart rvkomi-telegram-control.service
if [ -f "$ROOT/backup-webdav.json" ] && [ -f "$ROOT/backup-recovery.key" ]; then
    systemctl enable --now rvkomi-backup.timer
fi
if [ -f "$ROOT/router-agent.json" ]; then
    ROUTER_PROXY_READY=0
    if ! command -v nginx >/dev/null 2>&1; then
        if command -v ss >/dev/null 2>&1 && ss -ltnH '( sport = :443 )' | grep -q .; then
            echo "Порт 443 уже занят; Nginx для роутера автоматически не устанавливаю."
        else
            DEBIAN_FRONTEND=noninteractive apt-get install -y nginx
        fi
    fi
    if rvkomi-router-proxy-setup; then
        ROUTER_PROXY_READY=1
    fi
    if [ "$ROUTER_PROXY_READY" -eq 1 ]; then
        systemctl enable --now rvkomi-router-receiver.service rvkomi-router-monitor.timer
    else
        echo "Настройки агента сохранены, но receiver/monitor роутера не запущены: сначала настройте HTTPS proxy и DNS."
    fi
else
    echo "Настройки домашнего роутера отсутствуют; его receiver и таймер не запускались."
fi

echo "Полная установка завершена: контрольный бот, SSH-мониторинг и доступные по runtime-копии таймеры включены."
echo "Проверки доступны в Telegram; ИИ запускается кнопкой «ИИ-анализ всех узлов»."

