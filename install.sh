Attempting to perform the InitializeDefaultDrives operation on the 'FileSystem' provider failed.
#!/usr/bin/env bash
set -euo pipefail

BASE=/opt/rvkomi-server-manager
ETC=/etc/rvkomi-server-manager
STATE=/var/lib/rvkomi-server-manager
SERVICE=rvkomi-server-manager

if [ "$(id -u)" -ne 0 ]; then echo "Run as root: sudo bash install.sh" >&2; exit 1; fi
if ! grep -qiE 'ubuntu|debian' /etc/os-release; then echo "Ubuntu/Debian required" >&2; exit 1; fi
read -r -p "Название основного сервера: " MANAGER_NAME
if ! python3 -c 'import re,sys; sys.exit(0 if re.fullmatch(r"[\w.-]{1,48}", sys.argv[1]) else 1)' "$MANAGER_NAME"; then
    echo "Название должно содержать 1–48 букв, цифр, точек, дефисов или подчёркиваний." >&2
    exit 1
fi
systemctl stop "$SERVICE.service" 2>/dev/null || true
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y python3 python3-venv python3-pip openssh-client ca-certificates sudo
getent group rvkomi-manager >/dev/null || groupadd --system rvkomi-manager
id -u rvkomi-manager >/dev/null 2>&1 || useradd --system --gid rvkomi-manager --home-dir "$STATE" --create-home --shell /usr/sbin/nologin rvkomi-manager
install -d -o root -g rvkomi-manager -m 0750 "$BASE" "$ETC"
install -d -o rvkomi-manager -g rvkomi-manager -m 0700 "$STATE" "$STATE/ssh"
cp -a "$(cd "$(dirname "$0")" && pwd)/." "$BASE/"
python3 -m venv "$BASE/venv"
"$BASE/venv/bin/pip" install --disable-pip-version-check -r "$BASE/requirements.txt"
chown -R root:rvkomi-manager "$BASE"
chmod -R u=rwX,g=rX,o= "$BASE"
chmod 0750 "$BASE/fleetctl.py"
ln -sf "$BASE/fleetctl.py" /usr/local/bin/fleetctl
install -o root -g rvkomi-manager -m 0640 "$BASE/rvkomi-server-manager.service" /etc/systemd/system/rvkomi-server-manager.service
if [ ! -e "$ETC/bot.env" ]; then install -o root -g rvkomi-manager -m 0640 /dev/null "$ETC/bot.env"; fi
if [ ! -e "$ETC/manager.json" ]; then
cat > "$ETC/manager.json" <<'JSON'
{"monitor_interval_minutes": 15, "allowed_restart_services": ["ssh", "nginx", "docker", "telemt", "gotelegram-bot", "gokaskad"]}
JSON
fi
chown root:rvkomi-manager "$ETC/manager.json"
chmod 0640 "$ETC/manager.json"
cat > /etc/sudoers.d/rvkomi-server-manager <<'SUDOERS'
rvkomi-manager ALL=(root) NOPASSWD: /usr/bin/systemctl restart ssh, /usr/bin/systemctl restart nginx, /usr/bin/systemctl restart docker, /usr/bin/systemctl restart telemt, /usr/bin/systemctl restart gotelegram-bot, /usr/bin/systemctl restart gokaskad
SUDOERS
chmod 0440 /etc/sudoers.d/rvkomi-server-manager
visudo -cf /etc/sudoers.d/rvkomi-server-manager
chown -R rvkomi-manager:rvkomi-manager "$STATE"
runuser -u rvkomi-manager -- "$BASE/venv/bin/python" "$BASE/fleetctl.py" --register-main "$MANAGER_NAME"
systemctl daemon-reload
if grep -q '^BOT_TOKEN=.' "$ETC/bot.env" && grep -q '^BOT_CHAT_ID=.' "$ETC/bot.env"; then
    systemctl enable --now "$SERVICE.service"
    echo "Установка завершена. Основной сервер зарегистрирован; служба Telegram запущена."
else
    echo "Установка завершена. Основной сервер зарегистрирован. Для Telegram-управления запустите sudo fleetctl и выберите пункт 3."
fi
echo "Администрирование: sudo fleetctl"

