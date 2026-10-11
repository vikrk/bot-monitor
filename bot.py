Attempting to perform the InitializeDefaultDrives operation on the 'FileSystem' provider failed.
"""Minimal Telegram controller with one owner Chat ID and explicit approvals."""
import datetime
import html
import json
import os
import sqlite3
import subprocess
import time
import urllib.parse
import urllib.request

from storage import connect, audit

TOKEN = os.environ.get("BOT_TOKEN", "").strip()
OWNER = os.environ.get("BOT_CHAT_ID", "").strip()
CONFIG = os.environ.get("RVKOMI_MANAGER_CONFIG", "/etc/rvkomi-server-manager/manager.json")
SSH_DIR = os.environ.get("RVKOMI_MANAGER_SSH_DIR", "/var/lib/rvkomi-server-manager/ssh")
DB = os.environ.get("RVKOMI_MANAGER_DB", "/var/lib/rvkomi-server-manager/manager.sqlite3")
OFFSET_FILE = os.path.join(os.path.dirname(DB), ".telegram-offset")
PENDING = {}
SERVICE_ALLOWLIST = {"ssh", "nginx", "docker", "telemt", "gotelegram-bot", "gokaskad"}


def tg(method, payload=None, timeout=40):
    url = f"https://api.telegram.org/bot{TOKEN}/{method}"
    body = urllib.parse.urlencode(payload or {}).encode()
    req = urllib.request.Request(url, data=body)
    with urllib.request.urlopen(req, timeout=timeout) as response:
        result = json.load(response)
    if not result.get("ok"):
        raise RuntimeError(result.get("description", "Telegram API error"))
    return result["result"]


def send(chat, text, keyboard=None):
    data = {"chat_id": chat, "text": text, "parse_mode": "HTML"}
    if keyboard:
        data["reply_markup"] = json.dumps({"inline_keyboard": keyboard})
    tg("sendMessage", data)


def edit(chat, message_id, text, keyboard=None):
    data = {"chat_id": chat, "message_id": message_id, "text": text, "parse_mode": "HTML"}
    if keyboard:
        data["reply_markup"] = json.dumps({"inline_keyboard": keyboard})
    tg("editMessageText", data)


def answer(callback_id, text=""):
    tg("answerCallbackQuery", {"callback_query_id": callback_id, "text": text})


def kb(*rows):
    return [[{"text": title, "callback_data": code} for title, code in row] for row in rows]


def main_menu(chat, message_id=None):
    text = "<b>RVKOMI Server Manager</b>\nВыберите действие. Любое изменение требует отдельного подтверждения."
    keyboard = kb(
        [("Узлы", "nodes"), ("Проверить все", "check_all")],
        [("Мониторинг", "monitor"), ("Журнал", "audit")],
        [("Резервная копия", "backup")],
    )
    if message_id: edit(chat, message_id, text, keyboard)
    else: send(chat, text, keyboard)


def nodes_menu(chat, message_id=None):
    with connect() as db:
        rows = db.execute("SELECT id,name,kind,host,last_status FROM nodes WHERE enabled=1 ORDER BY name").fetchall()
    if not rows:
        text, keyboard = "Подключённых узлов нет. Добавьте сервер или роутер в терминальном меню fleetctl.", kb([("Назад", "menu")])
    else:
        text = "<b>Серверы и роутеры</b>\nНажмите узел для проверки и разрешённых действий."
        buttons = [[{"text": f"{r['name']} · {r['last_status'] or 'не проверен'}", "callback_data": f"node:{r['id']}"}] for r in rows]
        buttons.append([{"text": "Назад", "callback_data": "menu"}])
        keyboard = buttons
    if message_id: edit(chat, message_id, text, keyboard)
    else: send(chat, text, keyboard)


def run_ssh(node, remote_command, timeout=15):
    host = node["host"]
    user = node["user"]
    key = node["key_path"]
    cmd = ["ssh", "-i", key, "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
           "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={SSH_DIR}/known_hosts",
           "--", f"{user}@{host}", remote_command]
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        err = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "SSH timeout")
        return subprocess.CompletedProcess(cmd, 124, out, err)


def load_node(node_id):
    with connect() as db:
        return db.execute("SELECT * FROM nodes WHERE id=? AND enabled=1", (node_id,)).fetchone()


def check_node(node):
    # Fixed commands only; user-controlled strings never form remote command text.
    up = run_ssh(node, "uptime", 15)
    if up.returncode:
        status = "недоступен"
        details = (up.stderr or "SSH check failed").strip()[:500]
    else:
        disk = run_ssh(node, "df -P /", 15)
        status = "доступен"
        details = up.stdout.strip()[:350]
        if disk.returncode == 0:
            details += "\n" + disk.stdout.strip()[-350:]
    now = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    with connect() as db:
        db.execute("UPDATE nodes SET last_check=?,last_status=? WHERE id=?", (now, status, node["id"]))
        db.commit()
    audit(OWNER, node["name"], "check", status)
    return status, details


def node_card(chat, message_id, node_id):
    node = load_node(node_id)
    if not node:
        edit(chat, message_id, "Узел не найден.", kb([("Назад", "nodes")]))
        return
    text = f"<b>{html.escape(node['name'])}</b> ({node['kind']})\n<code>{html.escape(node['user'])}@{html.escape(node['host'])}</code>\nПоследняя проверка: {html.escape(node['last_status'] or 'нет данных')}"
    rows = [[("Проверить", f"check:{node_id}")], [("Предложить перезапуск службы", f"restart_menu:{node_id}")], [("Назад", "nodes")]]
    edit(chat, message_id, text, kb(*rows))


def confirmation(chat, message_id, node_id, service):
    node = load_node(node_id)
    if not node or service not in SERVICE_ALLOWLIST:
        edit(chat, message_id, "Узел или служба не разрешены.", kb([("Назад", f"node:{node_id}")]))
        return
    action_id = f"{node_id}:{service}:{int(time.time())}"
    PENDING[action_id] = {"node_id": node_id, "service": service, "expires": time.time() + 180}
    text = (f"<b>Подтвердите действие</b>\nУзел: {html.escape(node['name'])}\n"
            f"Действие: перезапуск службы <code>{service}</code>\n"
            "Запрос действителен 3 минуты.")
    edit(chat, message_id, text, kb([("Подтвердить", f"confirm:{action_id}"), ("Отмена", f"node:{node_id}")]))


def handle_callback(query):
    chat = str(query.get("message", {}).get("chat", {}).get("id", ""))
    if chat != OWNER:
        answer(query["id"], "Доступ закрыт")
        return
    data = query.get("data", "")
    mid = query.get("message", {}).get("message_id")
    answer(query["id"])
    if data == "menu": main_menu(chat, mid)
    elif data == "nodes": nodes_menu(chat, mid)
    elif data == "check_all":
        with connect() as db: ids = [r[0] for r in db.execute("SELECT id FROM nodes WHERE enabled=1")]
        results = []
        for node_id in ids:
            n = load_node(node_id)
            status, _ = check_node(n)
            results.append(f"{html.escape(n['name'])}: {status}")
        edit(chat, mid, "<b>Результаты проверок</b>\n" + ("\n".join(results) or "Нет подключённых узлов."), kb([("Назад", "menu")]))
    elif data == "monitor":
        try:
            with open(CONFIG, encoding="utf-8") as f: minutes = json.load(f).get("monitor_interval_minutes", 15)
        except Exception: minutes = 15
        edit(chat, mid, f"Интервал мониторинга: <b>{int(minutes)} минут</b>. Изменить его можно командой <code>sudo fleetctl</code> на управляющем сервере.", kb([("Проверить сейчас", "check_all"), ("Назад", "menu")]))
    elif data == "audit":
        with connect() as db: rows = db.execute("SELECT at,node,action,result FROM audit ORDER BY id DESC LIMIT 12").fetchall()
        body = "\n".join(f"{html.escape(r['at'])} · {html.escape(r['node'] or 'manager')} · {html.escape(r['action'])}: {html.escape(r['result'])}" for r in rows) or "Журнал пуст."
        edit(chat, mid, "<b>Последние действия</b>\n" + body, kb([("Назад", "menu")]))
    elif data == "backup":
        with connect() as db:
            db.execute("PRAGMA wal_checkpoint(FULL)")
            backup_path = os.path.join(os.path.dirname(DB), "manager-backup.sqlite3")
            dst = sqlite3.connect(backup_path)
            db.backup(dst); dst.close()
        os.chmod(backup_path, 0o600)
        audit(OWNER, None, "backup", "created locally")
        edit(chat, mid, "Резервная копия базы создана на управляющем сервере. Токен бота и SSH-ключи в неё не входят.", kb([("Назад", "menu")]))
    elif data.startswith("node:"):
        try: node_card(chat, mid, int(data.split(":", 1)[1]))
        except ValueError: edit(chat, mid, "Неверный номер узла.", kb([("Назад", "nodes")]))
    elif data.startswith("check:"):
        try: node = load_node(int(data.split(":", 1)[1]))
        except ValueError: node = None
        if node:
            status, details = check_node(node)
            edit(chat, mid, f"<b>{html.escape(node['name'])}: {status}</b>\n<pre>{html.escape(details)}</pre>", kb([("Назад к узлу", f"node:{node['id']}")]))
        else: edit(chat, mid, "Узел не найден.", kb([("Назад", "nodes")]))
    elif data.startswith("restart_menu:"):
        try: node_id = int(data.split(":", 1)[1])
        except ValueError: node_id = -1
        allowed = sorted(SERVICE_ALLOWLIST)
        rows = [[(f"Перезапустить {s}", f"restart:{node_id}:{s}")] for s in allowed]
        rows.append([("Назад", f"node:{node_id}")])
        edit(chat, mid, "Выберите службу. Доступны только фиксированные имена из списка разрешённых служб.", kb(*rows))
    elif data.startswith("restart:"):
        parts = data.split(":", 2)
        if len(parts) == 3:
            try: confirmation(chat, mid, int(parts[1]), parts[2])
            except ValueError: edit(chat, mid, "Неверные параметры.", kb([("Назад", "nodes")]))
    elif data.startswith("confirm:"):
        action_id = data[len("confirm:"):]
        action = PENDING.pop(action_id, None)
        if not action or action["expires"] < time.time():
            edit(chat, mid, "Подтверждение истекло. Запросите действие ещё раз.", kb([("Назад", "nodes")]))
            return
        node = load_node(action["node_id"])
        service = action["service"]
        if not node or service not in SERVICE_ALLOWLIST:
            edit(chat, mid, "Узел или служба не разрешены.", kb([("Назад", "nodes")]))
            return
        # service is selected from a hard-coded allowlist, never from free text.
        privilege = "" if node["user"] == "root" else "sudo -n "
        result = run_ssh(node, f"{privilege}systemctl restart {service}", 25)
        outcome = "запрос выполнен" if result.returncode == 0 else "не удалось: " + (result.stderr or result.stdout).strip()[:350]
        audit(OWNER, node["name"], "restart " + service, outcome)
        edit(chat, mid, f"<b>{html.escape(outcome)}</b>", kb([("Назад к узлу", f"node:{node['id']}")]))
    else:
        edit(chat, mid, "Неизвестная команда.", kb([("Меню", "menu")]))


def handle_message(message):
    chat = str(message.get("chat", {}).get("id", ""))
    text = message.get("text", "")
    if chat != OWNER:
        # Do not disclose owner or inventory to unknown chats.
        return
    if text.startswith("/start") or text.startswith("/menu"):
        main_menu(chat)
    elif text.startswith("/id"):
        send(chat, f"Ваш Chat ID: <code>{html.escape(chat)}</code>")
    elif text.startswith("/help"):
        send(chat, "Команды: /start, /menu, /help. Перезапуски выполняются только после нажатия подтверждения.")


def monitor_once():
    with connect() as db:
        nodes = db.execute("SELECT id FROM nodes WHERE enabled=1").fetchall()
    alerts = []
    for row in nodes:
        node = load_node(row["id"])
        status, details = check_node(node)
        if status != "доступен": alerts.append(f"{node['name']}: {details[:250]}")
    if alerts and OWNER:
        send(OWNER, "<b>Проблемы мониторинга</b>\n" + "\n".join(html.escape(x) for x in alerts))


def main():
    if not TOKEN or not OWNER:
        raise SystemExit("BOT_TOKEN or BOT_CHAT_ID is not configured; run sudo fleetctl")
    try: offset = int(open(OFFSET_FILE, encoding="utf-8").read().strip())
    except Exception: offset = 0
    last_monitor = 0.0
    while True:
        try:
            try:
                with open(CONFIG, encoding="utf-8") as f: interval = max(5, min(1440, int(json.load(f).get("monitor_interval_minutes", 15))))
            except Exception: interval = 15
            if time.time() - last_monitor >= interval * 60:
                monitor_once(); last_monitor = time.time()
            updates = tg("getUpdates", {"offset": offset, "timeout": 25, "allowed_updates": json.dumps(["message", "callback_query"])}, timeout=35)
            for update in updates:
                offset = int(update["update_id"]) + 1
                with open(OFFSET_FILE, "w", encoding="utf-8") as f: f.write(str(offset))
                if "callback_query" in update: handle_callback(update["callback_query"])
                elif "message" in update: handle_message(update["message"])
        except KeyboardInterrupt:
            break
        except Exception as exc:
            print(f"manager loop error: {type(exc).__name__}: {exc}", flush=True)
            time.sleep(4)


if __name__ == "__main__": main()

