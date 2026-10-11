"""Minimal Telegram controller with one owner Chat ID and explicit approvals."""
import datetime
import html
import json
import os
import re
import sqlite3
import subprocess
import threading
import time
import urllib.parse
import urllib.request

from storage import connect, audit, record_check
from dns_monitor import DNS_ROUTE_DEFAULTS, check_dns_routes, validate_endpoint, validate_querylog_path
from ai_diagnostics import analyze as ai_analyze, read_service_logs

TOKEN = os.environ.get("BOT_TOKEN", "").strip()
OWNER = os.environ.get("BOT_CHAT_ID", "").strip()
CONFIG = os.environ.get("RVKOMI_MANAGER_CONFIG", "/etc/rvkomi-server-manager/manager.json")
SSH_DIR = os.environ.get("RVKOMI_MANAGER_SSH_DIR", "/var/lib/rvkomi-server-manager/ssh")
DB = os.environ.get("RVKOMI_MANAGER_DB", "/var/lib/rvkomi-server-manager/manager.sqlite3")
OFFSET_FILE = os.path.join(os.path.dirname(DB), ".telegram-offset")
PENDING = {}
TEXT_PENDING = {}
DNS_CHECKS = set()
DNS_CHECKS_LOCK = threading.Lock()
AI_CHECKS = set()
AI_CHECKS_LOCK = threading.Lock()
SERVICE_ALLOWLIST = {"ssh", "nginx", "docker", "gokaskad", "rvkomi-server-manager", "AdGuardHome", "kaskad-egress", "kaskad-bot", "kaskad-monitor"}
DIAGNOSTIC_SERVICES = SERVICE_ALLOWLIST


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
    return tg("sendMessage", data)


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
        [("DNS-маршруты", "dns_nodes")],
        [("Мониторинг", "monitor"), ("Журнал", "audit")],
        [("Резервная копия", "backup")],
    )
    if message_id: edit(chat, message_id, text, keyboard)
    else: send(chat, text, keyboard)


def nodes_menu(chat, message_id=None):
    with connect() as db:
        rows = db.execute("SELECT id,name,kind,fingerprint,last_status FROM nodes WHERE enabled=1 ORDER BY name").fetchall()
    if not rows:
        text, keyboard = "Подключённых узлов нет. Добавьте сервер или роутер в терминальном меню fleetctl.", kb([("Назад", "menu")])
    else:
        text = "<b>Серверы и роутеры</b>\nНажмите узел для проверки и разрешённых действий."
        buttons = [[{"text": f"{r['name']} · {'основной · ' if r['fingerprint'] == 'local' else ''}{r['last_status'] or 'не проверен'}", "callback_data": f"node:{r['id']}"}] for r in rows]
        buttons.append([{"text": "Назад", "callback_data": "menu"}])
        keyboard = buttons
    if message_id: edit(chat, message_id, text, keyboard)
    else: send(chat, text, keyboard)


def run_ssh(node, remote_command, timeout=15):
    if node["fingerprint"] == "local":
        if remote_command == "uptime":
            cmd = ["/usr/bin/uptime"]
        elif remote_command == "df -P /":
            cmd = ["/usr/bin/df", "-P", "/"]
        else:
            match = re.fullmatch(r"(?:sudo -n )?systemctl restart ([A-Za-z0-9@_.-]+)", remote_command)
            log_match = re.fullmatch(r"journalctl --no-pager --since '2 hours ago' -n 80 -u ([A-Za-z0-9@_.-]{1,80})\.service", remote_command)
            if log_match and log_match.group(1) in DIAGNOSTIC_SERVICES:
                cmd = ["/usr/bin/journalctl", "--no-pager", "--since", "2 hours ago", "-n", "80", "-u", log_match.group(1) + ".service"]
            elif match and match.group(1) in SERVICE_ALLOWLIST:
                cmd = ["/usr/bin/sudo", "-n", "/usr/bin/systemctl", "restart", match.group(1)]
            else:
                return subprocess.CompletedProcess([], 2, "", "Local command is not allowed")
        try:
            return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        except subprocess.TimeoutExpired as exc:
            return subprocess.CompletedProcess(cmd, 124, exc.stdout or "", exc.stderr or "Command timeout")
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
        else:
            details += "\nПроверка диска завершилась ошибкой: " + (disk.stderr or disk.stdout or "неизвестная ошибка").strip()[:250]
    now = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    with connect() as db:
        db.execute("UPDATE nodes SET last_check=?,last_status=? WHERE id=?", (now, status, node["id"]))
        db.commit()
    audit(OWNER, node["name"], "check", status)
    record_check(node["id"], "ssh_basic", status, details)
    return status, details


def node_card(chat, message_id, node_id):
    node = load_node(node_id)
    if not node:
        edit(chat, message_id, "Узел не найден.", kb([("Назад", "nodes")]))
        return
    role = "основной сервер" if node["fingerprint"] == "local" else node["kind"]
    text = f"<b>{html.escape(node['name'])}</b> ({role})\n<code>{html.escape(node['user'])}@{html.escape(node['host'])}</code>\nПоследняя проверка: {html.escape(node['last_status'] or 'нет данных')}"
    rows = [[("Проверить", f"check:{node_id}"), ("ИИ-диагностика", f"ai_diag:{node_id}")], [("DNS-маршруты", f"dns_menu:{node_id}")], [("Предложить перезапуск службы", f"restart_menu:{node_id}")], [("Назад", "nodes")]]
    edit(chat, message_id, text, kb(*rows))


def dns_node_rows(exclude_id=None):
    with connect() as db:
        if exclude_id is None:
            return db.execute("SELECT id,name,host FROM nodes WHERE enabled=1 ORDER BY name").fetchall()
        return db.execute("SELECT id,name,host FROM nodes WHERE enabled=1 AND id<>? ORDER BY name", (exclude_id,)).fetchall()


def dns_nodes_menu(chat, message_id):
    with connect() as db:
        rows = db.execute("SELECT id,name,last_status FROM nodes WHERE enabled=1 ORDER BY name").fetchall()
    keyboard = [[(f"{row['name']} · {row['last_status'] or 'не проверен'}", f"dns_menu:{row['id']}")] for row in rows]
    keyboard.append([("Назад", "menu")])
    edit(chat, message_id, "<b>DNS-маршруты</b>\nВыбери узел AdGuard: здесь задаются endpoints и проверка доставки запросов по журналу AdGuard.", kb(*keyboard))


def dns_routes_menu(chat, message_id, node_id, note=""):
    node = load_node(node_id)
    if not node:
        edit(chat, message_id, "Узел не найден.", kb([("К узлам", "dns_nodes")]))
        return
    with connect() as db:
        routes = db.execute("SELECT id,route_type,endpoint,probe_count FROM dns_routes WHERE node_id=? AND enabled=1 ORDER BY id", (node_id,)).fetchall()
        config = db.execute("SELECT querylog_path FROM dns_node_config WHERE node_id=?", (node_id,)).fetchone()
    lines = [f"<b>DNS-маршруты: {html.escape(node['name'])}</b>"]
    lines.extend(f"• {html.escape(r['route_type'])}: <code>{html.escape(r['endpoint'][:120])}</code> — {r['probe_count']} проб" for r in routes[:12])
    if len(routes) > 12:
        lines.append(f"…и ещё {len(routes) - 12}")
    if not routes:
        lines.append("Маршруты пока не добавлены.")
    querylog = config["querylog_path"] if config else "не задан"
    lines.append(f"Журнал AdGuard: <code>{html.escape(querylog)}</code>")
    if note:
        lines.insert(0, html.escape(note))
    keyboard = kb(
        [("Добавить маршрут", f"dns_add:{node_id}"), ("Проверить сейчас", f"dns_check:{node_id}")],
        [("Задать путь к журналу", f"dns_log:{node_id}"), ("Копировать шаблон", f"dns_copy:{node_id}")],
        [("Удалить маршрут", f"dns_delete:{node_id}")],
        [("Назад к узлу", f"node:{node_id}"), ("К узлам", "dns_nodes")],
    )
    edit(chat, message_id, "\n".join(lines), keyboard)


def _dns_save_route(chat, pending, count):
    node = load_node(pending["node_id"])
    if not node:
        TEXT_PENDING.pop(chat, None)
        edit(chat, pending["message_id"], "Узел больше не доступен.", kb([("К узлам", "dns_nodes")]))
        return
    with connect() as db:
        db.execute("INSERT INTO dns_routes(node_id,route_type,endpoint,probe_count) VALUES(?,?,?,?) ON CONFLICT(node_id,route_type,endpoint) DO UPDATE SET probe_count=excluded.probe_count,enabled=1", (node["id"], pending["route_type"], pending["endpoint"], count))
    audit(OWNER, node["name"], "dns_route_add", f"{pending['route_type']}: {count} probes")
    TEXT_PENDING.pop(chat, None)
    edit(chat, pending["message_id"], f"Маршрут <b>{html.escape(pending['route_type'])}</b> сохранён: <code>{html.escape(pending['endpoint'])}</code>, проб: {count}.", kb([("К DNS-маршрутам", f"dns_menu:{node['id']}")]))


def _dns_check_worker(chat, message_id, node_id):
    try:
        node = load_node(node_id)
        if not node:
            text = "Узел не найден."
        else:
            result = check_dns_routes(node, SSH_DIR)
            record_check(node_id, "dns_routes", result.get("status", "unknown"), json.dumps(result, ensure_ascii=False))
            if result["status"] in ("not_configured", "log_error", "error"):
                text = f"<b>DNS-проверка: не выполнена</b>\n{html.escape(result['message'])}"
            else:
                lines = [f"<b>{html.escape(node['name'])}: DNS-проверка</b>"]
                for route in result["routes"]:
                    lines.append(f"{html.escape(route['route_type'])}: {route['logged']}/{route['total']}")
                    if route["send_errors"]:
                        lines.append(f"  Ошибки передачи: {len(route['send_errors'])}; итог считается по журналу.")
                lines.append(f"{'✅' if result['status'] == 'ok' else '⚠️'} В журнале AdGuard найдено {result['logged']}/{result['total']} уникальных проб.")
                lines.append("Ответ DNS сам по себе успехом не считается.")
                text = "\n".join(lines)
                audit(OWNER, node["name"], "dns_route_check", f"{result['logged']}/{result['total']} probes logged")
    except Exception as exc:
        text = f"<b>Ошибка DNS-проверки</b>\n{html.escape(type(exc).__name__ + ': ' + str(exc))}"
        if load_node(node_id):
            record_check(node_id, "dns_routes", "error", type(exc).__name__ + ": " + str(exc))
    finally:
        with DNS_CHECKS_LOCK:
            DNS_CHECKS.discard((chat, node_id))
    try:
        edit(chat, message_id, text[:3900], kb([("К DNS-маршрутам", f"dns_menu:{node_id}"), ("К узлам", "dns_nodes")]))
    except Exception:
        send(chat, text[:3900], kb([("К DNS-маршрутам", f"dns_menu:{node_id}")]))


def _ai_diagnose_worker(chat, message_id, node_id):
    try:
        node = load_node(node_id)
        if not node:
            text = "Узел не найден."
        else:
            status, details = check_node(node)
            with connect() as db:
                rows = db.execute("SELECT at,action,result FROM audit WHERE node=? ORDER BY id DESC LIMIT 50", (node["name"],)).fetchall()
                checks = db.execute("SELECT at,check_type,status,details FROM monitor_results WHERE node_id=? ORDER BY id DESC LIMIT 50", (node_id,)).fetchall()
            audit_rows = [f"{r['at']} {r['action']}: {r['result']}" for r in rows]
            check_rows = [f"{r['at']} [{r['check_type']}] {r['status']}: {r['details']}" for r in checks]
            logs = read_service_logs(node, run_ssh, sorted(DIAGNOSTIC_SERVICES))
            report = ai_analyze(node["name"], f"Текущая SSH/disk проверка: {status}\n{details}", check_rows, audit_rows, logs)
            audit(OWNER, node["name"], "ai_diagnosis", "analysis completed; no changes executed")
            text = f"<b>ИИ-диагностика · {html.escape(node['name'])}</b>\n{html.escape(report)}\n\n<i>Только анализ и предложения. Исправления выполняются отдельно после подтверждения.</i>"
    except Exception as exc:
        text = f"<b>ИИ-диагностика не выполнена</b>\n{html.escape(str(exc)[:500])}"
    finally:
        with AI_CHECKS_LOCK:
            AI_CHECKS.discard((chat, node_id))
    try:
        edit(chat, message_id, text[:3900], kb([("К узлу", f"node:{node_id}"), ("К узлам", "nodes")]))
    except Exception:
        send(chat, text[:3900], kb([("К узлу", f"node:{node_id}")]))


def _handle_text_input(chat, message):
    pending = TEXT_PENDING.get(chat)
    if not pending:
        return False
    if pending.get("expires", 0) < time.time():
        TEXT_PENDING.pop(chat, None)
        send(chat, "Ввод устарел. Открой DNS-маршруты ещё раз.", kb([("DNS-маршруты", "dns_nodes")]))
        return True
    value = message.get("text", "").strip()
    if pending["action"] == "dns_endpoint":
        try:
            pending["endpoint"] = validate_endpoint(pending["route_type"], value)
        except ValueError as exc:
            send(chat, f"Адрес не принят: {html.escape(str(exc))}\nОтправь корректный адрес или нажми отмену.", kb([("Отмена", f"dns_cancel:{pending['node_id']}")]))
            return True
        pending["action"] = "dns_count_choice"
        default_count = DNS_ROUTE_DEFAULTS[pending["route_type"]][1]
        sent = send(chat, f"Адрес принят. Число проб по умолчанию: {default_count}.", kb(
            [(f"Оставить {default_count}", "dns_count_default"), ("Указать другое", "dns_count_custom")],
            [("Отмена", f"dns_cancel:{pending['node_id']}")],
        ))
        pending["message_id"] = sent["message_id"]
        return True
    if pending["action"] == "dns_count":
        try:
            count = int(value)
            if not 1 <= count <= 64:
                raise ValueError
        except ValueError:
            send(chat, "Число проб должно быть от 1 до 64. Отправь число ещё раз или отмени настройку.", kb([("Отмена", f"dns_cancel:{pending['node_id']}")]))
            return True
        _dns_save_route(chat, pending, count)
        return True
    if pending["action"] == "dns_log_path":
        try:
            path = validate_querylog_path(value)
        except ValueError as exc:
            send(chat, f"Путь не принят: {html.escape(str(exc))}\nОтправь путь ещё раз или нажми отмену.", kb([("Отмена", f"dns_cancel:{pending['node_id']}")]))
            return True
        node = load_node(pending["node_id"])
        if not node:
            TEXT_PENDING.pop(chat, None)
            send(chat, "Узел больше не доступен.", kb([("К узлам", "dns_nodes")]))
            return True
        with connect() as db:
            db.execute("INSERT INTO dns_node_config(node_id,querylog_path) VALUES(?,?) ON CONFLICT(node_id) DO UPDATE SET querylog_path=excluded.querylog_path", (node["id"], path))
        audit(OWNER, node["name"], "dns_querylog_set", "AdGuard query log path updated")
        TEXT_PENDING.pop(chat, None)
        edit(chat, pending["message_id"], f"Путь к журналу AdGuard сохранён: <code>{html.escape(path)}</code>.", kb([("К DNS-маршрутам", f"dns_menu:{node['id']}")]))
        return True
    return False


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
    elif data == "dns_nodes": dns_nodes_menu(chat, mid)
    elif data.startswith("ai_diag:"):
        try: node_id = int(data.split(":", 1)[1])
        except ValueError: node_id = -1
        node = load_node(node_id)
        if not node:
            edit(chat, mid, "Узел не найден.", kb([("К узлам", "nodes")]))
        else:
            with AI_CHECKS_LOCK:
                busy = (chat, node_id) in AI_CHECKS
                if not busy: AI_CHECKS.add((chat, node_id))
            if busy:
                edit(chat, mid, "ИИ-диагностика этого узла уже выполняется.", kb([("К узлу", f"node:{node_id}")]))
            else:
                edit(chat, mid, f"Собираю последнюю проверку и журналы разрешённых служб узла <b>{html.escape(node['name'])}</b>. Данные будут отправлены настроенному ИИ-провайдеру; исправления не запускаются.", kb([("К узлу", f"node:{node_id}")]))
                threading.Thread(target=_ai_diagnose_worker, args=(chat, mid, node_id), daemon=True).start()
    elif data.startswith("dns_menu:"):
        try: dns_routes_menu(chat, mid, int(data.split(":", 1)[1]))
        except ValueError: edit(chat, mid, "Неверный номер узла.", kb([("К узлам", "dns_nodes")]))
    elif data.startswith("dns_add:"):
        try: node_id = int(data.split(":", 1)[1])
        except ValueError: node_id = -1
        if not load_node(node_id):
            edit(chat, mid, "Узел не найден.", kb([("К DNS-маршрутам", "dns_nodes")]))
        else:
            choices = list(DNS_ROUTE_DEFAULTS)
            rows = [[(f"{name} · {DNS_ROUTE_DEFAULTS[name][1]} проб", f"dns_type:{node_id}:{i}")] for i, name in enumerate(choices)]
            rows.append([("Отмена", f"dns_menu:{node_id}")])
            edit(chat, mid, "Выбери тип DNS-маршрута.", kb(*rows))
    elif data.startswith("dns_type:"):
        parts = data.split(":")
        try: node_id, index = int(parts[1]), int(parts[2])
        except (ValueError, IndexError): node_id, index = -1, -1
        choices = list(DNS_ROUTE_DEFAULTS)
        if not load_node(node_id) or not 0 <= index < len(choices):
            edit(chat, mid, "Узел или тип маршрута не найден.", kb([("К DNS-маршрутам", "dns_nodes")]))
        else:
            route_type = choices[index]
            TEXT_PENDING[chat] = {"action": "dns_endpoint", "node_id": node_id, "route_type": route_type,
                                  "message_id": mid, "expires": time.time() + 300}
            proto = DNS_ROUTE_DEFAULTS[route_type][0]
            example = "https://dns.example.org/dns-query" if proto == "doh" else "dns.example.org:853"
            edit(chat, mid, f"Маршрут <b>{html.escape(route_type)}</b>. Отправь {'HTTPS URL' if proto == 'doh' else 'адрес host:port'}: <code>{example}</code>", kb([("Отмена", f"dns_cancel:{node_id}")]))
    elif data == "dns_count_default":
        pending = TEXT_PENDING.get(chat)
        if not pending or pending.get("action") != "dns_count_choice" or pending.get("expires", 0) < time.time():
            TEXT_PENDING.pop(chat, None); edit(chat, mid, "Настройка истекла. Начни заново.", kb([("К DNS-маршрутам", "dns_nodes")]))
        else:
            pending["message_id"] = mid
            _dns_save_route(chat, pending, DNS_ROUTE_DEFAULTS[pending["route_type"]][1])
    elif data == "dns_count_custom":
        pending = TEXT_PENDING.get(chat)
        if not pending or pending.get("action") != "dns_count_choice" or pending.get("expires", 0) < time.time():
            TEXT_PENDING.pop(chat, None); edit(chat, mid, "Настройка истекла. Начни заново.", kb([("К DNS-маршрутам", "dns_nodes")]))
        else:
            pending["action"] = "dns_count"; pending["message_id"] = mid; pending["expires"] = time.time() + 300
            edit(chat, mid, "Отправь число проб от 1 до 64.", kb([("Отмена", f"dns_cancel:{pending['node_id']}")]))
    elif data.startswith("dns_log:"):
        try: node_id = int(data.split(":", 1)[1])
        except ValueError: node_id = -1
        if not load_node(node_id):
            edit(chat, mid, "Узел не найден.", kb([("К узлам", "dns_nodes")]))
        else:
            TEXT_PENDING[chat] = {"action": "dns_log_path", "node_id": node_id, "message_id": mid, "expires": time.time() + 300}
            edit(chat, mid, "Отправь абсолютный Linux-путь к <code>querylog.json</code>. Файл должен быть читаем пользователем SSH-подключения.", kb([("Отмена", f"dns_cancel:{node_id}")]))
    elif data.startswith("dns_cancel:"):
        try: node_id = int(data.split(":", 1)[1])
        except ValueError: node_id = -1
        TEXT_PENDING.pop(chat, None)
        dns_routes_menu(chat, mid, node_id, "Ввод отменён.")
    elif data.startswith("dns_delete:"):
        try: node_id = int(data.split(":", 1)[1])
        except ValueError: node_id = -1
        if not load_node(node_id):
            edit(chat, mid, "Узел не найден.", kb([("К узлам", "dns_nodes")]))
        else:
            with connect() as db:
                routes = db.execute("SELECT id,route_type,endpoint FROM dns_routes WHERE node_id=? AND enabled=1 ORDER BY id", (node_id,)).fetchall()
            rows = [[(f"{route['route_type']} · {route['endpoint'][:32]}", f"dns_del_select:{node_id}:{route['id']}")] for route in routes]
            rows.append([("Назад", f"dns_menu:{node_id}")])
            edit(chat, mid, "Выбери маршрут для удаления." if routes else "Удалять нечего: маршрутов нет.", kb(*rows))
    elif data.startswith("dns_del_select:"):
        parts = data.split(":")
        try: node_id, route_id = int(parts[1]), int(parts[2])
        except (ValueError, IndexError): node_id, route_id = -1, -1
        with connect() as db:
            route = db.execute("SELECT route_type,endpoint FROM dns_routes WHERE id=? AND node_id=? AND enabled=1", (route_id, node_id)).fetchone()
        if route:
            edit(chat, mid, f"Удалить маршрут <b>{html.escape(route['route_type'])}</b> <code>{html.escape(route['endpoint'][:120])}</code>?", kb([("Удалить", f"dns_del_yes:{node_id}:{route_id}"), ("Отмена", f"dns_menu:{node_id}")]))
        else: edit(chat, mid, "Маршрут не найден.", kb([("К DNS-маршрутам", f"dns_menu:{node_id}")]))
    elif data.startswith("dns_del_yes:"):
        parts = data.split(":")
        try: node_id, route_id = int(parts[1]), int(parts[2])
        except (ValueError, IndexError): node_id, route_id = -1, -1
        node = load_node(node_id)
        with connect() as db:
            route = db.execute("SELECT route_type FROM dns_routes WHERE id=? AND node_id=?", (route_id, node_id)).fetchone()
            cur = db.execute("DELETE FROM dns_routes WHERE id=? AND node_id=?", (route_id, node_id))
        if node and cur.rowcount and route:
            audit(OWNER, node["name"], "dns_route_delete", route["route_type"])
            dns_routes_menu(chat, mid, node_id, "Маршрут удалён.")
        else: edit(chat, mid, "Маршрут уже отсутствует.", kb([("К DNS-маршрутам", f"dns_menu:{node_id}")]))
    elif data.startswith("dns_copy:"):
        try: target_id = int(data.split(":", 1)[1])
        except ValueError: target_id = -1
        nodes = dns_node_rows(target_id)
        rows = [[(f"{n['name']} · {n['host']}", f"dns_copy_from:{target_id}:{n['id']}")] for n in nodes]
        rows.append([("Назад", f"dns_menu:{target_id}")])
        edit(chat, mid, "Выбери узел-источник. Маршруты будут добавлены к выбранному узлу; путь к журналу задаётся отдельно.", kb(*rows))
    elif data.startswith("dns_copy_from:"):
        parts = data.split(":")
        try: target_id, source_id = int(parts[1]), int(parts[2])
        except (ValueError, IndexError): target_id, source_id = -1, -1
        target, source = load_node(target_id), load_node(source_id)
        if not target or not source or target_id == source_id:
            edit(chat, mid, "Не удалось выбрать узлы.", kb([("К DNS-маршрутам", f"dns_menu:{target_id}")]))
        else:
            with connect() as db:
                routes = db.execute("SELECT route_type,endpoint,probe_count FROM dns_routes WHERE node_id=? AND enabled=1", (source_id,)).fetchall()
                for route in routes:
                    db.execute("INSERT INTO dns_routes(node_id,route_type,endpoint,probe_count) VALUES(?,?,?,?) ON CONFLICT(node_id,route_type,endpoint) DO UPDATE SET probe_count=excluded.probe_count,enabled=1", (target_id, route["route_type"], route["endpoint"], route["probe_count"]))
            audit(OWNER, target["name"], "dns_routes_clone", f"copied {len(routes)} routes from {source['name']}")
            dns_routes_menu(chat, mid, target_id, f"Скопировано маршрутов: {len(routes)}. Задай путь к журналу на целевом узле.")
    elif data.startswith("dns_check:"):
        try: node_id = int(data.split(":", 1)[1])
        except ValueError: node_id = -1
        node = load_node(node_id)
        if not node:
            edit(chat, mid, "Узел не найден.", kb([("К узлам", "dns_nodes")]))
        else:
            with DNS_CHECKS_LOCK:
                busy = (chat, node_id) in DNS_CHECKS
                if not busy: DNS_CHECKS.add((chat, node_id))
            if busy:
                edit(chat, mid, "Проверка этого узла уже выполняется.", kb([("К DNS-маршрутам", f"dns_menu:{node_id}")]))
            else:
                edit(chat, mid, f"Начинаю DNS-проверку узла <b>{html.escape(node['name'])}</b>. Результат засчитывается по журналу AdGuard.", kb([("К DNS-маршрутам", f"dns_menu:{node_id}")]))
                threading.Thread(target=_dns_check_worker, args=(chat, mid, node_id), daemon=True).start()
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
        TEXT_PENDING.pop(chat, None)
        main_menu(chat)
    elif text.startswith("/id"):
        send(chat, f"Ваш Chat ID: <code>{html.escape(chat)}</code>")
    elif text.startswith("/cancel"):
        pending = TEXT_PENDING.pop(chat, None)
        if pending:
            dns_routes_menu(chat, pending["message_id"], pending["node_id"], "Ввод отменён.")
        else:
            send(chat, "Активных запросов ввода нет.", kb([("Меню", "menu")]))
    elif text.startswith("/help"):
        send(chat, "Команды: /start, /menu, /help. Перезапуски выполняются только после нажатия подтверждения.")
    elif _handle_text_input(chat, message):
        return


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
