#!/opt/rvkomi-server-manager/venv/bin/python
"""Interactive setup and administration for RVKOMI Server Manager."""
import getpass
import hashlib
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
import secrets
import ssl
import struct
import time

ROOT = "/etc/rvkomi-server-manager"
STATE = "/var/lib/rvkomi-server-manager"
SSH_DIR = os.path.join(STATE, "ssh")
CONFIG = os.path.join(ROOT, "manager.json")
ENV_FILE = os.path.join(ROOT, "bot.env")
sys.path.insert(0, "/opt/rvkomi-server-manager")
from storage import connect, audit


def api(token, method, payload=None, timeout=35):
    req = urllib.request.Request(
        f"https://api.telegram.org/bot{token}/{method}",
        data=json.dumps(payload or {}).encode() if payload is not None else None,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.load(resp)
    if not data.get("ok"):
        raise RuntimeError(data.get("description", "Telegram API error"))
    return data["result"]


def save_bot_env(token, chat_id):
    if not re.fullmatch(r"\d{1,20}", str(chat_id)):
        raise ValueError("Chat ID должен быть числовым")
    api(token, "sendMessage", {"chat_id": chat_id, "text": "RVKOMI Server Manager подключён. Доступ привязан к этому чату."})
    with open(ENV_FILE, "w", encoding="utf-8") as f:
        f.write(f"BOT_TOKEN={token}\nBOT_CHAT_ID={chat_id}\n")
    os.chmod(ENV_FILE, 0o640)
    subprocess.run(["chown", "root:rvkomi-manager", ENV_FILE], check=False)
    subprocess.run(["systemctl", "enable", "rvkomi-server-manager.service"], check=False)
    subprocess.run(["systemctl", "restart", "rvkomi-server-manager.service"], check=False)


def bot_wizard():
    print("Подключение Telegram-бота по сценарию goKaskad")
    print("Создайте бота через @BotFather и вставьте его токен ниже.")
    token = getpass.getpass("Токен бота (ввод скрыт): ").strip()
    if not re.fullmatch(r"\d{5,15}:[A-Za-z0-9_-]{20,}", token):
        print("Формат токена не распознан."); return
    try:
        me = api(token, "getMe", timeout=15)
    except Exception as exc:
        print(f"Telegram не подтвердил токен: {exc}"); return
    print(f"Бот подтверждён: @{me.get('username', 'unknown')}")
    print("1. Получить Chat ID автоматически (напишите боту /start)")
    print("2. Ввести Chat ID вручную")
    mode = input("Выбор [1/2]: ").strip()
    was_active = subprocess.run(["systemctl", "is-active", "--quiet", "rvkomi-server-manager.service"], check=False).returncode == 0
    if mode == "1":
        if was_active: subprocess.run(["systemctl", "stop", "rvkomi-server-manager.service"], check=False)
        print("Откройте своего бота в Telegram, отправьте /start, затем нажмите Enter.")
        input()
        try:
            updates = api(token, "getUpdates", {"timeout": 0, "allowed_updates": ["message"]}, timeout=15)
        except Exception as exc:
            if was_active: subprocess.run(["systemctl", "start", "rvkomi-server-manager.service"], check=False)
            print(f"Не удалось получить Chat ID: {exc}"); return
        chats = []
        for u in updates:
            msg = u.get("message", {})
            chat = msg.get("chat", {})
            if msg.get("text", "").split()[0:1] == ["/start"] and chat.get("type") == "private":
                chats.append(str(chat.get("id")))
        chat_id = chats[-1] if chats else ""
        if not chat_id:
            if was_active: subprocess.run(["systemctl", "start", "rvkomi-server-manager.service"], check=False)
            print("Сообщение не найдено. Повторите автоопределение или задайте Chat ID вручную."); return
        print(f"Найден личный Chat ID: {chat_id}")
    elif mode == "2":
        chat_id = input("Chat ID администратора: ").strip()
    else:
        print("Неизвестный пункт."); return
    if input(f"Привязать администратора {chat_id} к @{me.get('username')}? [y/N] ").strip().lower() != "y":
        if was_active and mode == "1": subprocess.run(["systemctl", "start", "rvkomi-server-manager.service"], check=False)
        print("Отменено."); return
    try:
        save_bot_env(token, chat_id)
    except Exception as exc:
        print(f"Не удалось сохранить и проверить привязку: {exc}"); return
    print("Бот подключён, тестовое сообщение отправлено.")


def public_source_ip():
    try:
        with urllib.request.urlopen("https://api.ipify.org", timeout=5) as r:
            return r.read(80).decode().strip()
    except Exception:
        return ""


def ensure_key():
    os.makedirs(SSH_DIR, mode=0o700, exist_ok=True)
    priv = os.path.join(SSH_DIR, "id_ed25519")
    pub = priv + ".pub"
    if not os.path.exists(priv):
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "rvkomi-server-manager", "-f", priv], check=True)
        subprocess.run(["chown", "-R", "rvkomi-manager:rvkomi-manager", SSH_DIR], check=False)
    return priv, pub


def add_node(kind):
    try:
        import paramiko
    except ImportError:
        print("Не установлен Paramiko. Повторите установку проекта."); return
    name = input("Имя узла: ").strip()
    host = input("IP или DNS-имя: ").strip()
    user = input("SSH-пользователь: ").strip()
    if not re.fullmatch(r"[\w.-]{1,48}", name) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,253}", host) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,31}", user):
        print("Недопустимое имя, адрес или SSH-пользователь."); return
    source_ip = public_source_ip()
    try: source_ip = str(ipaddress.ip_address(source_ip))
    except ValueError:
        print("Не удалось определить публичный IP управляющего сервера. Ключ не устанавливается, потому что SSH-доступ должен быть ограничен этим IP."); return
    password = getpass.getpass("Пароль SSH (только для установки ключа, ввод скрыт): ")
    transport = None
    try:
        # Verify the server key before sending the SSH password.
        transport = paramiko.Transport((host, 22))
        transport.start_client(timeout=12)
        key = transport.get_remote_server_key()
        fp = "SHA256:" + __import__('base64').b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")
        print(f"Fingerprint SSH: {fp}")
        if input("Сверьте fingerprint с сервером и подтвердите [yes]: ").strip() != "yes":
            print("Подключение отменено."); transport.close(); password = ""; return
        transport.auth_password(user, password)
        if not transport.is_authenticated():
            print("SSH не подтвердил пароль."); transport.close(); password = ""; return
        channel = transport.open_session(timeout=8)
        channel.exec_command("printf '%s\\n' \"$HOME\"")
        home = channel.makefile("r").read().decode("utf-8", "strict").strip()
        channel.recv_exit_status()
        channel.close()
        if not home.startswith("/") or "\n" in home:
            print("Не удалось безопасно определить домашний каталог SSH-пользователя."); return
        priv, pub = ensure_key()
        public_key = open(pub, encoding="utf-8").read().strip().split()
        if len(public_key) < 2 or public_key[0] != "ssh-ed25519":
            print("Неверный формат ключа менеджера."); return
        key_line = f'from="{source_ip}" {public_key[0]} {public_key[1]} rvkomi-server-manager'
        sftp = paramiko.SFTPClient.from_transport(transport)
        ssh_dir = home.rstrip("/") + "/.ssh"
        try: sftp.mkdir(ssh_dir, 0o700)
        except IOError: pass
        sftp.chmod(ssh_dir, 0o700)
        auth = ssh_dir + "/authorized_keys"
        existing = ""
        try:
            with sftp.open(auth, "r") as f: existing = f.read().decode("utf-8", "replace")
        except IOError: pass
        if public_key[1] not in existing:
            with sftp.open(auth, "a") as f: f.write(key_line + "\n")
        sftp.chmod(auth, 0o600)
        sftp.close()
        # Pin the exact host key that the operator just compared, so later
        # health checks cannot silently accept a replacement host.
        known_hosts = os.path.join(SSH_DIR, "known_hosts")
        host_entry = f"{host} {key.get_name()} {key.get_base64()}\n"
        os.makedirs(SSH_DIR, mode=0o700, exist_ok=True)
        try:
            with open(known_hosts, encoding="utf-8") as known: pinned = known.read()
        except FileNotFoundError:
            pinned = ""
        if host_entry not in pinned:
            with open(known_hosts, "a", encoding="utf-8") as known: known.write(host_entry)
        os.chmod(known_hosts, 0o600)
        subprocess.run(["chown", "-R", "rvkomi-manager:rvkomi-manager", SSH_DIR], check=False)
        transport.close()
        password = ""
        with connect() as db:
            db.execute("INSERT INTO nodes(name,host,user,kind,key_path,fingerprint) VALUES(?,?,?,?,?,?)",
                       (name, host, user, kind, priv, fp)); db.commit()
        audit("local-admin", name, "connect_" + kind, "public key installed")
        print(f"Узел «{name}» подключён по ключу с ограничением источника {source_ip}.")
    except Exception as exc:
        try:
            if transport: transport.close()
        except Exception: pass
        password = ""
        print(f"Не удалось подключить узел: {exc}")
    finally:
        if transport:
            try: transport.close()
            except Exception: pass
        password = ""


def register_main(name):
    name = name.strip()
    if not re.fullmatch(r"[\w.-]{1,48}", name):
        raise ValueError("Название должно содержать 1–48 букв, цифр, точек, дефисов или подчёркиваний.")
    host = socket.getfqdn() or socket.gethostname() or "localhost"
    with connect() as db:
        local = db.execute("SELECT id FROM nodes WHERE fingerprint='local' LIMIT 1").fetchone()
        if local:
            collision = db.execute("SELECT id FROM nodes WHERE name=? AND id<>?", (name, local["id"])).fetchone()
            if collision:
                raise ValueError(f"Имя «{name}» уже занято другим узлом.")
            db.execute("UPDATE nodes SET name=?,host=?,user='local',kind='server',key_path='',enabled=1 WHERE id=?",
                       (name, host, local["id"]))
        else:
            collision = db.execute("SELECT id FROM nodes WHERE name=?", (name,)).fetchone()
            if collision:
                raise ValueError(f"Имя «{name}» уже занято другим узлом.")
            db.execute("INSERT INTO nodes(name,host,user,kind,key_path,fingerprint) VALUES(?,?,?,'server','','local')",
                       (name, host, "local"))
    audit("installer", name, "register_main", "local management server registered")
    print(f"Основной сервер «{name}» добавлен в список узлов ({host}).")


def set_interval():
    try: minutes = int(input("Интервал мониторинга в минутах (5–1440): "))
    except ValueError: print("Введите число."); return
    if not 5 <= minutes <= 1440: print("Допустимый диапазон — 5–1440 минут."); return
    with open(CONFIG, encoding="utf-8") as f: cfg = json.load(f)
    cfg["monitor_interval_minutes"] = minutes
    with open(CONFIG, "w", encoding="utf-8") as f: json.dump(cfg, f, indent=2)
    print(f"Интервал установлен: {minutes} минут.")


def show_nodes():
    with connect() as db:
        rows = db.execute("SELECT name,kind,host,user,last_status,last_check FROM nodes ORDER BY name").fetchall()
    if not rows: print("Подключённых узлов пока нет.")
    for r in rows:
        label = "основной сервер" if r["user"] == "local" else r["kind"]
        print(f"{r['name']} [{label}] {r['user']}@{r['host']} — {r['last_status'] or 'нет проверки'}")


DNS_ROUTE_DEFAULTS = {
    "DoH-origin": ("doh", 1), "DoH-CDN": ("doh", 1),
    "DoT": ("dot", 1), "DNS-relay-DoH": ("doh", 16),
    "DNS-relay-DoT": ("dot", 4), "AdGuard DoH": ("doh", 16),
    "AdGuard DoT": ("dot", 4),
}


def dns_node_rows():
    with connect() as db:
        return db.execute("SELECT id,name,host,user,kind,key_path,fingerprint,enabled FROM nodes WHERE enabled=1 ORDER BY name").fetchall()


def choose_node(prompt="Выберите узел: "):
    rows = dns_node_rows()
    if not rows:
        print("Нет подключённых узлов."); return None
    for i, row in enumerate(rows, 1): print(f"{i}. {row['name']} — {row['host']}")
    try: idx = int(input(prompt)) - 1
    except ValueError: print("Введите номер."); return None
    if not 0 <= idx < len(rows): print("Нет такого номера."); return None
    return rows[idx]


def dns_route_menu():
    node = choose_node("Узел для DNS-маршрутов: ")
    if not node: return
    while True:
        print(f"\nDNS-маршруты узла «{node['name']}»")
        print("1. Добавить маршрут\n2. Список маршрутов\n3. Удалить маршрут\n4. Путь к журналу AdGuard\n5. Проверить маршруты сейчас\n6. Скопировать шаблон с другого узла\n0. Назад")
        choice = input("Выбор: ").strip()
        if choice == "0": return
        if choice == "1":
            kinds = list(DNS_ROUTE_DEFAULTS)
            for i, kind in enumerate(kinds, 1):
                proto, count = DNS_ROUTE_DEFAULTS[kind]
                print(f"{i}. {kind} ({proto.upper()}, {count} проб по умолчанию)")
            try: idx = int(input("Тип маршрута: ")) - 1
            except ValueError: print("Введите номер."); continue
            if not 0 <= idx < len(kinds): print("Нет такого типа."); continue
            kind = kinds[idx]; proto, default_count = DNS_ROUTE_DEFAULTS[kind]
            endpoint = input("URL DoH (https://host/dns-query) или адрес DoT (host:853): ").strip()
            try:
                parsed = urllib.parse.urlsplit(endpoint if proto == "doh" else "tls://" + endpoint)
                if proto == "doh":
                    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
                        raise ValueError("Нужен HTTPS URL без логина, пароля и query-параметров.")
                elif parsed.scheme != "tls" or not parsed.hostname or parsed.username or parsed.password or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
                    raise ValueError("Нужен адрес host:port для DoT.")
                count_raw = input(f"Число проб [{default_count}]: ").strip()
                count = int(count_raw or default_count)
                if not 1 <= count <= 64: raise ValueError("Число проб должно быть от 1 до 64.")
            except Exception as exc: print(f"Параметры не приняты: {exc}"); continue
            with connect() as db:
                db.execute("INSERT INTO dns_routes(node_id,route_type,endpoint,probe_count) VALUES(?,?,?,?) ON CONFLICT(node_id,route_type,endpoint) DO UPDATE SET probe_count=excluded.probe_count,enabled=1", (node["id"], kind, endpoint, count))
            audit("local-admin", node["name"], "dns_route_add", f"{kind}: {count} probes")
            print("Маршрут сохранён.")
        elif choice == "2":
            with connect() as db:
                routes = db.execute("SELECT id,route_type,endpoint,probe_count FROM dns_routes WHERE node_id=? AND enabled=1 ORDER BY route_type,id", (node["id"],)).fetchall()
                cfg = db.execute("SELECT querylog_path FROM dns_node_config WHERE node_id=?", (node["id"],)).fetchone()
            if not routes: print("Маршруты ещё не заданы.")
            for route in routes: print(f"{route['id']}. {route['route_type']} — {route['endpoint']} ({route['probe_count']} проб)")
            print("Журнал AdGuard:", cfg["querylog_path"] if cfg else "не задан")
        elif choice == "3":
            with connect() as db: routes = db.execute("SELECT id,route_type,endpoint FROM dns_routes WHERE node_id=? AND enabled=1 ORDER BY id", (node["id"],)).fetchall()
            if not routes: print("Маршрутов нет."); continue
            for route in routes: print(f"{route['id']}. {route['route_type']} — {route['endpoint']}")
            try: rid = int(input("ID маршрута: "))
            except ValueError: print("Введите ID."); continue
            with connect() as db: cur = db.execute("DELETE FROM dns_routes WHERE id=? AND node_id=?", (rid, node["id"]))
            print("Удалено." if cur.rowcount else "Маршрут не найден.")
        elif choice == "4":
            path = input("Абсолютный путь к querylog.json на узле AdGuard: ").strip()
            if not path.startswith("/") or "\n" in path or "\r" in path: print("Укажите абсолютный Linux-путь."); continue
            with connect() as db: db.execute("INSERT INTO dns_node_config(node_id,querylog_path) VALUES(?,?) ON CONFLICT(node_id) DO UPDATE SET querylog_path=excluded.querylog_path", (node["id"], path))
            audit("local-admin", node["name"], "dns_querylog_set", path)
            print("Путь сохранён. Убедитесь, что файл доступен SSH-пользователю для чтения.")
        elif choice == "5": run_dns_check(node)
        elif choice == "6":
            sources = [r for r in dns_node_rows() if r["id"] != node["id"]]
            if not sources: print("Нет другого узла для копирования."); continue
            for i, source in enumerate(sources, 1): print(f"{i}. {source['name']} — {source['host']}")
            try: idx = int(input("Копировать маршруты с узла: ")) - 1
            except ValueError: print("Введите номер."); continue
            if not 0 <= idx < len(sources): print("Нет такого номера."); continue
            source = sources[idx]
            with connect() as db:
                source_routes = db.execute("SELECT route_type,endpoint,probe_count FROM dns_routes WHERE node_id=? AND enabled=1", (source["id"],)).fetchall()
                for route in source_routes:
                    db.execute("INSERT INTO dns_routes(node_id,route_type,endpoint,probe_count) VALUES(?,?,?,?) ON CONFLICT(node_id,route_type,endpoint) DO UPDATE SET probe_count=excluded.probe_count,enabled=1", (node["id"], route["route_type"], route["endpoint"], route["probe_count"]))
            audit("local-admin", node["name"], "dns_routes_clone", f"copied {len(source_routes)} routes from {source['name']}")
            print(f"Скопировано маршрутов: {len(source_routes)}. Проверьте endpoints и задайте путь к журналу AdGuard на целевом узле.")
        else: print("Нет такого пункта.")


def dns_packet(qname):
    labels = qname.rstrip(".").split(".")
    q = b"".join(bytes([len(x)]) + x.encode("ascii") for x in labels) + b"\0" + struct.pack("!HH", 1, 1)
    return struct.pack("!HHHHHH", secrets.randbelow(65536), 0x0100, 1, 0, 0, 0) + q


def send_dns_probe(endpoint, proto, qname):
    packet = dns_packet(qname)
    if proto == "doh":
        req = urllib.request.Request(endpoint, data=packet, headers={"Content-Type": "application/dns-message", "Accept": "application/dns-message"}, method="POST")
        with urllib.request.urlopen(req, timeout=8, context=ssl.create_default_context()) as response:
            response.read(4096)
    else:
        parsed = urllib.parse.urlsplit("tls://" + endpoint)
        host, port = parsed.hostname, parsed.port or 853
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=8) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as conn:
                conn.sendall(struct.pack("!H", len(packet)) + packet)
                head = conn.recv(2)
                if len(head) != 2: raise OSError("не получен DNS-ответ по DoT")
                size = struct.unpack("!H", head)[0]
                remaining = size
                while remaining:
                    chunk = conn.recv(remaining)
                    if not chunk: raise OSError("оборван DNS-ответ по DoT")
                    remaining -= len(chunk)


def read_querylog(node, path, marker):
    if node["fingerprint"] == "local":
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            f.seek(max(0, os.path.getsize(path) - 8 * 1024 * 1024)); return f.read()
    try: import paramiko
    except ImportError as exc: raise RuntimeError("Paramiko не установлен") from exc
    if not re.fullmatch(r"/[A-Za-z0-9_./-]{1,240}", path): raise ValueError("Недопустимый путь журнала")
    client = paramiko.SSHClient(); client.load_host_keys(os.path.join(SSH_DIR, "known_hosts")); client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.connect(node["host"], username=node["user"], key_filename=node["key_path"], timeout=10, look_for_keys=False, allow_agent=False)
        # Path has a strict character allowlist; tail reads a bounded recent window.
        _, stdout, stderr = client.exec_command("tail -c 8388608 -- " + path, timeout=12)
        data = stdout.read().decode("utf-8", "replace")
        status = stdout.channel.recv_exit_status()
        if status: raise RuntimeError(stderr.read().decode("utf-8", "replace")[:300] or "не удалось прочитать query log")
        return data
    finally: client.close()


def run_dns_check(node):
    with connect() as db:
        routes = db.execute("SELECT route_type,endpoint,probe_count FROM dns_routes WHERE node_id=? AND enabled=1 ORDER BY id", (node["id"],)).fetchall()
        cfg = db.execute("SELECT querylog_path FROM dns_node_config WHERE node_id=?", (node["id"],)).fetchone()
    if not routes: print("Для узла не настроены DNS-маршруты."); return
    if not cfg or not cfg["querylog_path"]: print("Сначала задайте путь к журналу AdGuard в DNS-меню."); return
    probes = []
    for route_index, route in enumerate(routes):
        proto = DNS_ROUTE_DEFAULTS.get(route["route_type"], ("doh", 1))[0]
        for _ in range(route["probe_count"]):
            qname = "rvk-" + secrets.token_hex(12) + ".example.org"
            try: send_dns_probe(route["endpoint"], proto, qname); sent = True
            except Exception as exc:
                sent = False; print(f"{route['route_type']}: отправка не удалась ({type(exc).__name__}: {exc})")
            probes.append((route_index, route["route_type"], qname, sent))
    found = set(); deadline = time.time() + 25
    while time.time() < deadline:
        try:
            log = read_querylog(node, cfg["querylog_path"], "rvk-")
            found = {q for _, _, q, _sent in probes if q in log}
        except Exception as exc:
            print(f"Не удалось прочитать журнал AdGuard: {exc}"); return
        if all(q in found for _, _, q, _sent in probes): break
        time.sleep(2)
    for route_index, route in enumerate(routes):
        related = [(q, sent) for idx, _, q, sent in probes if idx == route_index]
        count = sum(1 for q, _sent in related if q in found)
        print(f"{route['route_type']}: {count}/{route['probe_count']} — обнаружено в журнале AdGuard")
    total = len(probes); logged = len(found)
    print(f"Итого: {logged}/{total} проб обнаружено в журнале AdGuard. Ответ DNS сам по себе не засчитывается.")
    audit("local-admin", node["name"], "dns_route_check", f"{logged}/{total} probes logged")


def backup():
    import datetime
    with connect() as db:
        db.execute("PRAGMA wal_checkpoint(FULL)")
        target = os.path.join(STATE, "backup-" + datetime.datetime.now().strftime("%Y%m%d-%H%M%S") + ".sqlite3")
        dest = __import__('sqlite3').connect(target)
        db.backup(dest); dest.close()
    os.chmod(target, 0o600)
    print(f"Резервная копия создана: {target} (токен и SSH-ключи в неё не входят).")


def restore_backup():
    import glob
    files = sorted(glob.glob(os.path.join(STATE, "backup-*.sqlite3")), reverse=True)
    if not files:
        print("Локальных резервных копий нет."); return
    for i, path in enumerate(files, 1): print(f"{i}. {os.path.basename(path)}")
    try: selected = int(input("Номер копии для восстановления: ")) - 1
    except ValueError: print("Введите номер."); return
    if selected < 0 or selected >= len(files): print("Нет такого номера."); return
    path = files[selected]
    if input(f"Остановить службу и заменить базу копией {os.path.basename(path)}? [yes/no] ").strip() != "yes":
        print("Восстановление отменено."); return
    subprocess.run(["systemctl", "stop", "rvkomi-server-manager.service"], check=False)
    source = __import__('sqlite3').connect(f"file:{path}?mode=ro", uri=True)
    target = __import__('sqlite3').connect(os.path.join(STATE, "manager.sqlite3"))
    try: source.backup(target)
    finally: target.close(); source.close()
    subprocess.run(["chown", "rvkomi-manager:rvkomi-manager", os.path.join(STATE, "manager.sqlite3")], check=False)
    subprocess.run(["systemctl", "start", "rvkomi-server-manager.service"], check=False)
    print("База восстановлена. Токен и ключи SSH не затрагивались.")


def revoke_node():
    import paramiko
    with connect() as db: rows = db.execute("SELECT id,name,host,user,key_path FROM nodes WHERE enabled=1 AND fingerprint<>'local' ORDER BY name").fetchall()
    if not rows: print("Активных подключённых узлов нет. Основной сервер переименовывается через пункт 15."); return
    for i, row in enumerate(rows, 1): print(f"{i}. {row['name']} — {row['user']}@{row['host']}")
    try: selected = int(input("Номер узла для отключения: ")) - 1
    except ValueError: print("Введите номер."); return
    if selected < 0 or selected >= len(rows): print("Нет такого номера."); return
    node = rows[selected]
    if input(f"Отключить узел «{node['name']}»? [yes/no] ").strip() != "yes": print("Отменено."); return
    try:
        client = paramiko.SSHClient()
        client.load_host_keys(os.path.join(SSH_DIR, "known_hosts"))
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        client.connect(node["host"], username=node["user"], key_filename=node["key_path"], timeout=10, look_for_keys=False, allow_agent=False)
        _, stdout, _ = client.exec_command("printf '%s\\n' \"$HOME\"", timeout=8)
        home = stdout.read().decode().strip()
        sftp = client.open_sftp()
        auth = home.rstrip("/") + "/.ssh/authorized_keys"
        with sftp.open(auth, "r") as f: lines = f.read().decode("utf-8", "replace").splitlines()
        kept = [line for line in lines if "rvkomi-server-manager" not in line]
        with sftp.open(auth, "w") as f: f.write("\n".join(kept) + ("\n" if kept else ""))
        sftp.chmod(auth, 0o600); sftp.close(); client.close()
        result = "manager public key removed from remote authorized_keys"
    except Exception as exc:
        result = f"local access disabled; remote key may remain ({type(exc).__name__})"
        print("Удалённо убрать ключ не удалось; локальный доступ всё равно будет отключён.")
    with connect() as db: db.execute("UPDATE nodes SET enabled=0 WHERE id=?", (node["id"],)); db.commit()
    audit("local-admin", node["name"], "revoke", result)
    print(f"Узел «{node['name']}» отключён. Результат: {result}")


def main():
    if os.geteuid() != 0: print("Запустите через sudo fleetctl."); return 1
    while True:
        print("\nRVKOMI Server Manager")
        for i, item in enumerate([
            "Установка на сервер — состав установки", "Подключение другого сервера", "Установка Telegram-бота",
            "Настройка времени мониторинга", "Подключение роутера по SSH", "Список серверов и роутеров",
            "Проверить узел сейчас", "Действия после подтверждения в Telegram", "Журнал действий",
            "Резервная копия настроек и восстановление", "Управление доступом администратора", "Диагностика управляющего сервера", "Отключить сервер или роутер", "Выход",
            "Задать имя основного сервера", "DNS-маршруты: добавить и проверить"], 1):
            print(f" {i:2}. {item}")
        choice = input("Выберите пункт: ").strip()
        if choice == "1":
            print("Устанавливаются: Python runtime, служба Telegram-бота, локальная база узлов/журнала, SSH-клиент и отдельный Ed25519 ключ. Открытые входящие порты не требуются. Менеджер не меняет GoInstaller, GoTelegram, firewall или настройки MTProto.")
        elif choice == "2": add_node("server")
        elif choice == "3": bot_wizard()
        elif choice == "4": set_interval()
        elif choice == "5": add_node("router")
        elif choice == "6": show_nodes()
        elif choice == "7": print("Разовая проверка доступна в Telegram: Узлы → Проверить.")
        elif choice == "8": print("Подтверждаемые исправления: только перезапуск разрешённой службы после проверки. Открытые команды не поддерживаются.")
        elif choice == "9":
            with connect() as db:
                for r in db.execute("SELECT at,actor,node,action,result FROM audit ORDER BY id DESC LIMIT 25"):
                    print(f"{r['at']} {r['actor']} {r['node'] or '-'} {r['action']}: {r['result']}")
        elif choice == "10":
            print("1. Создать резервную копию\n2. Восстановить копию")
            operation = input("Выбор: ").strip()
            if operation == "1": backup()
            elif operation == "2": restore_backup()
            else: print("Нет такого пункта.")
        elif choice == "11": print("Администратор — единственный личный Chat ID, заданный при привязке Telegram-бота. Для смены повторите настройку пункта 3.")
        elif choice == "12":
            print("Версия Python:", sys.version.split()[0])
            print("systemd:", shutil.which("systemctl") or "не найден")
            with connect() as db: print("Узлов в базе:", db.execute("SELECT count(*) FROM nodes").fetchone()[0])
            print("SSH:", shutil.which("ssh") or "не найден")
        elif choice == "13": revoke_node()
        elif choice == "14": return 0
        elif choice == "15":
            main_name = input("Название основного сервера: ").strip()
            try: register_main(main_name)
            except Exception as exc: print(f"Не удалось зарегистрировать основной сервер: {exc}")
        elif choice == "16": dns_route_menu()
        else: print("Нет такого пункта.")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--register-main":
        register_main(sys.argv[2])
    else:
        raise SystemExit(main())
