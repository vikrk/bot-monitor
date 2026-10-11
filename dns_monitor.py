"""DNS route probes confirmed by entries in AdGuard Home's query log."""
import secrets
import os
import re
import socket
import ssl
import struct
import subprocess
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

from storage import connect

DNS_ROUTE_DEFAULTS = {
    "DoH-origin": ("doh", 1), "DoH-CDN": ("doh", 1),
    "DoT": ("dot", 1), "DNS-relay-DoH": ("doh", 16),
    "DNS-relay-DoT": ("dot", 4), "AdGuard DoH": ("doh", 16),
    "AdGuard DoT": ("dot", 4),
}


def validate_endpoint(route_type, endpoint):
    if route_type not in DNS_ROUTE_DEFAULTS:
        raise ValueError("Неизвестный тип DNS-маршрута")
    endpoint = endpoint.strip()
    if not endpoint or len(endpoint) > 2048 or any(c in endpoint for c in "\r\n\0"):
        raise ValueError("Пустой или слишком длинный адрес")
    proto, _ = DNS_ROUTE_DEFAULTS[route_type]
    parsed = urllib.parse.urlsplit(endpoint if proto == "doh" else "tls://" + endpoint)
    if proto == "doh":
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("Для DoH нужен HTTPS URL без логина, пароля и query-параметров")
        try:
            if parsed.port is not None and not 1 <= parsed.port <= 65535:
                raise ValueError("Недопустимый порт")
        except ValueError as exc:
            raise ValueError("Некорректный HTTPS URL или порт") from exc
    elif parsed.scheme != "tls" or not parsed.hostname or parsed.username or parsed.password or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ValueError("Для DoT укажи host:port, например dns.example.org:853")
    else:
        try:
            if parsed.port is not None and not 1 <= parsed.port <= 65535:
                raise ValueError("Недопустимый порт")
        except ValueError as exc:
            raise ValueError("Некорректный адрес или порт DoT") from exc
    return endpoint


def validate_querylog_path(path):
    path = path.strip()
    if not re.fullmatch(r"/[A-Za-z0-9_./-]{1,240}", path):
        raise ValueError("Нужен абсолютный Linux-путь без пробелов и спецсимволов")
    if "/../" in path or path.endswith("/.."):
        raise ValueError("Путь не должен содержать переходы через ..")
    return path


def dns_packet(qname):
    labels = qname.rstrip(".").split(".")
    question = b"".join(bytes([len(label)]) + label.encode("ascii") for label in labels) + b"\0" + struct.pack("!HH", 1, 1)
    return struct.pack("!HHHHHH", secrets.randbelow(65536), 0x0100, 1, 0, 0, 0) + question


def send_dns_probe(endpoint, proto, qname):
    packet = dns_packet(qname)
    if proto == "doh":
        request = urllib.request.Request(
            endpoint, data=packet,
            headers={"Content-Type": "application/dns-message", "Accept": "application/dns-message"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=8, context=ssl.create_default_context()) as response:
            response.read(4096)
        return
    parsed = urllib.parse.urlsplit("tls://" + endpoint)
    host, port = parsed.hostname, parsed.port or 853
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=8) as raw:
        with context.wrap_socket(raw, server_hostname=host) as conn:
            conn.sendall(struct.pack("!H", len(packet)) + packet)
            head = conn.recv(2)
            if len(head) != 2:
                raise OSError("не получен DNS-ответ по DoT")
            remaining = struct.unpack("!H", head)[0]
            while remaining:
                chunk = conn.recv(remaining)
                if not chunk:
                    raise OSError("оборван DNS-ответ по DoT")
                remaining -= len(chunk)


def read_querylog(node, path, ssh_dir):
    path = validate_querylog_path(path)
    if node["fingerprint"] == "local":
        with open(path, "rb") as stream:
            stream.seek(max(0, os.path.getsize(path) - 8 * 1024 * 1024))
            return stream.read().decode("utf-8", "replace")
    remote_command = "tail -c 8388608 -- " + path
    command = [
        "ssh", "-i", node["key_path"], "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
        "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={ssh_dir}/known_hosts",
        "--", f"{node['user']}@{node['host']}", remote_command,
    ]
    try:
        result = subprocess.run(command, capture_output=True, timeout=12, check=False)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("превышено время чтения query log по SSH") from exc
    if result.returncode:
        detail = result.stderr.decode("utf-8", "replace").strip()[:250]
        raise RuntimeError(detail or "не удалось прочитать query log по SSH")
    return result.stdout.decode("utf-8", "replace")


def check_dns_routes(node, ssh_dir, log_wait_seconds=25):
    """Send unique probes and count only names present in the selected node's AdGuard log."""
    with connect() as db:
        routes = db.execute(
            "SELECT id,route_type,endpoint,probe_count FROM dns_routes WHERE node_id=? AND enabled=1 ORDER BY id",
            (node["id"],),
        ).fetchall()
        config = db.execute("SELECT querylog_path FROM dns_node_config WHERE node_id=?", (node["id"],)).fetchone()
    if not routes:
        return {"status": "not_configured", "message": "DNS-маршруты не настроены", "routes": []}
    if not config or not config["querylog_path"]:
        return {"status": "not_configured", "message": "Не задан путь к журналу AdGuard", "routes": []}

    probes = []
    for route in routes:
        proto, _ = DNS_ROUTE_DEFAULTS.get(route["route_type"], (None, 0))
        if proto is None:
            return {"status": "error", "message": f"Неизвестный тип маршрута: {route['route_type']}", "routes": []}
        try:
            validate_endpoint(route["route_type"], route["endpoint"])
        except ValueError as exc:
            return {"status": "error", "message": f"{route['route_type']}: {exc}", "routes": []}
        for _ in range(route["probe_count"]):
            qname = "rvk-" + secrets.token_hex(12) + ".example.org"
            probes.append({"route_id": route["id"], "route_type": route["route_type"],
                           "endpoint": route["endpoint"], "proto": proto, "qname": qname,
                           "send_error": ""})

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {pool.submit(send_dns_probe, p["endpoint"], p["proto"], p["qname"]): p for p in probes}
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as exc:
                futures[future]["send_error"] = f"{type(exc).__name__}: {exc}"

    found = set()
    deadline = time.monotonic() + max(0, log_wait_seconds)
    while True:
        try:
            querylog = read_querylog(node, config["querylog_path"], ssh_dir)
        except Exception as exc:
            return {"status": "log_error", "message": f"Не удалось прочитать журнал AdGuard: {exc}", "routes": []}
        found = {probe["qname"] for probe in probes if probe["qname"] in querylog}
        if len(found) == len(probes) or time.monotonic() >= deadline:
            break
        time.sleep(min(2, max(0, deadline - time.monotonic())))

    results = []
    for route in routes:
        route_probes = [p for p in probes if p["route_id"] == route["id"]]
        results.append({
            "route_type": route["route_type"], "endpoint": route["endpoint"],
            "total": len(route_probes), "logged": sum(p["qname"] in found for p in route_probes),
            "send_errors": [p["send_error"] for p in route_probes if p["send_error"]],
        })
    total, logged = len(probes), len(found)
    return {"status": "ok" if total == logged else "incomplete", "message": "",
            "routes": results, "total": total, "logged": logged}
