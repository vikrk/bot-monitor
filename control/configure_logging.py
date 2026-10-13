#!/usr/bin/python3
"""Install diagnostic logging on a systemd Linux server; never configure routes."""
import argparse
import datetime
import fcntl
import glob
import grp
import json
import os
from pathlib import Path
import pwd
import re
import shlex
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time

BASE = Path('/usr/local/lib/rvkomi-watchdog')
ROOT = Path('/etc/rvkomi-watchdog')
STATE = Path('/var/lib/rvkomi-watchdog')
LOG = Path('/var/log/rvkomi-watchdog')
XRAY_LOG = {'access': '/var/log/xray/access.log', 'error': '/var/log/xray/error.log',
            'loglevel': 'info', 'dnsLog': True}
RETENTION = 72 * 3600


def run(args, timeout=45, check=True):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if check and result.returncode:
        # Do not print service configuration, DB content or log lines with secrets.
        raise RuntimeError('Command failed: ' + args[0] + ' (exit ' + str(result.returncode) + ')')
    return result


def active(unit):
    return run(['systemctl', 'is-active', '--quiet', unit], check=False).returncode == 0


def loaded(unit):
    return run(['systemctl', 'show', '-p', 'LoadState', '--value', unit]).stdout.strip() == 'loaded'


def put(path, text, mode=0o644):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.read_text() == text:
        return False
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name, dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as handle:
            if path.exists():
                previous = path.stat()
                os.fchown(handle.fileno(), previous.st_uid, previous.st_gid)
            os.fchmod(handle.fileno(), mode)
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return True


def backup(path):
    directory = Path('/var/backups/rvkomi-logging') / str(time.time_ns())
    directory.mkdir(mode=0o700, parents=True)
    destination = directory / Path(path).name
    shutil.copy2(path, destination)
    destination.chmod(0o600)
    return destination


def service_log_directory(unit):
    directory = Path('/var/log/xray' if unit == 'x-ui' else '/var/log/xray-standalone')
    directory.mkdir(mode=0o750, parents=True, exist_ok=True)
    user = run(['systemctl', 'show', '-p', 'User', '--value', unit]).stdout.strip() or 'root'
    group = run(['systemctl', 'show', '-p', 'Group', '--value', unit]).stdout.strip()
    owner = pwd.getpwnam(user)
    gid = grp.getgrnam(group).gr_gid if group else owner.pw_gid
    os.chown(directory, owner.pw_uid, gid)
    for filename in ('access.log', 'error.log'):
        path = directory / filename
        path.touch(exist_ok=True)
        path.chmod(0o640)
        os.chown(path, owner.pw_uid, gid)
    changed = put('/etc/systemd/system/' + unit + '.service.d/rvkomi-logging.conf',
                  '[Service]\nReadWritePaths=' + str(directory) + '\n')
    if changed:
        run(['systemctl', 'daemon-reload'])
    return changed


def journal():
    changed = put('/etc/systemd/journald.conf.d/zz-rvkomi-retention.conf',
                  '[Journal]\nStorage=persistent\nCompress=yes\nMaxRetentionSec=72h\nMaxFileSec=1h\n'
                  'SystemMaxUse=1G\nRuntimeMaxUse=1G\nSystemMaxFileSize=16M\nSystemMaxFiles=256\n'
                  'SystemKeepFree=1G\nRateLimitIntervalSec=0\n')
    path = Path('/var/log/journal')
    path.mkdir(parents=True, exist_ok=True)
    os.chown(path, 0, grp.getgrnam('systemd-journal').gr_gid)
    path.chmod(0o2755)
    if changed:
        run(['systemctl', 'restart', 'systemd-journald'])
    run(['journalctl', '--flush'])
    return 'persistent; 72h; rotate 1h; limit 1G'


def panel_xray():
    db = Path('/etc/x-ui/x-ui.db')
    config = Path('/usr/local/x-ui/bin/config.json')
    binary = next((p for p in Path('/usr/local/x-ui/bin').glob('xray-linux-*')
                   if p.is_file() and os.access(p, os.X_OK)), Path('/usr/local/x-ui/bin/xray-linux-amd64'))
    if not loaded('x-ui') or not db.is_file():
        return 'not installed'
    con = sqlite3.connect('file:' + str(db) + '?mode=ro', uri=True)
    try:
        row = con.execute("SELECT key,value FROM settings WHERE key IN ('xrayTemplateConfig','xrayTemplate') "
                          "ORDER BY CASE key WHEN 'xrayTemplateConfig' THEN 0 ELSE 1 END LIMIT 1").fetchone()
    finally:
        con.close()
    if not row:
        raise RuntimeError('3X-UI has no Xray template; logging requires a supported panel template')
    template_key = row[0]
    template = json.loads(row[1])
    desired = {**template.get('log', {}), **XRAY_LOG}
    current = json.loads(config.read_text()) if config.exists() else None
    dropin = service_log_directory('x-ui')
    if template.get('log') == desired and (current is None or current.get('log') == desired) and not dropin:
        return 'access + error/info + DNS already enabled'
    if not binary.exists() or current is None:
        raise RuntimeError('3X-UI runtime config or Xray binary is missing')
    template['log'] = desired
    candidate = {**current, 'log': desired}
    fd, name = tempfile.mkstemp(prefix='rvkomi-log-', suffix='.json', dir=config.parent)
    try:
        with os.fdopen(fd, 'w') as handle:
            os.fchmod(handle.fileno(), 0o600)
            json.dump(candidate, handle)
        run([str(binary), 'run', '-test', '-config', name])
    finally:
        os.unlink(name)
    was_active = active('x-ui')
    saved_config = backup(config)
    saved_db = None
    try:
        if was_active:
            run(['systemctl', 'stop', 'x-ui'])
        # sqlite backup includes WAL and is independent of filesystem copies.
        saved_db = backup(db)
        con = sqlite3.connect(db)
        copy = sqlite3.connect(saved_db)
        con.backup(copy)
        copy.close()
        try:
            row = con.execute("SELECT value FROM settings WHERE key=?", (template_key,)).fetchone()
            fresh = json.loads(row[0])
            fresh['log'] = {**fresh.get('log', {}), **XRAY_LOG}
            con.execute("UPDATE settings SET value=? WHERE key=?", (json.dumps(fresh), template_key))
            con.commit()
        finally:
            con.close()
        put(config, json.dumps(candidate, indent=2) + '\n', 0o600)
        if was_active:
            run(['systemctl', 'start', 'x-ui'])
            if not active('x-ui'):
                raise RuntimeError('3X-UI did not start with logging enabled')
    except Exception:
        if was_active:
            run(['systemctl', 'stop', 'x-ui'], check=False)
        shutil.copy2(saved_config, config)
        if saved_db:
            source = sqlite3.connect(saved_db)
            target = sqlite3.connect(db)
            source.backup(target)
            target.close()
            source.close()
        if was_active:
            run(['systemctl', 'start', 'x-ui'])
        raise
    return 'access + error/info + DNS enabled in panel template and runtime'


def standalone_xray():
    if not loaded('xray'):
        return 'not installed'
    command = run(['systemctl', 'show', '-p', 'ExecStart', '--value', 'xray']).stdout
    match = re.search(r'(?:-config|-c)\s+([^\s;]+)', command)
    path = Path(match.group(1)) if match else next(
        (p for p in (Path('/usr/local/etc/xray/config.json'), Path('/etc/xray/config.json')) if p.is_file()), None)
    if not path or not path.is_file():
        raise RuntimeError('Standalone Xray config location is unsupported')
    config = json.loads(path.read_text())
    desired = {**config.get('log', {}), **XRAY_LOG,
               'access': '/var/log/xray-standalone/access.log',
               'error': '/var/log/xray-standalone/error.log'}
    dropin = service_log_directory('xray')
    if config.get('log') == desired and not dropin:
        return 'access + error/info + DNS already enabled'
    binary = shutil.which('xray') or '/usr/local/bin/xray'
    config['log'] = desired
    fd, temporary = tempfile.mkstemp(suffix='.json', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as handle:
            os.fchmod(handle.fileno(), 0o600)
            json.dump(config, handle)
        run([binary, 'run', '-test', '-config', temporary])
    finally:
        os.unlink(temporary)
    saved = backup(path)
    was_active = active('xray')
    try:
        put(path, json.dumps(config, indent=2) + '\n', path.stat().st_mode & 0o777)
        if was_active:
            run(['systemctl', 'restart', 'xray'])
    except Exception:
        shutil.copy2(saved, path)
        if was_active:
            run(['systemctl', 'restart', 'xray'])
        raise
    return 'access + error/info + DNS enabled'


# Preserve quoted strings, comments, include contexts, and all route directives.
TOKENS = re.compile(r'\s+|#[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[{};]|[^\s{};#]+')
START, END = '# BEGIN RVKOMI DIAGNOSTIC LOGGING', '# END RVKOMI DIAGNOSTIC LOGGING'


def nginx():
    if not shutil.which('nginx'):
        return 'not installed'
    run(['nginx', '-t'])
    dump = run(['nginx', '-T']).stdout
    files = re.findall(r'^# configuration file (.+):$', dump, re.M)
    if not files:
        raise RuntimeError('Cannot determine nginx configuration files')
    originals, updates, visiting = {}, {}, set()
    main = Path(files[0])
    prefix = main.parent
    preread = 'ssl_preread' in dump or '--with-stream_ssl_preread_module' in run(['nginx', '-V']).stderr
    http_format = """log_format rvkomi_http escape=json '{"time":"$time_iso8601","request_id":"$request_id","client":"$remote_addr","server":"$server_name","port":"$server_port","host":"$host","method":"$request_method","uri":"$uri","status":$status,"request_time":"$request_time","upstream":"$upstream_addr","upstream_status":"$upstream_status","connect_time":"$upstream_connect_time","header_time":"$upstream_header_time","response_time":"$upstream_response_time","tls":"$ssl_protocol","cipher":"$ssl_cipher","sni":"$ssl_server_name"}';
access_log /var/log/nginx/rvkomi-http.log rvkomi_http;
"""
    sni = '$ssl_preread_server_name' if preread else '-'
    tls = '$ssl_preread_protocol' if preread else '-'
    stream_format = """log_format rvkomi_sni escape=json '{"time":"$time_iso8601","remote":"$remote_addr","protocol":"$protocol","status":$status,"sni":"%s","tls":"%s","session_time":"$session_time","upstream":"$upstream_addr","connect_time":"$upstream_connect_time","first_byte_time":"$upstream_first_byte_time","bytes_sent":$bytes_sent,"bytes_received":$bytes_received}';
access_log /var/log/nginx/rvkomi-sni.log rvkomi_sni;
""" % (sni, tls)
    contexts = set()
    def visit(path, inherited):
        path = path.resolve()
        identity = (str(path), inherited)
        if identity in visiting:
            return
        visiting.add(identity)
        original = path.read_text()
        text = re.sub(r'\n?[ \t]*' + re.escape(START) + r'\n.*?' + re.escape(END) + r'\n?', '', original, flags=re.S)
        originals[path] = original
        tokens = [(m.group(), m.start(), m.end()) for m in TOKENS.finditer(text)
                  if not m.group().isspace() and not m.group().startswith('#')]
        stack, statement, edits = [inherited], [], []
        for value, start, stop in tokens:
            if value == '{':
                name = statement[0][0] if statement else ''
                context = name if name in ('http', 'stream') else stack[-1]
                stack.append(context)
                if name in ('http', 'stream'):
                    contexts.add(name)
                    content = http_format if name == 'http' else stream_format
                    edits.append((stop, stop, '\n' + START + '\n' + content + END + '\n'))
                elif name in ('server', 'location') and context in ('http', 'stream'):
                    format_name, filename = ('rvkomi_http', 'http') if context == 'http' else ('rvkomi_sni', 'sni')
                    edits.append((stop, stop, '\n' + START + '\naccess_log /var/log/nginx/rvkomi-' + filename + '.log ' + format_name + ';\n' + END + '\n'))
                statement = []
            elif value == '}':
                if len(stack) > 1:
                    stack.pop()
                statement = []
            elif value == ';':
                if statement:
                    directive = statement[0][0]
                    if directive == 'include' and len(statement) == 2:
                        pattern = statement[1][0].strip('\'"')
                        if not Path(pattern).is_absolute():
                            pattern = str(prefix / pattern)
                        for filename in sorted(glob.glob(pattern)):
                            visit(Path(filename), stack[-1])
                    elif directive == 'access_log' and len(statement) == 2 and statement[1][0] == 'off' and stack[-1] in ('http', 'stream'):
                        edits.append((statement[0][1], stop, '# RVKOMI: diagnostic access logging enabled\n'))
                statement = []
            else:
                statement.append((value, start, stop))
        for start, stop, replacement in sorted(edits, reverse=True):
            text = text[:start] + replacement + text[stop:]
        if path in updates and updates[path] != text:
            raise RuntimeError('nginx file reused across incompatible contexts')
        updates[path] = text
    visit(main, 'main')
    if 'http' not in contexts and 'stream' not in contexts:
        raise RuntimeError('No nginx HTTP/stream context found')
    changed = [path for path, text in updates.items() if text != originals[path]]
    written = []
    try:
        for path in changed:
            backup(path)
            put(path, updates[path], path.stat().st_mode & 0o777)
            written.append(path)
        run(['nginx', '-t'])
        if changed and active('nginx'):
            run(['systemctl', 'reload', 'nginx'])
    except Exception:
        for path in written:
            put(path, originals[path], path.stat().st_mode & 0o777)
        raise
    return {'http': 'http' in contexts, 'stream': 'stream' in contexts, 'sni_preread_available': preread}


def adguard():
    if not loaded('AdGuardHome'):
        return 'not installed'
    import yaml
    pid = run(['systemctl', 'show', '-p', 'MainPID', '--value', 'AdGuardHome']).stdout.strip()
    paths = [Path('/opt/AdGuardHome/AdGuardHome.yaml'), Path('/etc/AdGuardHome/AdGuardHome.yaml')]
    if pid.isdigit() and int(pid):
        args = Path('/proc/' + pid + '/cmdline').read_bytes().decode().split('\0')
        for index, arg in enumerate(args[:-1]):
            if arg in ('-c', '--config'):
                candidate = Path(args[index + 1])
                if not candidate.is_absolute():
                    candidate = Path(os.readlink('/proc/' + pid + '/cwd')) / candidate
                paths.insert(0, candidate)
    path = next((p for p in paths if p.is_file()), None)
    if path is None:
        raise RuntimeError('AdGuardHome config location is unsupported')
    data = yaml.safe_load(path.read_text())
    for key in ('querylog', 'statistics'):
        if not isinstance(data.get(key), dict) or 'interval' not in data[key]:
            raise RuntimeError('AdGuardHome interval schema is unsupported')
    if all(data[k].get('enabled') is True and data[k]['interval'] == '6h' for k in ('querylog', 'statistics')):
        return 'querylog + statistics 6h already configured'
    was_active = active('AdGuardHome')
    if was_active:
        run(['systemctl', 'stop', 'AdGuardHome'])
    saved = None
    try:
        # Re-read after graceful stop: AdGuard can save its current settings at exit.
        saved = backup(path)
        data = yaml.safe_load(path.read_text())
        for key in ('querylog', 'statistics'):
            data[key]['enabled'] = True
            data[key]['interval'] = '6h'
        put(path, yaml.safe_dump(data, allow_unicode=True, sort_keys=False), 0o600)
        if was_active:
            run(['systemctl', 'start', 'AdGuardHome'])
            if not active('AdGuardHome'):
                raise RuntimeError('AdGuardHome did not start with 6h retention')
    except Exception:
        if saved:
            shutil.copy2(saved, path)
        if was_active:
            run(['systemctl', 'restart', 'AdGuardHome'])
        raise
    return 'querylog + statistics 6h; DNS/filtering rules preserved'


def containers():
    if not shutil.which('docker') or not active('docker'):
        return []
    result = run(['docker', 'ps', '--format', '{{.Names}}'], check=False)
    if result.returncode:
        return []
    forwarded = []
    for name in result.stdout.splitlines():
        if not re.fullmatch(r'amnezia[A-Za-z0-9_.-]*', name, re.I):
            continue
        driver = run(['docker', 'inspect', '--format', '{{.HostConfig.LogConfig.Type}}', name]).stdout.strip()
        if driver == 'journald':
            continue
        if driver == 'none':
            raise RuntimeError('Amnezia container has logging driver none; stdout cannot be forwarded')
        unit = 'rvkomi-container-journal@' + name + '.service'
        run(['systemctl', 'enable', '--now', unit])
        forwarded.append(name)
    manifest = STATE / 'container-journal-forwarders.json'
    previous = json.loads(manifest.read_text()) if manifest.exists() else []
    for name in set(previous) - set(forwarded):
        if re.fullmatch(r'amnezia[A-Za-z0-9_.-]*', name, re.I):
            run(['systemctl', 'disable', '--now', 'rvkomi-container-journal@' + name + '.service'])
    put(manifest, json.dumps(forwarded) + '\n', 0o600)
    return forwarded


def install_units(agent_dirs):
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    LOG.mkdir(mode=0o750, parents=True, exist_ok=True)
    config = ROOT / 'diagnostic-logging.json'
    previous = json.loads(config.read_text()) if config.exists() else {}
    directories = set(previous.get('agent_dirs', [])) | {str(Path(p).resolve()) for p in agent_dirs}
    put(config, json.dumps({'agent_dirs': sorted(directories), 'retention_hours': 72, 'adguard_hours': 6}, indent=2) + '\n', 0o600)
    put('/etc/systemd/system/rvkomi-log-maintenance.service',
        '[Unit]\nDescription=RVKOMI diagnostic logging and 72h retention\nAfter=systemd-journald.service\n'
        '[Service]\nType=oneshot\nExecStart=/usr/bin/python3 ' + str(BASE / 'configure_logging.py') + ' maintain\n'
        'TimeoutStartSec=5min\nUMask=0077\n')
    put('/etc/systemd/system/rvkomi-log-maintenance.timer',
        '[Unit]\nDescription=Hourly RVKOMI log rotation and retention\n[Timer]\nOnCalendar=hourly\n'
        'Persistent=true\n[Install]\nWantedBy=timers.target\n')
    put('/etc/systemd/system/rvkomi-container-journal@.service',
        '[Unit]\nDescription=RVKOMI container %i journal forwarder\nAfter=docker.service\n'
        '[Service]\nExecStart=/usr/bin/env docker logs --follow --timestamps --since=1m %i\n'
        'Restart=on-failure\nRestartSec=30s\nStandardOutput=journal\nStandardError=journal\n'
        'SyslogIdentifier=amnezia-%i\n[Install]\nWantedBy=multi-user.target\n')
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'enable', '--now', 'rvkomi-log-maintenance.timer'])


def retention():
    # Only known diagnostic log directories, not backups, AdGuard querylog or databases.
    directories = [Path('/var/log/xray'), Path('/var/log/xray-standalone'), Path('/var/log/nginx'),
                   Path('/var/log/x-ui'), Path('/var/log/rvkomi-probes'), Path('/var/log/rvkomi-xray'), LOG]
    files = sorted({str(p) for directory in directories if directory.exists()
                    for p in directory.glob('*.log') if p.is_file() and not p.is_symlink()})
    if files:
        text = '\n'.join('"' + p + '"' for p in files) + """ {
    hourly
    rotate 96
    missingok
    notifempty
    compress
    delaycompress
    dateext
    dateformat -%Y%m%dT%H%M%S
    copytruncate
    su root root
}
"""
        put(ROOT / 'diagnostic-logrotate.conf', text, 0o600)
        run(['logrotate', '--state', str(STATE / 'diagnostic-logrotate.state'),
             str(ROOT / 'diagnostic-logrotate.conf')])
    run(['journalctl', '--rotate', '--vacuum-time=72h'])
    cut, removed = time.time() - RETENTION, 0
    for directory in directories:
        if not directory.exists():
            continue
        for path in directory.iterdir():
            if path.is_symlink() or not path.is_file():
                continue
            match = re.fullmatch(r'.+\.log-(\d{8}T\d{6})(?:\.gz)?', path.name)
            numbered = re.fullmatch(r'.+\.log\.\d+(?:\.gz)?', path.name)
            if not match and not numbered:
                continue
            stamp = datetime.datetime.strptime(match[1], '%Y%m%dT%H%M%S').timestamp() if match else path.stat().st_mtime
            if stamp < cut:
                path.unlink()
                removed += 1
    system_pattern = re.compile(r'(?:(?:goamnezia|gotelegram|godns).*\.log|syslog|auth\.log|kern\.log|daemon\.log|messages|debug|user\.log|cron\.log|mail(?:\.log|\.info|\.warn|\.err)|ufw\.log|fail2ban\.log)\.[0-9]+(?:\.gz)?$')
    for path in Path('/var/log').iterdir():
        if not path.is_symlink() and path.is_file() and system_pattern.fullmatch(path.name) and path.stat().st_mtime < cut:
            path.unlink()
            removed += 1
    config = json.loads((ROOT / 'diagnostic-logging.json').read_text())
    # Keep the current state snapshot; trim timestamped check histories under their writer locks.
    histories = [(STATE / 'history.jsonl', STATE / 'history.lock')]
    histories += [(Path(p) / 'read-only-check.jsonl', Path(p) / 'check.lock') for p in config['agent_dirs']]
    for path, lock in histories:
        if not path.is_file() or path.is_symlink():
            continue
        with lock.open('a+') as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            history_cut = time.time() - 30 * 86400 if path == STATE / 'history.jsonl' else cut
            kept = []
            for line in path.read_text().splitlines():
                try:
                    item = json.loads(line)
                    stamp = item.get('t', item.get('last_check'))
                    if isinstance(stamp, (float, int)) and stamp >= history_cut:
                        kept.append(line)
                except ValueError:
                    continue
            put(path, '\n'.join(kept) + ('\n' if kept else ''), 0o600)
    return {'archives_removed': removed, 'retention_hours': 72}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('install', 'maintain'))
    parser.add_argument('--agent-dir', action='append', default=[])
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('Diagnostic logging requires root on a systemd Linux server')
    if not shutil.which('systemctl') or not shutil.which('logrotate'):
        raise SystemExit('systemd and logrotate are required')
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (STATE / 'logging-setup.lock').open('a+') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if args.operation == 'install':
            install_units(args.agent_dir)
        result = {'updated_at': time.time(), 'components': {}, 'errors': {}}
        for name, function in [('journald', journal), ('xui_xray', panel_xray),
                               ('standalone_xray', standalone_xray), ('nginx', nginx),
                               ('adguard', adguard), ('amnezia_journal_forwarders', containers),
                               ('retention', retention)]:
            try:
                result['components'][name] = function()
            except Exception as exc:
                result['errors'][name] = {'type': type(exc).__name__,
                    'reason': str(exc) if isinstance(exc, RuntimeError) else 'Configuration could not be applied; consult journal'}
        put(STATE / 'diagnostic-logging-status.json', json.dumps(result, indent=2) + '\n', 0o600)
        print(json.dumps(result))
        if result['errors']:
            raise SystemExit(1)


if __name__ == '__main__':
    main()
