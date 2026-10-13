#!/usr/bin/python3
"""Inventory-driven UI using the existing control bot API and report formatter."""
import concurrent.futures
import fcntl
import json
import secrets
import threading
import time
import fleet
import advanced
import ai_diagnostics

COMMANDS = [('menu', 'Меню серверов'), ('status', 'Последние результаты'), ('check_all', 'Свежая проверка всех узлов'),
            ('resources', 'Ресурсы всех узлов'), ('history', 'История проверок'), ('ai_all', 'ИИ-анализ всех узлов'),
            ('cancel', 'Отменить предложения перезапуска'), ('help', 'Настройка и команды')]
HELP = ('/menu — подключённые узлы\n/status — последние результаты\n/check_all — свежие проверки\n'
        '/resources — ресурсы\n/history — история\n/ai_all — ИИ-диагностика\n/cancel — отмена предложений\n\n'
        'Добавление сервера, роутера и изменение профилей: sudo fleetctl на управляющем сервере. '
        'Проверяются только настроенные службы и маршруты. Перезапуск доступен только для служб из разрешённого списка '
        'и требует вашего подтверждения. Автоматического reboot нет.')


def run(tc, mode):
    class Controller(tc.Bot):
        def menu(self):
            rows = [[{'text': '📊 Статус', 'callback_data': 'fleetmenu:status'},
                     {'text': '🔎 Проверить все', 'callback_data': 'fleetmenu:check_all'}],
                    [{'text': '🧠 ИИ-анализ всех', 'callback_data': 'fleetmenu:ai_all'}]]
            for identifier, node in fleet.nodes().items():
                rows.append([{'text': ('📡 ' if node['kind'] == 'router' else '🖥 ') + node['name'],
                              'callback_data': 'fleetnode:' + identifier}])
            rows.extend([[{'text': '⚙️ Ресурсы', 'callback_data': 'fleetmenu:resources'},
                          {'text': '📈 История', 'callback_data': 'fleetmenu:history'}],
                         [{'text': '➕ Подключение / настройки', 'callback_data': 'fleetmenu:help'}]])
            self.send('Подключённые узлы. Выберите сервер или роутер.', {'inline_keyboard': rows})

        def node_menu(self, identifier):
            node = fleet.nodes()[identifier]
            profile = node.get('profile', {})
            text = node['name'] + ' — ' + node['address'] + '\n'
            text += 'Службы: ' + (', '.join(profile.get('services', [])) or 'не настроены') + '\n'
            text += 'HTTP: ' + str(len(profile.get('urls', []))) + '; TLS: ' + str(len(profile.get('tls', []))) + '; DNS: ' + str(len(profile.get('dns_routes', [])))
            rows = [[{'text': '🔎 Проверить', 'callback_data': 'fleetcheck:' + identifier}]]
            if node['transport'] in ('local', 'ssh-agent'):
                rows.append([{'text': '📜 Журналы служб', 'callback_data': 'fleetlogs:' + identifier}])
                for index, service in enumerate(profile.get('allowed_restarts', [])):
                    rows.append([{'text': 'Предложить перезапуск ' + service, 'callback_data': 'fleetrepair:' + identifier + ':' + str(index)}])
            rows.append([{'text': 'Назад', 'callback_data': 'fleetmenu:menu'}])
            self.send(text, {'inline_keyboard': rows})

        def checks(self, identifiers, fresh=True):
            for identifier in identifiers:
                try:
                    node = fleet.nodes()[identifier]
                    result = fleet.check(identifier) if fresh else fleet.status(identifier)
                    if fresh: advanced.journal(identifier, result, 'check')
                    if result.get('skipped'):
                        self.send(node['name'] + ': проверка пропущена (' + str(result['skipped']) +
                                  '); время последнего результата не изменено.')
                        continue
                    if result.get('connection_error'):
                        self.send('⚠️ ' + node['name'] + ': текущий SSH/RPC недоступен; далее последний сохранённый результат.')
                    if not fresh and not result.get('last_check'):
                        self.send(node['name'] + ': SSH доступен; плановая проверка ещё не выполнялась.')
                    else:
                        if not fresh: result = {key: value for key, value in result.items() if key != 'report'}
                        self.send(tc.format_result(node['name'], result))
                except Exception:
                    self.send('⚠️ ' + fleet.label(identifier) + ': проверку получить не удалось. Проверьте SSH-доступ и профиль.')

        def resources(self):
            lines = ['⚙️ Ресурсы подключённых узлов']
            for identifier in fleet.nodes():
                try:
                    metrics = fleet.rpc(identifier, 'extras')
                    advanced.journal(identifier, metrics, 'resources')
                    lines.append(f"{fleet.label(identifier)}: диск свободно {metrics.get('disk_free_gb', '?')} ГБ; "
                        f"RAM {metrics.get('memory_available_mb', '?')}/{metrics.get('memory_total_mb', '?')} МБ; нагрузка {metrics.get('load', [])}")
                except Exception: lines.append(fleet.label(identifier) + ': ресурсы недоступны')
            self.send('\n'.join(lines))

        def history(self):
            rows = advanced.history()
            lines = ['📈 История за 24 часа']
            for identifier in fleet.nodes():
                checks = [row for row in rows if row.get('h') == identifier and row.get('t', 0) > time.time() - 86400
                          and row.get('source') in ('check', 'scheduled') and not row.get('skipped')]
                ok = sum(not row.get('failures') for row in checks)
                lines.append(fleet.label(identifier) + ': ' + (str(ok) + '/' + str(len(checks)) + ' проверок успешно' if checks else 'данных пока нет'))
            self.send('\n'.join(lines))

        def logs(self, identifier):
            try:
                result = fleet.rpc(identifier, 'logs')
                self.send('📜 ' + fleet.label(identifier) + '\n' + ai_diagnostics.redact(json.dumps(result, ensure_ascii=False))[:3500])
            except Exception: self.send('Журналы настроенных служб недоступны. Проверьте права SSH-пользователя.')

        def ai(self):
            try: ai_diagnostics.load_config()
            except Exception as exc: self.send(str(exc)); return
            self.send('🧠 Получаю проверки и журналы всех подключённых узлов. Анализ может занять несколько минут.')
            checks, logs = {}, []
            for identifier, node in fleet.nodes().items():
                try:
                    result = fleet.check(identifier)
                    advanced.journal(identifier, result, 'check')
                    checks[node['name']] = result
                except Exception: checks[node['name']] = {'error': 'SSH/проверка недоступны'}
                if node['transport'] in ('local', 'ssh-agent'):
                    try: logs.append(node['name'] + ': ' + json.dumps(fleet.rpc(identifier, 'logs'), ensure_ascii=False))
                    except Exception: logs.append(node['name'] + ': журналы недоступны')
            history = [row for row in advanced.history() if row.get('h') in fleet.nodes()][-160:]
            try: result = ai_diagnostics.analyze(checks, history, {}, '\n'.join(logs))
            except Exception as exc: result = str(exc)
            self.send('🧠 ИИ-анализ всех узлов\n\n' + result + '\n\nПредложения ИИ не исполняются автоматически. Перезапуски — через кнопки разрешённых служб.')

        def repair(self, identifier, index):
            node = fleet.nodes()[identifier]
            service = node.get('profile', {}).get('allowed_restarts', [])[index]
            nonce = secrets.token_hex(16)
            message = self.send('Перезапустить ' + service + ' на «' + node['name'] + '»? Подключения этой службы могут прерваться. Подтверждение действует 2 минуты.',
                {'inline_keyboard': [[{'text': 'Подтвердить', 'callback_data': 'fleetconfirm:' + nonce},
                                     {'text': 'Отмена', 'callback_data': 'fleetabort:' + nonce}]]})
            with self.lock:
                self.state.setdefault('repairs', {})[nonce] = {'node': identifier, 'service': service,
                    'expires': time.time() + 120, 'message_id': message['message_id']}
                self.state['repairs'] = {key: value for key, value in self.state['repairs'].items() if value['expires'] > time.time()}
                self.save()

        def execute_repair(self, proposal):
            try:
                result = fleet.rpc(proposal['node'], 'restart ' + proposal['service'])
                self.send(fleet.label(proposal['node']) + ': ' + ('перезапуск подтверждён' if result.get('restarted') else 'служба не подтвердила перезапуск'))
                self.checks([proposal['node']])
            except Exception: self.send('Перезапуск не подтверждён. Проверьте статус и журнал перед повторным запросом.')

        def callback(self, query):
            if not tc.authorized_callback(query, self.owner): return
            kind, _, value = query.get('data', '').partition(':')
            try:
                if kind == 'fleetmenu':
                    self.answer(query['id'], 'Принято'); self.handle_command(value, time.time())
                elif kind in ('fleetnode', 'fleetcheck', 'fleetlogs') and value in fleet.nodes():
                    self.answer(query['id'], 'Принято')
                    if kind == 'fleetnode': self.node_menu(value)
                    elif kind == 'fleetcheck': self.start_checks([value])
                    else: self.executor.submit(self.logs, value)
                elif kind == 'fleetrepair':
                    identifier, _, index = value.partition(':')
                    if identifier in fleet.nodes() and index.isdigit():
                        self.answer(query['id'], 'Подготовка предложения'); self.repair(identifier, int(index))
                elif kind in ('fleetconfirm', 'fleetabort'):
                    with self.lock:
                        proposal = self.state.get('repairs', {}).get(value)
                        if not proposal or proposal['message_id'] != query.get('message', {}).get('message_id') or proposal['expires'] < time.time():
                            self.answer(query['id'], 'Предложение истекло или уже использовано'); return
                        del self.state['repairs'][value]; self.save()
                    self.remove_buttons(proposal['message_id'])
                    if kind == 'fleetabort': self.answer(query['id'], 'Отменено')
                    else:
                        self.answer(query['id'], 'Подтверждение принято'); self.reboot_executor.submit(self.execute_repair, proposal)
            except Exception: self.answer(query['id'], 'Узел или действие изменились; откройте меню заново')

        def start_checks(self, identifiers):
            with self.lock:
                if any(time.time() - self.state['check_times'].get(key, 0) < 30 for key in identifiers):
                    self.send('Проверка уже запрошена. Подождите 30 секунд.'); return
                for key in identifiers: self.state['check_times'][key] = time.time()
                self.save()
            self.send('🔎 Начинаю проверку настроенных служб и маршрутов.')
            self.executor.submit(self.checks, identifiers)

        def handle_command(self, command, message_date):
            if command in ('start', 'menu'): self.menu()
            elif command == 'help': self.send(HELP)
            elif command == 'status': self.executor.submit(self.checks, list(fleet.nodes()), False)
            elif command == 'check_all': self.start_checks(list(fleet.nodes()))
            elif command == 'resources': self.executor.submit(self.resources)
            elif command == 'history': self.executor.submit(self.history)
            elif command == 'ai_all':
                with self.lock:
                    if time.time() - self.state.get('last_ai_request', 0) < 60:
                        self.send('ИИ-анализ недавно запрошен. Подождите минуту.'); return
                    self.state['last_ai_request'] = time.time(); self.save()
                self.executor.submit(self.ai)
            elif command == 'cancel':
                with self.lock:
                    self.state['repairs'] = {}; self.save()
                self.send('Неподтверждённые перезапуски отменены.')
            else: self.send('Используйте /menu или /help.')

        def poll(self):
            if self.state.get('offset') is None:
                updates = self.api.call('getUpdates', {'timeout': 0, 'allowed_updates': ['message', 'callback_query']})
                self.state['offset'] = max((item['update_id'] + 1 for item in updates), default=0); self.save()
            while True:
                try: updates = self.api.call('getUpdates', {'offset': self.state['offset'], 'timeout': 25,
                    'allowed_updates': ['message', 'callback_query']}, timeout=35)
                except RuntimeError: time.sleep(10); continue
                for update in updates:
                    with self.lock: self.state['offset'] = update['update_id'] + 1; self.save()
                    try: self.dispatch(update)
                    except Exception: print(json.dumps({'event': 'dispatch-error'}), flush=True)

    credentials = json.loads((fleet.ROOT / 'telegram.json').read_text())
    owner = int(credentials['chat_id'])
    if owner <= 0: raise ValueError('Нужен личный чат владельца')
    api = tc.API(credentials)
    me = api.call('getMe')
    if api.call('getWebhookInfo').get('url'): raise RuntimeError('Сначала отключите existing webhook этого бота')
    fleet.STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    if mode == 'register':
        api.call('setMyCommands', {'commands': [{'command': c, 'description': d} for c, d in COMMANDS],
            'scope': {'type': 'chat', 'chat_id': owner}})
        print(json.dumps({'registered': True})); return
    bot = Controller(api, owner, None, fleet.STATE / 'generic-control-state.json', me['username'])
    if mode == 'verify': bot.checks(list(fleet.nodes())); return
    if mode == 'announce': bot.send('Мониторинг подключённых узлов готов.\n' + HELP); return
    with (fleet.STATE / 'telegram-control.lock').open('a+') as lock:
        try: fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError: return
        bot.poll()


def monitor(tc):
    fleet.STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (fleet.STATE / 'extra-monitor.lock').open('a+') as lock:
        try: fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError: return
        path = fleet.STATE / 'generic-monitor-state.json'
        state = advanced.read(path, {'hosts': {}, 'queue': []})
        def one(identifier):
            if advanced.read(fleet.STATE / 'maintenance-central.json').get(identifier, {}).get('until', 0) > time.time():
                return identifier, {'skipped': 'maintenance'}
            try: return identifier, fleet.check(identifier)
            except Exception: return identifier, {'failures': ['ssh-or-check-unavailable'], 'last_check': time.time()}
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
            for identifier, result in pool.map(one, fleet.nodes()):
                advanced.journal(identifier, result, 'scheduled')
                if result.get('skipped'):
                    continue
                previous = state['hosts'].get(identifier, {})
                failures = result.get('failures', ['invalid-result'])
                count = previous.get('failed_count', 0) + 1 if failures else 0
                signature = sorted(failures) if count >= 3 else previous.get('signature', [])
                if count >= 3 and signature != previous.get('signature', []):
                    state['queue'].append('⚠️ ' + fleet.label(identifier) + ': 3 проверки подряд с ошибками: ' + ', '.join(signature))
                elif not failures and previous.get('signature'):
                    state['queue'].append('✅ ' + fleet.label(identifier) + ': проверки восстановились.')
                state['hosts'][identifier] = {'failed_count': count, 'signature': signature if failures else [], 'last_check': result.get('last_check')}
        credentials = json.loads((fleet.ROOT / 'telegram.json').read_text())
        api = tc.API(credentials)
        queue = state['queue'][-50:]
        state['queue'] = queue
        for index, text in enumerate(queue):
            try: api.call('sendMessage', {'chat_id': int(credentials['chat_id']), 'text': text[:3900]}, timeout=12)
            except Exception: state['queue'] = queue[index:]; break
        else: state['queue'] = []
        advanced.atomic(path, state)
        print(json.dumps({'monitored_nodes': len(fleet.nodes()), 'queued': len(state['queue'])}))
