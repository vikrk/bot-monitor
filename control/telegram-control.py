#!/usr/bin/python3
"""Owner-only Telegram control plane. No arbitrary shell or automatic OS reboot."""
import copy, argparse, concurrent.futures, fcntl, json, os, re, secrets, subprocess, threading, time, urllib.error, urllib.request
from pathlib import Path
import history_diagnostics
import advanced
import home_monitor
import ai_diagnostics
import ai_admin

ROOT=Path('/etc/rvkomi-watchdog');STATE=Path('/var/lib/rvkomi-watchdog')
BRIDGE='/usr/local/lib/rvkomi-watchdog/bot-bridge.py'
NONCE=re.compile(r'^[0-9a-f]{32}$')
HOSTS=['spb','nl','dns','www','space','latvia','fin','telegramm']
AI_HOSTS=['spb','nl','dns','www','space','latvia','fin','telegramm']
EXTRA_HOSTS=['dns','www','space','latvia','fin','telegramm']
COMMANDS=[('status','Последний статус всех серверов'),('check_all','Свежая проверка всех серверов'),('ai_all','ИИ-анализ всех серверов и роутера'),('check_spb','SPB: маршруты, CDN и TLS-рукопожатие'),('check_nl','NL: маршруты, CDN и TLS-рукопожатие'),('check_dns','DNS: DoH/DoT, CDN и все подмены → FIN'),('check_www','Проверка WWW: VLESS и все выходы'),('check_space','Проверка SPACE'),('check_latvia','Проверка LATVIA'),('check_fin','FIN: VLESS и все SNI relay-проверки'),('check_telegramm','Проверка TELEGRAMM: службы'),('reboot_spb','Ручной reboot SPB с подтверждением'),('reboot_nl','Ручной reboot NL с подтверждением'),('cancel','Отмена неподтверждённых запросов'),('help','Команды и ограничения')]
HELP='DNS: все SNI-подмены → FIN. FIN: основной relay; NL: сохранён для отката.\nАвтоперезагрузки отключены.\n/status — последний статус\n/check_all — проверить все восемь серверов\n/check_spb /check_nl /check_dns /check_www /check_space /check_latvia /check_fin /check_telegramm — проверить выбранный сервер\n/reboot_spb /reboot_nl — запросить reboot\n/cancel — отменить неподтверждённые запросы\n\nReboot требует одноразового подтверждения за 2 минуты. Между перезагрузками любых серверов — минимум 10 минут. Одновременного reboot обоих серверов нет. DNS и WWW: ограниченное автоисправление; SPACE, LATVIA, FIN и TELEGRAMM: только наблюдение. Новые узлы не поддерживают reboot. Команды принимаются только от владельца в подключённом личном чате.'


# Read-only menu actions. Reboot remains available only through its existing flow.
BUTTON_COMMANDS={
    '☰ Меню':'menu', '📊 Статус':'status',
    '🔎 Проверить все':'check_all', '🧠 ИИ-анализ всех':'ai_all', 'ℹ️ Помощь':'help', '📡 PING':'ping', '🔌 CDN NL':'cdn_nl', '🔴 CDN NL':'cdn_nl', '🟢 CDN NL':'cdn_nl',
}
MENU_COMMANDS={'menu','help','status','check_all','ai_all','ping','cdn_nl',*('check_'+h for h in HOSTS)}
REPLY_KEYBOARD={'keyboard':[[{'text':'☰ Меню'},{'text':'📊 Статус'}],
    [{'text':'🔎 Проверить все'},{'text':'📡 PING'}],
    [{'text':'🧠 ИИ-анализ всех'}],
    [{'text':'🔌 CDN NL'},{'text':'ℹ️ Помощь'}]],
    'resize_keyboard':True,'is_persistent':True,'one_time_keyboard':False}
INLINE_MENU={'inline_keyboard':[
    [{'text':'📊 Статус всех','callback_data':'menu:status'},
     {'text':'🔎 Проверить все','callback_data':'menu:check_all'}],
    [{'text':'🧠 ИИ-анализ всех узлов','callback_data':'menu:ai_all'}],
    *[[{'text':'🔎 '+h.upper(),'callback_data':'menu:check_'+h} for h in row]
      for row in [('spb','nl'),('dns','www'),('space','latvia')]],
    [{'text':'🔎 FIN','callback_data':'menu:check_fin'},
     {'text':'🔎 TELEGRAM','callback_data':'menu:check_telegramm'}],
    [{'text':'ℹ️ Помощь','callback_data':'menu:help'}],
    [{'text':'📡 PING серверов и роутера','callback_data':'menu:ping'}],
    [{'text':'🔌 CDN NL — включить / выключить','callback_data':'menu:cdn_nl'}],
    [{'text':'✖️ Закрыть меню','callback_data':'menu:close'}]
]}
COMMANDS.insert(0,('cdn_nl','Включить или выключить YANDEX CDN на NL'))
HELP+='\n/cdn_nl — состояние и кнопка включения/выключения YANDEX CDN на NL. Применение перезапускает Xray: VPN-сессии NL могут кратковременно прерваться.'
COMMANDS.insert(0,('menu','Кнопки проверки серверов'))
COMMANDS.insert(1,('ping','По 4 ping: средняя задержка и потери'))
HELP+='\n\n/menu — открыть кнопки проверки. Кнопки не перезагружают серверы.'
HELP+='\n/ping — 4 ICMP-запроса к восьми серверам и роутеру настроенному адресу, с TELEGRAM. Нет ответа на ping не доказывает отказ VPN.'


HELP+='\n/check_spb и /check_nl: дополнительно TLS-рукопожатие CDN и origin, имя и цепочка сертификата, срок действия. Сбой только CDN не перезапускает службы.'

# Fixed, owner-controlled inventory; no user-provided ping destinations.
def inventory_ping_targets():
    import fleet
    if fleet.enabled():return [(n['name'],n['address']) for n in fleet.nodes().values() if n['transport']!='local']
    result=[]
    for filename in ('control-nodes.json','extra-nodes.json'):
        try:
            for name,node in json.loads((ROOT/filename).read_text()).items():
                result.append((name.upper(),node['address']))
        except (OSError,ValueError):pass
    return result
PING_TARGETS=inventory_ping_targets()

def ping_target(target):
    label,address=target
    env=os.environ.copy();env['LC_ALL']='C';env['LANG']='C'
    try:
        r=subprocess.run(['/usr/bin/ping','-4','-n','-c','4','-i','0.5','-W','2',address],
            capture_output=True,text=True,timeout=14,env=env)
    except (OSError,subprocess.TimeoutExpired):
        return {'label':label,'address':address,'error':'Не удалось завершить ping'}
    counts=re.search(r'(\d+) packets transmitted, (\d+) received',r.stdout)
    timing=re.search(r'(?:rtt|round-trip) min/avg/max/(?:mdev|stddev) = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)',r.stdout)
    if not counts or r.returncode not in (0,1):
        return {'label':label,'address':address,'error':'Ошибка выполнения ping'}
    sent,received=map(int,counts.groups())
    if not 0<=received<=sent<=4 or (received and timing is None):
        return {'label':label,'address':address,'error':'Некорректный результат ping'}
    return {'label':label,'address':address,'sent':sent,'received':received,
        'average_ms':float(timing.group(2)) if received else None}

def format_pings(results):
    lines=['📡 PING серверов и роутера — по 4 запроса','Точка проверки: TELEGRAM; его собственный адрес проверяется локально.','Роутер: настроенному адресу (IPv4-адрес, полученный из DNS).','']
    for r in results:
        if r.get('error'):
            lines.append('⚠️ '+r['label']+': '+r['error']);continue
        ok=r['received'];sent=r['sent'];avg=r['average_ms']
        latency=f'{avg:.2f} мс' if avg is not None else 'нет ответов'
        loss='без потерь' if sent==4 and ok==4 else 'потеряно '+str(sent-ok)+' из '+str(sent)
        lines.append(r['label']+': '+latency+'; '+loss)
    lines.extend(['','Среднее рассчитано только по полученным ответам.','ICMP может быть заблокирован: это не полная проверка VPN/служб.','Для проверки служб используйте кнопки «Проверить».'])
    return '\n'.join(lines)

def authorized_message(message,owner):
    return (message.get('chat',{}).get('type')=='private' and message.get('chat',{}).get('id')==owner
      and message.get('from',{}).get('id')==owner and not message.get('from',{}).get('is_bot',False)
      and not message.get('forward_origin') and not message.get('forward_from'))

def authorized_callback(query,owner):
    return (query.get('from',{}).get('id')==owner and not query.get('from',{}).get('is_bot',False)
      and query.get('message',{}).get('chat',{}).get('id')==owner
      and query.get('message',{}).get('chat',{}).get('type')=='private')

def atomic(path,data):
    tmp=path.with_name('.'+path.name+'.tmp');fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
    with os.fdopen(fd,'w') as f:json.dump(data,f,ensure_ascii=False);f.flush();os.fsync(f.fileno())
    os.replace(tmp,path)

COMMANDS.extend(home_monitor.COMMANDS)
BUTTON_COMMANDS.update(home_monitor.BUTTONS)
MENU_COMMANDS.update(c for c,d in home_monitor.COMMANDS)
REPLY_KEYBOARD['keyboard'].extend(home_monitor.REPLY_ROWS)
INLINE_MENU['inline_keyboard'][-1:-1]=home_monitor.INLINE_ROWS
HELP+='\n/home_check — домашняя DNS/HTTPS-проверка; /router — роутер, диски и WebDAV. Ресурсы каждый час, связь каждые 5 минут, домашние проверки каждые 2 часа. Yandex CDN: только 08:00 МСК при включённом NL CDN. Автоисправлений на роутере нет.'

COMMANDS.extend(advanced.COMMANDS)
BUTTON_COMMANDS.update(advanced.BUTTONS)
MENU_COMMANDS.update(c for c,d in advanced.COMMANDS)
REPLY_KEYBOARD['keyboard'].extend(advanced.REPLY_ROWS)
INLINE_MENU['inline_keyboard'][-1:-1]=advanced.INLINE_ROWS
HELP+='\n\n/summary — сводка; /backup и /backup_status — зашифрованные копии на роутер; /maintenance — обслуживание; /history — история за сутки; /certificates — сертификаты; /resources — ресурсы. История 30 дней. Копии ежедневно 04:00 МСК; сертификаты ежедневно 09:00 МСК. SSH-доступ не изменён. DE исключён.'

# Compact bottom keyboard: all other actions are in /menu.
REPLY_KEYBOARD['keyboard']=[[{'text':'🔌 CDN NL'}]]

COMMANDS.insert(0,('dns_sni_check','Проверить DNS и SNI-relay FIN'))
MENU_COMMANDS.add('dns_sni_check')
INLINE_MENU['inline_keyboard'].insert(1,[{'text':'🌐 Проверка DNS и SNI-relay','callback_data':'menu:dns_sni_check'}])
COMMANDS.insert(0,('ai_change','Предложить изменение с подтверждением'))
MENU_COMMANDS.add('ai_change')
INLINE_MENU['inline_keyboard'].insert(1,[{'text':'🛠 ИИ: предложить изменение','callback_data':'menu:ai_change'}])
HELP+='\n/ai_change — предложение правки: добавление доменов в существующее proxy-правило DNS-перезаписи, пользовательские правила и HTTPS-подписки AdGuard, SNI-домены и явные назначения FIN или перезапуск разрешённых служб. Только после объяснения и одноразового подтверждения владельца.'

class API:
    def __init__(self,credentials):self.token=credentials['bot_token'];self.opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    def call(self,method,data=None,timeout=40):
        req=urllib.request.Request('https://api.telegram.org/bot'+self.token+'/'+method,data=json.dumps(data or {}).encode(),headers={'Content-Type':'application/json'})
        try:
            with self.opener.open(req,timeout=timeout) as r:result=json.load(r)
        except urllib.error.HTTPError as exc:raise RuntimeError('Telegram HTTP '+str(exc.code)) from None
        except Exception:raise RuntimeError('Telegram transport unavailable') from None
        if not result.get('ok'):raise RuntimeError('Telegram request rejected')
        return result['result']

class Nodes:
    def call(self,host,action,nonce=None):
        if host not in HOSTS+['carol'] or action not in ['status','check','prepare','cancel','confirm','cdn-status','cdn-enable','cdn-disable']:raise ValueError('Invalid RPC')
        if action.startswith('cdn-') and (host!='nl' or nonce is not None):raise ValueError('CDN control only on NL')
        if nonce is not None and not NONCE.fullmatch(nonce):raise ValueError('Invalid request id')
        if host=='carol':host='spb'
        if host in EXTRA_HOSTS:
            if action not in ['status','check'] or nonce is not None:raise ValueError('Read-only node')
            cfg=json.loads((ROOT/'extra-nodes.json').read_text())[host]
        else:
            cfg=json.loads((ROOT/'control-nodes.json').read_text())[host]
        args=['ssh','-4','-T','-F','/dev/null','-i',cfg['key'],'-p',str(cfg['port']),
          '-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','StrictHostKeyChecking=yes',
          '-o','UserKnownHostsFile='+cfg['known_hosts'],'-o','GlobalKnownHostsFile=/dev/null',
          '-o','HostKeyAlgorithms=ssh-ed25519','-o','PasswordAuthentication=no','-o','ConnectTimeout=6',
          '-o','ServerAliveInterval=10','-o','ServerAliveCountMax=2','root@'+cfg['address'],
          action+(' '+nonce if nonce else '')]
        try:r=subprocess.run(args,capture_output=True,text=True,timeout=145 if host in EXTRA_HOSTS and action=='check' else (225 if action=='check' else 130))
        except subprocess.TimeoutExpired:raise RuntimeError('Node request timed out') from None
        if r.returncode:raise RuntimeError('Node RPC failed (exit='+str(r.returncode)+'): '+history_diagnostics.text(r.stderr))
        try:return json.loads(r.stdout)
        except Exception:raise RuntimeError('Invalid node response') from None

def format_relay_checks(checks):
    lines=[]
    dns=checks.get('dns_rewrite',{})
    for transport,label in [('doh','AdGuard DoH'),('dot','AdGuard DoT'),('system','Системный DNS → NL')]:
        items=[v for v in dns.values() if v.get('transport')==transport]
        if items:
            lines.append(label+': '+str(sum(bool(v.get('ok')) for v in items))+'/'+str(len(items)))
            for v in items:
                if not v.get('ok'):
                    detail=', '.join(v.get('addresses',[])) or v.get('error','нет ответа')
                    lines.append('  ⚠️ '+v.get('domain','?')+': '+detail[:120])
    for domain,v in sorted(checks.get('sni_relay',{}).items()):
        lines.append('SNI '+domain+': '+('✅ '+str(v.get('tls',''))+' HTTP '+str(v.get('http_status','?')) if v.get('ok') else '❌ '+str(v.get('error','нет ответа'))))
    if checks.get('sni_relay'):lines.append('SNI: проверка транспорта и сертификата; HTTP 403/429 не доказывает работу аккаунта.')
    return lines

def format_cdn_tls_checks(checks):
    errors={'certificate-expired':'сертификат просрочен','hostname-mismatch':'имя не совпадает с сертификатом','certificate-verification':'цепочка сертификата не прошла проверку','tls-alert-internal-error':'TLS alert internal error','tls-handshake-error':'ошибка TLS-рукопожатия','dns-resolution-error':'ошибка DNS','connection-timeout':'таймаут подключения','probe-timeout':'таймаут DNS/TLS-проверки','connection-refused':'порт отклонил подключение','connection-error':'ошибка соединения','probe-error':'ошибка TLS-проверки'}
    lines=[]
    for key,v in checks.items():
        address=str(v.get('host','?'))+':'+str(v.get('port',443))
        if v.get('ok'):
            detail=str(v.get('tls','TLS'))+'; SNI '+str(v.get('server_name') or '?')+'; ALPN '+str(v.get('alpn') or 'нет')+'; имя и цепочка сертификата ✅; до окончания '+str(v.get('cert_days_remaining','?'))+' дн.'
        else:detail=errors.get(v.get('error'),str(v.get('error','нет ответа')))
        lines.append(('✅ ' if v.get('ok') else '❌ ')+v.get('label',key)+' TLS '+address+' — '+detail)
    if checks:lines.append('Сбой CDN/TLS сам по себе не запускает перезапуск служб.')
    return lines

def format_result(host,result):
    host=host if host in ['spb','carol'] else host.upper()
    if result.get('skipped'):return host+': проверка уже выполняется; повтори запрос позже.'
    if result.get('bridge_error'):return host+': ошибка проверки; требуется журнал.'
    if 'report' in result:
        report=result['report'];services=report.get('services',{});bad=result.get('failures',[])
        lines=[host+(': последний статус' if result.get('saved_result') else ': свежая проверка'), 'Службы: '+', '.join(k+(' ✅' if v else ' ❌') for k,v in services.items())]
        for basic,value in report.get('basics',{}).items():
            extra=(' ('+str(value['free_mb'])+' МБ свободно)') if 'free_mb' in value else (' ('+str(value['cert_days_remaining'])+' дней до окончания TLS)') if 'cert_days_remaining' in value else ''
            lines.append(basic+': '+('✅' if value.get('ok') else '❌')+extra)
        for group,values in report.get('groups',{}).items():
            ok=sum(bool(x.get('ok')) for x in values.values());lines.append(group+': '+str(ok)+'/'+str(len(values)))
        lines.append('⚠️ Не прошли: '+', '.join(bad) if bad else '✅ Все проверяемые маршруты прошли.')
        lines.append('Это проверка без исправлений и перезапусков.')
        if result.get('auto_repair_enabled'):lines.append('Фоновое ограниченное автоисправление включено; reboot не подключён.')
    else:
        age=max(0,int(time.time()-result.get('last_check',time.time()))) if result.get('last_check') else None
        lines=[host+': последний статус','Возраст проверки: '+((str(age//60)+' мин.' if age>=60 else 'менее 1 мин.') if age is not None else 'нет данных'),
          'Службы: '+', '.join(k+(' ✅' if v else ' ❌') for k,v in result.get('services',{}).items()),
          '⚠️ Не прошли: '+', '.join(result.get('failures',[])) if result.get('failures') else '✅ Последние проверки прошли.',
          ('Ограниченное автоисправление включено; reboot не подключён.' if result.get('auto_repair_enabled') else 'Reboot и автоисправления для этого узла не подключены.' if result.get('read_only') else 'Автоперезагрузка: '+('⚠️ включена' if result.get('auto_reboot_enabled') else 'выключена.'))]
    checks=result.get('report',{}).get('relay_checks',{}) if 'report' in result else result.get('relay_checks',{})
    lines.extend(format_relay_checks(checks))
    lines.extend(format_cdn_tls_checks(result.get('report',{}).get('cdn_tls',{}) if 'report' in result else result.get('cdn_tls',{})))
    for label, outcome in result.get('report', {}).get('groups', {}).get('HTTP(S)', {}).items():
        if 'cdn_hint' in outcome: lines.append(label + ': HTTP ' + str(outcome.get('http_status', '?')) + '; CDN ' + outcome['cdn_hint'])
    lines.extend(str(note)[:350] for note in result.get('report', {}).get('notes', [])[:6])
    return '\n'.join(lines)[:3700]

class Bot:
    def __init__(self,api,owner,nodes,statefile,username,executor=None):
        self.api=api;self.owner=owner;self.nodes=nodes;self.statefile=statefile;self.username=username
        self.lock=threading.RLock();self.executor=executor or concurrent.futures.ThreadPoolExecutor(max_workers=2)
        self.reboot_executor=executor or concurrent.futures.ThreadPoolExecutor(max_workers=1)
        try:self.state=json.loads(statefile.read_text())
        except FileNotFoundError:self.state={'pending':{},'offset':None}
        self.state.setdefault('pending',{});self.state.setdefault('check_times',{})
        self.next_cdn_refresh=0;self.cdn_refresh_busy=False
        self.next_maintenance_tick=0;self.maintenance_tick_busy=False
    def save(self):atomic(self.statefile,self.state)
    def send(self,text,keyboard=None):
        data={'chat_id':self.owner,'text':text[:3900]}
        if keyboard:data['reply_markup']=keyboard
        return self.api.call('sendMessage',data,timeout=15)
    def answer(self,qid,text):
        try:self.api.call('answerCallbackQuery',{'callback_query_id':qid,'text':text[:180]},timeout=10)
        except RuntimeError:pass
    def remove_buttons(self,message_id):
        try:self.api.call('editMessageReplyMarkup',{'chat_id':self.owner,'message_id':message_id,'reply_markup':{'inline_keyboard':[]}},timeout=10)
        except RuntimeError:pass
    def cdn_keyboards(self,enabled):
        label=('🟢' if enabled else '🔴')+' CDN NL';style='success' if enabled else 'danger'
        reply=copy.deepcopy(REPLY_KEYBOARD);menu=copy.deepcopy(INLINE_MENU)
        for row in reply['keyboard']:
            for button in row:
                if button.get('text')=='🔌 CDN NL':button.update(text=label,style=style)
        for row in menu['inline_keyboard']:
            for button in row:
                if button.get('callback_data')=='menu:cdn_nl':button.update(text=label,style=style)
        return reply,menu
    def refresh_cdn_ui(self,force=False):
        try:
            r=self.nodes.call('nl','cdn-status');enabled=r['enabled'];reply,menu=self.cdn_keyboards(enabled)
            with self.lock:
                changed=self.state.get('cdn_keyboard_enabled') is not enabled
                if changed or force:
                    self.send(('🟢' if enabled else '🔴')+' CDN NL: '+('включён' if enabled else 'выключен')+'.',reply)
                    mid=self.state.get('cdn_menu_message_id')
                    if mid:
                        try:self.api.call('editMessageReplyMarkup',{'chat_id':self.owner,'message_id':mid,'reply_markup':menu},timeout=10)
                        except RuntimeError:pass
                    self.state['cdn_keyboard_enabled']=enabled;self.save()
        except Exception:
            if force:self.send('⚠️ Не удалось прочитать состояние CDN NL. Используй /cdn_nl. Состояние не изменено.')
        finally:
            with self.lock:self.cdn_refresh_busy=False
    def close_main_menu(self):
        with self.lock:
            mid=self.state.pop('cdn_menu_message_id',None)
            if mid:self.save()
        if mid:self.remove_buttons(mid)
    def show_menu(self):
        self.close_main_menu()
        try:
            enabled=self.nodes.call('nl','cdn-status')['enabled'];reply,menu=self.cdn_keyboards(enabled)
        except Exception:menu=INLINE_MENU
        msg=self.send('🖥 Проверка серверов\nСтатус — последние результаты; Проверить — новая проверка.\nCDN NL: красный — выключен; зелёный — включён. Перезагрузка сервера этими кнопками не запускается.',menu)
        with self.lock:self.state['cdn_menu_message_id']=msg['message_id'];self.save()
        self.refresh_cdn_ui()
    def show_cdn(self):
        try:r=self.nodes.call('nl','cdn-status')
        except Exception:self.send('⚠️ Не удалось получить состояние CDN NL. Ничего не изменено.');return
        enabled=r['enabled'];nonce=secrets.token_hex(16)
        with self.lock:
            self.state['cdn_pending']={'nonce':nonce,'target':not enabled,'expires':time.time()+120,'message_id':None};self.save()
        self.refresh_cdn_ui()
        msg=self.send('🔌 NL: YANDEX CDN '+('ВКЛЮЧЁН' if enabled else 'ВЫКЛЮЧЕН')+'.\nИзменяется только входящий XHTTP/CDN, не UUID и не настройки клиентов.\n⚠️ При применении Xray будет перезапущен; VPN-сессии NL могут кратковременно оборваться. Сервер не перезагружается.\nКнопка действует 2 минуты.',
            {'inline_keyboard':[[{'text':('⛔ Выключить CDN NL' if enabled else '✅ Включить CDN NL'),'callback_data':'cdnset:'+nonce,'style':('danger' if enabled else 'success')},{'text':'Отмена','callback_data':'cdnabort:'+nonce}]]})
        with self.lock:
            if self.state.get('cdn_pending',{}).get('nonce')==nonce:
                self.state['cdn_pending']['message_id']=msg['message_id'];self.save()
    def execute_cdn(self,target):
        try:
            r=self.nodes.call('nl','cdn-enable' if target else 'cdn-disable')
            self.send('✅ NL: YANDEX CDN '+('включён' if r['enabled'] else 'выключен')+'. UUID клиентов сохранены. Сервер не перезагружался.')
        except Exception:
            self.send('⚠️ Не удалось подтвердить переключение CDN NL. Открой «CDN NL», чтобы узнать фактическое состояние; при ошибке применения предусмотрен откат.')
        self.refresh_cdn_ui()
    def cdn_callback(self,q,kind,nonce):
        if not NONCE.fullmatch(nonce):self.answer(q.get('id'),'Недопустимый запрос');return
        with self.lock:
            p=self.state.get('cdn_pending',{})
            if p.get('nonce')!=nonce or p.get('message_id')!=q.get('message',{}).get('message_id'):
                self.answer(q.get('id'),'Кнопка уже использована или устарела');return
            self.state.pop('cdn_pending',None);self.save()
        self.remove_buttons(p.get('message_id'))
        if kind=='cdnabort':self.answer(q.get('id'),'Отменено');return
        if p.get('expires',0)<time.time():self.answer(q.get('id'),'Подтверждение истекло');return
        self.answer(q.get('id'),'Применяю настройку')
        self.reboot_executor.submit(self.execute_cdn,p['target'])
    def run_pings(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(PING_TARGETS)) as pool:
            results=list(pool.map(ping_target,PING_TARGETS))
        for r in results:
            host=next((h for h in HOSTS if advanced.label(h)==r['label']),None)
            if host:advanced.journal(host,r,'ping')
        self.send(format_pings(results))
    def run_checks(self,hosts,fresh):
        for host in hosts:
            try:
                result=self.nodes.call(host,'check' if fresh else 'status')
                if fresh:advanced.journal(host,result,'check')
                if result.get('skipped')=='maintenance':self.send('🛠 '+advanced.label(host)+': обслуживание; автоматические тревоги и исправления временно приостановлены.')
                else:self.send(format_result(host,result))
            except Exception:self.send('⚠️ '+host+': не удалось выполнить запрос. Это не подтверждает остановку сервера; проверь доступность и журнал.')
    def run_ai_all(self):
        try:ai_diagnostics.load_config()
        except Exception as exc:self.send('⚠️ '+str(exc));return
        self.send('🧠 Получаю свежие проверки всех серверов и состояние домашнего роутера для ИИ-анализа. Исправления не запускаются.')
        checks={}
        for host in AI_HOSTS:
            try:
                result=self.nodes.call(host,'check')
                advanced.journal(host,result,'check')
                checks[advanced.label(host)]=result
            except Exception as exc:
                checks[advanced.label(host)]={'error':'Проверка не получена: '+type(exc).__name__}
        router={}
        try:router=home_monitor.read(STATE/'router-state.json')
        except Exception:router={'error':'Состояние роутера недоступно'}
        logs=[]
        for service in ('rvkomi-telegram-control','rvkomi-extra-monitor','rvkomi-certificates','rvkomi-router-receiver'):
            try:
                proc=subprocess.run(['/usr/bin/journalctl','--no-pager','--since','2 hours ago','-n','60','-u',service+'.service'],capture_output=True,text=True,timeout=8)
                logs.append('### '+service+'\n'+(proc.stdout if proc.returncode==0 else 'Журнал службы недоступен.'))
            except Exception:logs.append('### '+service+'\nЖурнал службы недоступен.')
        history=[row for row in advanced.history() if row.get('h') in AI_HOSTS][-160:]
        try:answer=ai_diagnostics.analyze(checks,history,router,'\n'.join(logs))
        except Exception as exc:answer='⚠️ '+str(exc)
        self.send('🧠 ИИ-анализ всех узлов\n\n'+answer+'\n\nЭтот анализ ничего не меняет. /ai_change — отдельный точный план разрешённого изменения с объяснением и подтверждением владельца.')
    def request_reboot(self,host):
        with self.lock:
            generation=self.state.get('cancel_generation',0)
            now=time.time()
            if now-self.state.get('last_reboot_request',0)<600:
                self.send('Перезагрузка пока заблокирована: между подтверждёнными reboot должно пройти 10 минут.');return
            if any(p.get('expires',0)>now for p in self.state['pending'].values()):
                self.send('Уже есть запрос подтверждения. Подтверди его или отправь /cancel.');return
        nonce=secrets.token_hex(16)
        try:prepared=self.nodes.call(host,'prepare',nonce)
        except Exception:self.send('⚠️ '+host+': не удалось подготовить запрос. Reboot не выполнялся.');return
        if not prepared.get('prepared'):self.send('⚠️ '+host+': запрос не подготовлен; сервер занят.');return
        with self.lock:
            if self.state.get('cancel_generation',0)!=generation:
                try:self.nodes.call(host,'cancel',nonce)
                except Exception:pass
                return
            self.state['pending']={nonce:{'host':host,'expires':time.time()+120,'message_id':None}}
            self.save()
        msg=self.send('⚠️ Перезагрузить '+host+'? VPN-сессии через него оборвутся.\nПодтверждение действует 2 минуты. Работоспособность второго сервера будет проверена перед reboot.',
          {'inline_keyboard':[[{'text':'Подтвердить reboot '+host,'callback_data':'confirm:'+nonce},{'text':'Отмена','callback_data':'cancel:'+nonce}]]})
        with self.lock:
            if nonce in self.state['pending']:self.state['pending'][nonce]['message_id']=msg['message_id'];self.save()
    def cancel(self):
        with self.lock:
            pending=self.state.pop('ai_admin_pending',{})
            self.state.pop('ai_admin_waiting',None);self.save()
        if pending.get('message_id'):self.remove_buttons(pending['message_id'])
        with self.lock:self.state.pop('cdn_pending',None);self.state.pop('backup_pending',None);items=list(self.state['pending'].items());self.state['pending']={};self.state['cancel_generation']=self.state.get('cancel_generation',0)+1;self.save()
        for nonce,p in items:
            self.remove_buttons(p.get('message_id'))
            try:self.nodes.call(p['host'],'cancel',nonce)
            except Exception:pass
        self.send('Неподтверждённые запросы отменены. Уже подтверждённый reboot не отменяется этой командой.')
    def execute_reboot(self,host,nonce):
        try:
            result=self.nodes.call(host,'confirm',nonce)
            if result.get('accepted'):self.send('🔄 '+host+': ручная перезагрузка принята. Уведомление после загрузки придёт от мониторинга.')
            else:self.send('⚠️ '+host+': reboot НЕ выполнен. Причина: '+str(result.get('reason','unknown'))+'.')
        except Exception:
            self.send('⚠️ '+host+': результат команды не подтверждён. НЕ повторяй reboot сразу: связь могла оборваться из-за начавшейся перезагрузки. Проверь /status после восстановления связи.')
    def callback(self,q):
        if not authorized_callback(q,self.owner):return
        data=q.get('data','');kind,sep,nonce=data.partition(':')
        if sep and kind in ('aiconfirm','aiabort'):
            ai_admin.callback(self,q,kind,nonce);return
        if sep and kind in ['maintnode','maintset']:
            advanced.maintenance_callback(self,q,kind,nonce);return
        if sep and kind in ['backupconfirm','backupcancel']:
            advanced.backup_callback(self,q,kind,nonce);return
        if kind=='menu' and sep:
            if nonce=='close':
                self.answer(q.get('id'),'Меню закрыто')
                self.close_main_menu()
                self.remove_buttons(q.get('message',{}).get('message_id'));return
            if nonce not in MENU_COMMANDS:
                self.answer(q.get('id'),'Недопустимая команда');return
            self.answer(q.get('id'),'Принято')
            self.handle_command(nonce,time.time());return
        if sep and kind in ['cdnset','cdnabort']:
            self.cdn_callback(q,kind,nonce);return
        if not sep or kind not in ['confirm','cancel'] or not NONCE.fullmatch(nonce):self.answer(q.get('id'),'Недопустимый запрос');return
        with self.lock:
            p=self.state['pending'].get(nonce)
            if not p or p.get('message_id')!=q.get('message',{}).get('message_id'):
                self.answer(q.get('id'),'Запрос уже использован или неизвестен');return
            if p['expires']<time.time():
                self.state['pending'].pop(nonce,None);self.save();self.answer(q.get('id'),'Подтверждение истекло');return
            if kind=='confirm' and time.time()-self.state.get('last_reboot_request',0)<600:
                self.answer(q.get('id'),'Действует интервал 10 минут');return
            self.state['pending'].pop(nonce,None)
            if kind=='confirm':self.state['last_reboot_request']=time.time();self.state['last_reboot_host']=p['host']
            self.save()
        self.remove_buttons(p['message_id'])
        if kind=='cancel':
            self.answer(q.get('id'),'Отменено')
            self.reboot_executor.submit(self.nodes.call,p['host'],'cancel',nonce)
        else:
            self.answer(q.get('id'),'Подтверждение принято')
            self.reboot_executor.submit(self.execute_reboot,p['host'],nonce)
    def dispatch(self,update):
        if 'callback_query' in update:self.callback(update['callback_query']);return
        m=update.get('message',{})
        if not authorized_message(m,self.owner):return
        text=m.get('text','').strip()
        if ai_admin.consume(self,m):return
        if text in BUTTON_COMMANDS:
            self.handle_command(BUTTON_COMMANDS[text],m.get('date',0));return
        words=text.split()
        if not words or not words[0].startswith('/'):return
        cmd,_,address=words[0][1:].partition('@')
        if address and address.lower()!=self.username.lower():return
        if len(words)!=1:self.send('Команда не принимает аргументы. Используй меню или /help.');return
        self.handle_command(cmd,m.get('date',0))
    def handle_command(self,cmd,message_date):
        if cmd not in ('menu','start'):self.close_main_menu()
        if cmd=='start':
            self.refresh_cdn_ui(force=True)
            self.show_menu();return
        if cmd=='menu':self.show_menu();return
        if cmd=='help':self.send(HELP);return
        if cmd=='cdn_nl':
            if time.time()-message_date>180:self.send('Старый запрос отклонён. Открой свежую кнопку CDN NL.');return
            self.reboot_executor.submit(self.show_cdn);return
        if cmd=='ping':
            with self.lock:
                now=time.time()
                if now-self.state['check_times'].get('_ping',0)<30:
                    self.send('PING недавно запрошен. Подожди 30 секунд.');return
                self.state['check_times']['_ping']=now;self.save()
            self.send('📡 Выполняю по 4 ping к 9 целям (8 серверов и роутер) с TELEGRAM.');self.executor.submit(self.run_pings);return
        if cmd=='dns_sni_check':
            if time.time()-message_date>180:self.send('Запрос устарел; открой меню снова.');return
            with self.lock:
                if time.time()-self.state['check_times'].get('_dns_sni',0)<60:self.send('Проверка недавно запрошена; подожди минуту.');return
                self.state['check_times']['_dns_sni']=time.time();self.save()
            self.send('🌐 Проверяю DNS/DoH/DoT и DNS-перезаписи, затем TLS через SNI-relay FIN. Без изменения настроек.');self.executor.submit(self.run_checks,['dns','fin'],True);return
        if cmd=='ai_change':
            if time.time()-message_date>180:self.send('Запрос устарел; открой /ai_change снова.');return
            ai_admin.begin(self);return
        if cmd=='ai_all':
            with self.lock:
                now=time.time()
                if now-self.state['check_times'].get('_ai_all',0)<300:
                    self.send('ИИ-анализ недавно запускался. Подожди 5 минут.');return
                self.state['check_times']['_ai_all']=now;self.save()
            self.executor.submit(self.run_ai_all);return
        if cmd=='cancel':self.cancel();return
        if cmd in dict(home_monitor.COMMANDS):
            if time.time()-message_date>180:self.send('Старый запрос отклонён. Открой свежее меню.');return
            self.executor.submit(home_monitor.handle,self,cmd);return
        if cmd=='status':self.executor.submit(advanced.summary,self);return
        if cmd in dict(advanced.COMMANDS):
            if time.time()-message_date>180:self.send('Старое меню отклонено. Открой /menu заново.');return
            self.executor.submit(advanced.handle,self,cmd);return
        if cmd=='check_all' or cmd in ['check_'+h for h in HOSTS]:
            hosts=HOSTS if cmd=='check_all' else [cmd.split('_',1)[1]]
            with self.lock:
                now=time.time()
                if any(now-self.state['check_times'].get(h,0)<30 for h in hosts):self.send('Проверка недавно запрошена. Подожди 30 секунд.');return
                for h in hosts:self.state['check_times'][h]=now
                self.save()
            self.send('🔎 Начинаю проверку '+', '.join(hosts)+'. Это может занять до нескольких минут.');self.executor.submit(self.run_checks,hosts,True);return
        if cmd in ['reboot_spb','reboot_nl']:
            if time.time()-message_date>180:self.send('Старый запрос reboot отклонён. Отправь свежую команду.');return
            self.reboot_executor.submit(self.request_reboot,cmd.split('_',1)[1]);return
        self.send('Неизвестная команда. Используй /help.')
    def run_maintenance_tick(self):
        try:advanced.maintenance_tick(self)
        finally:
            with self.lock:self.maintenance_tick_busy=False
    def poll(self):
        if self.state.get('offset') is None:
            updates=self.api.call('getUpdates',{'timeout':0,'allowed_updates':['message','callback_query']})
            self.state['offset']=max((u['update_id']+1 for u in updates),default=0);self.save()
        while True:
            with self.lock:
                if time.time()>=self.next_maintenance_tick and not self.maintenance_tick_busy:
                    self.next_maintenance_tick=time.time()+60;self.maintenance_tick_busy=True
                    self.executor.submit(self.run_maintenance_tick)
                if time.time()>=self.next_cdn_refresh and not self.cdn_refresh_busy:
                    self.next_cdn_refresh=time.time()+60;self.cdn_refresh_busy=True
                    self.executor.submit(self.refresh_cdn_ui)
            try:updates=self.api.call('getUpdates',{'offset':self.state['offset'],'timeout':25,'allowed_updates':['message','callback_query']},timeout=35)
            except RuntimeError:
                print(json.dumps({'event':'telegram-poll-retry'}),flush=True);time.sleep(10);continue
            for u in updates:
                with self.lock:self.state['offset']=max(self.state['offset'],u['update_id']+1);self.save()
                try:self.dispatch(u)
                except Exception:print(json.dumps({'event':'dispatch-error'}),flush=True)

def main():
    p=argparse.ArgumentParser();p.add_argument('mode',choices=['register','poll','announce','verify']);a=p.parse_args()
    import fleet,generic_control,sys
    if fleet.enabled():return generic_control.run(sys.modules[__name__],a.mode)
    credentials=json.loads((ROOT/'telegram.json').read_text());owner=int(credentials['chat_id'])
    if owner<=0:raise ValueError('Private chat enrollment required')
    api=API(credentials);me=api.call('getMe')
    if api.call('getWebhookInfo').get('url'):raise RuntimeError('Existing webhook; control service not started')
    if a.mode=='register':
        api.call('setMyCommands',{'commands':[{'command':c,'description':d} for c,d in COMMANDS],'scope':{'type':'chat','chat_id':owner}})
        commands=api.call('getMyCommands',{'scope':{'type':'chat','chat_id':owner}})
        print(json.dumps({'registered_commands':[c['command'] for c in commands]}));return
    if a.mode=='verify':
        nodes=Nodes();results={}
        for host in HOSTS:
            r=nodes.call(host,'check');results[host]={'failures':r.get('failures'),'skipped':r.get('skipped')}
            api.call('sendMessage',{'chat_id':owner,'text':'Тест команды проверки (без reboot):\n'+format_result(host,r)})
        print(json.dumps({'read_only_checks':results}));return
    if a.mode=='announce':api.call('sendMessage',{'chat_id':owner,'text':'✅ Автоперезагрузки SPB и NL отключены. Ручное управление готово.\n\n'+HELP});print(json.dumps({'announcement_delivered':True}));return
    STATE.mkdir(mode=0o700,parents=True,exist_ok=True)
    with (STATE/'telegram-control.lock').open('a+') as f:
        try:fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:print(json.dumps({'already_running':True}));return
        Bot(api,owner,Nodes(),STATE/'telegram-control-state.json',me['username']).poll()

if __name__=='__main__':
    try:main()
    except Exception as exc:print(json.dumps({'control_error':type(exc).__name__}),flush=True);raise SystemExit(1)
