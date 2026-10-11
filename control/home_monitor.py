#!/usr/bin/python3
import concurrent.futures,json,os,secrets,time,threading,socket,ssl,urllib.request,urllib.error,struct,random,urllib.parse
from pathlib import Path
import advanced
STATE=Path('/var/lib/rvkomi-watchdog');LOCK=threading.Lock()
COMMANDS=[('home_check','Проверка серверов из домашнего интернета'),('router','Роутер, диск, WebDAV и резервные копии')]
BUTTONS={'🏠 Проверка из дома':'home_check','📡 Роутер':'router'}
REPLY_ROWS=[[{'text':'🏠 Проверка из дома'},{'text':'📡 Роутер'}]]
INLINE_ROWS=[[{'text':'🏠 Проверка из дома','callback_data':'menu:home_check'},{'text':'📡 Роутер','callback_data':'menu:router'}]]
def read(p):
 try:return json.loads(p.read_text())
 except (OSError,ValueError):return {}
def atomic(p,d):
 t=p.with_suffix('.tmp');t.write_text(json.dumps(d,ensure_ascii=False));t.chmod(0o600);os.replace(t,p)
def age(t):return str(max(0,int((time.time()-t)/60)))+' мин' if t else 'нет данных'
def webdav_status():
 try:
  with advanced.dav_req('PROPFIND',advanced.webdav()['url'],headers={'Depth':'0'}) as f:
   f.read(65536);return f.status in (200,207)
 except Exception:return False
def router_text(d,dav):
 now=time.time();r=d.get('resources',{});lines=['📡 Домашний роутер','Агент: '+('✅ на связи' if now-d.get('last_heartbeat',0)<1000 else '❌ нет связи более 16 минут'),'Возраст ресурсов: '+age(d.get('resources_time',0))]
 if r:
  sec=int(r.get('uptime_s',0));lines+=['Время работы: '+str(sec//86400)+' д '+str(sec%86400//3600)+' ч '+str(sec%3600//60)+' мин','CPU: '+str(r.get('cpu_percent','?'))+'%','RAM: свободно/доступно '+str(round(r.get('memory_available_kb',0)/1024))+' из '+str(round(r.get('memory_total_kb',0)/1024))+' МБ','Swap занят: '+str(round(r.get('swap_used_kb',0)/1024))+' МБ']
  for disk in r.get('disks',[]):lines.append('Диск '+str(disk.get('name',''))[:70]+': '+str(disk.get('free_mb','?'))+' МБ свободно ('+str(disk.get('free_percent','?'))+'%)')
  lines.append('Диск ADATA: '+('✅ подключён' if r.get('backup_disk_present') else '❌ не обнаружен'))
 lines.append('WebDAV с TELEGRAM: '+('✅ доступен' if dav else '❌ недоступен'))
 b=read(STATE/'backup-state.json');hosts=b.get('hosts',{})
 successes=[v for v in hosts.values() if v.get('ok') or v.get('verified') or v.get('status')=='ok']
 if b.get('finished'):lines.append('Последнее копирование: '+age(b['finished'])+' назад; проверено '+str(len(successes))+' из '+str(len(hosts))+' серверов; /backup_status')
 else:lines.append('Копирование: подробности /backup_status')
 lines+=['Ресурсы каждый час; связь контролируется каждые 5 минут.','Автоперезагрузок и изменений VPN нет.']
 return '\n'.join(lines)
def router(bot):bot.send(router_text(read(STATE/'router-state.json'),webdav_status()))
def home_check(bot):
 if not LOCK.acquire(blocking=False):bot.send('Домашняя проверка уже выполняется.');return
 try:
  old=read(STATE/'router-task.json')
  if time.time()-old.get('requested',0)<600:bot.send('Проверка недавно запрошена. Подожди десять минут.');return
  tid=secrets.token_hex(16);atomic(STATE/'router-task.json',{'id':tid,'requested':time.time()});bot.send('🏠 Запрашиваю проверку с роутера. Ожидание очередного обращения агента и проверки может занять до 6 минут. VPN-настройки не меняются.')
  deadline=time.monotonic()+370;d={}
  while time.monotonic()<deadline:
   d=read(STATE/'router-state.json')
   if d.get('task_id')==tid:break
   time.sleep(2)
  fresh=d.get('task_id')==tid
  if not fresh:bot.send('⚠️ Агент не прислал свежую проверку вовремя. Последние данные: '+age(d.get('checks_time',0))+'. /router покажет состояние связи.');return
  with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
   baseline=dict(zip(TARGETS,ex.map(lambda kv:check(*kv),TARGETS.items())))
  atomic(STATE/'router-baseline.json',{'checked':time.time(),'checks':baseline})
  lines=['🏠 Серверы из домашнего интернета','Домашние результаты: '+age(d.get('checks_time',0))+' назад','Сравнение: домашний маршрут роутера ↔ TELEGRAM','']
  for k in TARGETS:
   a=d.get('checks',{}).get(k,{});b=baseline.get(k,{})
   label='✅ обе точки' if a.get('ok') and b.get('ok') else '⚠️ только TELEGRAM' if b.get('ok') else '⚠️ только дом' if a.get('ok') else '❌ обе точки'
   lines.append(k+': '+label+'; дом '+str(a.get('total_ms','—'))+' мс; TELEGRAM '+str(b.get('total_ms','—'))+' мс')
   if not a.get('ok'):lines.append('  Дом: '+str(a.get('error') or 'DNS/HTTP-проверка не прошла'))
  q=d.get('checks',{}).get('SYSTEM DNS',{});lines.append('Системный DNS роутера: '+('✅' if q.get('ok') else '❌'))
  y=d.get('yandex',{})
  lines.append('Yandex CDN: '+('отключён на NL — не проверяется' if not d.get('yandex_enabled') else (('✅' if y.get('ok') else '⚠️')+' последний результат '+age(y.get('checked',0))) if y else 'ожидает плановой проверки в 08:00 МСК'))
  lines+=['','Время — полный DNS/HTTPS-запрос, не ping. TLS проверяется по имени и цепочке сертификата.','Это проверка доступности HTTPS/DoH, НЕ авторизация VLESS и НЕ гарантия отсутствия блокировки VPN.','Используется действующий маршрут самого роутера; настройки политик и VPN не менялись.']
  bot.send('\n'.join(lines))
 finally:LOCK.release()
def handle(bot,cmd):
 if cmd=='router':router(bot)
 elif cmd=='home_check':home_check(bot)
def tick(bot):
 try:enabled=bot.nodes.call('nl','cdn-status')['enabled'];atomic(STATE/'router-settings.json',{'yandex_enabled':enabled})
 except Exception:pass
 d=read(STATE/'router-state.json');previous=read(STATE/'router-alert-state.json');faults=[];now=time.time();r=d.get('resources',{})
 if now-d.get('last_heartbeat',0)>1000:faults.append('агент не на связи')
 if d and now-d.get('resources_time',0)>10800:faults.append('ресурсы не обновляются')
 if r and not r.get('backup_disk_present'):faults.append('диск ADATA не обнаружен')
 for disk in r.get('disks',[]):
  if disk.get('free_percent',100)<10:faults.append('мало места: '+str(disk.get('name')))
 if d.get('resources_time')!=previous.get('sample_time'):
  previous['cpu_samples']=previous.get('cpu_samples',0)+1 if r.get('cpu_percent',0)>90 else 0
  previous['ram_samples']=previous.get('ram_samples',0)+1 if r.get('memory_available_kb',1000000)<32768 else 0
  previous['sample_time']=d.get('resources_time')
 if previous.get('cpu_samples',0)>=3:faults.append('CPU выше 90% в трёх замерах')
 if previous.get('ram_samples',0)>=3:faults.append('доступной RAM меньше 32 МБ в трёх замерах')
 # The shared WebDAV endpoint is checked every 5 minutes, not every heartbeat.
 if now-previous.get('dav_checked',0)>300:
  previous['dav_ok']=webdav_status();previous['dav_checked']=now
 if not previous.get('dav_ok',True):faults.append('WebDAV недоступен')
 old=previous.get('faults',[]);same=faults==old;count=previous.get('count',0)+1 if same else 1
 if faults and count>=3 and faults!=previous.get('announced',[]):bot.send('⚠️ Роутер: '+', '.join(faults)+'. Наблюдение без автоматических исправлений.');previous['announced']=faults
 elif not faults and previous.get('announced'):bot.send('✅ Роутер: связь, ресурсы и WebDAV восстановились.');previous['announced']=[]
 uptime=r.get('uptime_s');old_u=previous.get('uptime_s')
 if uptime is not None and old_u is not None and uptime+60<old_u:bot.send('🔄 Роутер перезагрузился: время работы '+str(uptime//60)+' мин.')
 if uptime is not None:previous['uptime_s']=uptime
 previous.update(faults=faults,count=count);atomic(STATE/'router-alert-state.json',previous)
 if d.get('checks_time') and d['checks_time']!=previous.get('home_seen'):
  bad=sorted(k for k,v in d.get('checks',{}).items() if not v.get('ok'))
  oldbad=previous.get('home_bad',[])
  if bad and bad!=oldbad:bot.send('⚠️ Домашние DNS/HTTPS-проверки: '+', '.join(bad)+'. Сравнение доступно по кнопке «Проверка из дома». Это не доказательство блокировки VPN.')
  elif not bad and oldbad:bot.send('✅ Домашние DNS/HTTPS-проверки восстановились.')
  previous.update(home_seen=d['checks_time'],home_bad=bad);atomic(STATE/'router-alert-state.json',previous)

CTX=ssl.create_default_context()
TARGETS={'SPB':'https://spb.vikrk.online/','NL':'https://my393.rvkomi.space/','DNS':'https://rvkomi.ru/dns-query','WWW':'https://www.davpon.online/','SPACE':'https://rvkomi.space/','LATVIA':'https://vikrk.online/','FIN':'https://davpon.online/','TELEGRAM':'https://rvkomi.online/','CDN SPB':'https://edge.vikrk.online/health','DNS CDN':'https://doh.rvkomi.ru/dns-query'}
OPENER=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=CTX))
def dns_packet(name):
 i=random.randrange(65536);q=b''.join(bytes([len(x)])+x.encode() for x in name.split('.'))+b'\0'+struct.pack('!HH',1,1)
 return i,struct.pack('!HHHHHH',i,0x0100,1,0,0,0)+q
def check(label,url):
 st=time.monotonic();host=urllib.parse.urlparse(url).hostname
 r={'host':host,'ok':False}
 try:
  r['addresses']=sorted({x[4][0] for x in socket.getaddrinfo(host,443,socket.AF_INET)})
  if '/dns-query' in url:
   i,p=dns_packet('www.cloudflare.com');req=urllib.request.Request(url,data=p,headers={'Content-Type':'application/dns-message','Accept':'application/dns-message'})
   with OPENER.open(req,timeout=10) as f:
    b=f.read(4096);r['http']=f.status;r['rcode']=struct.unpack('!H',b[2:4])[0]&15;r['answers']=struct.unpack('!H',b[6:8])[0];r['ok']=r['http']==200 and r['rcode']==0 and r['answers']>0
  else:
   with OPENER.open(urllib.request.Request(url,headers={'User-Agent':'RVK-HomeMonitor/1.0'}),timeout=10) as f:
    r['http']=f.status;f.read(1024);r['ok']=200<=f.status<400
  r['tls_verified']=True
 except urllib.error.HTTPError as e:r.update(http=e.code,tls_verified=True,error='HTTP '+str(e.code))
 except Exception as e:r['error']=type(e).__name__
 r['total_ms']=round((time.monotonic()-st)*1000,1);return r

