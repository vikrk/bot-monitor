#!/usr/bin/python3
"""Owner-only operational UI, bounded history, encrypted WebDAV backups."""
import re,urllib.parse,xml.etree.ElementTree as ET,base64,concurrent.futures,copy,datetime,fcntl,hashlib,hmac,importlib.util,json,os,secrets,shutil,sqlite3,subprocess,tarfile,tempfile,time,urllib.request,urllib.error
from pathlib import Path
BASE=Path('/usr/local/lib/rvkomi-watchdog');ROOT=Path('/etc/rvkomi-watchdog');STATE=Path('/var/lib/rvkomi-watchdog')
HOSTS=['spb','nl','dns','www','space','latvia','fin','telegramm'];ALL=HOSTS;LABEL={'telegramm':'TELEGRAM'}
import fleet
if fleet.enabled():
 HOSTS=list(fleet.nodes());ALL=HOSTS;LABEL={h:n['name'] for h,n in fleet.nodes().items()}
ACTIONS={'extras','certs','backup-export','maint-15','maint-30','maint-60','maint-off'}
COMMANDS=[('summary','Общая сводка одним сообщением'),('backup','Создать зашифрованные копии на роутере'),('backup_status','Статус копий и теста восстановления'),('maintenance','Обслуживание: 15/30/60 минут'),('history','История проверок за сутки'),('certificates','Сроки сертификатов'),('resources','RAM, диск и запас Nginx')]
BUTTONS={'🖥 Сводка':'summary','💾 Создать копии':'backup','📦 Статус копий':'backup_status','🛠 Обслуживание':'maintenance','📈 История':'history','🔐 Сертификаты':'certificates','⚙️ Ресурсы':'resources'}
INLINE_ROWS=[[{'text':'🖥 Общая сводка','callback_data':'menu:summary'}],[{'text':'💾 Создать копии','callback_data':'menu:backup'},{'text':'📦 Статус копий','callback_data':'menu:backup_status'}],[{'text':'🛠 Обслуживание','callback_data':'menu:maintenance'},{'text':'📈 История','callback_data':'menu:history'}],[{'text':'🔐 Сертификаты','callback_data':'menu:certificates'},{'text':'⚙️ Ресурсы','callback_data':'menu:resources'}]]
REPLY_ROWS=[[{'text':'🖥 Сводка'},{'text':'📈 История'}],[{'text':'💾 Создать копии'},{'text':'📦 Статус копий'}],[{'text':'🛠 Обслуживание'},{'text':'🔐 Сертификаты'}],[{'text':'⚙️ Ресурсы'}]]
def read(p,default=None):
 try:return json.loads(p.read_text())
 except (FileNotFoundError,ValueError):return {} if default is None else default
def atomic(p,d):
 p.parent.mkdir(mode=0o700,parents=True,exist_ok=True);q=p.with_name('.'+p.name+'.tmp');q.write_text(json.dumps(d,ensure_ascii=False));q.chmod(0o600);q.replace(p)
def label(h):return LABEL.get(h,h.upper())
def load_tc():
 s=importlib.util.spec_from_file_location('tc',BASE/'telegram-control.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def ssh_job(host,action):
 if host not in ALL or action not in ACTIONS:raise ValueError('Restricted action')
 cfg=read(ROOT/('control-nodes.json' if host in ['spb','nl'] else 'extra-nodes.json'))[host]
 args=['ssh','-4','-T','-F','/dev/null','-p',str(cfg['port']),'-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+cfg['known_hosts'],'-o','GlobalKnownHostsFile=/dev/null','-o','HostKeyAlgorithms=ssh-ed25519','-o','ConnectTimeout=7','-o','ServerAliveInterval=10','-o','ServerAliveCountMax=2','-i',cfg['key'],'-o','IdentitiesOnly=yes','-o','BatchMode=yes','-o','PasswordAuthentication=no','root@'+cfg['address'],action]
 return args,os.environ.copy()
def rpc(host,action):
 if fleet.enabled():return fleet.rpc(host,action)
 args,env=ssh_job(host,action);r=subprocess.run(args,env=env,stdin=subprocess.DEVNULL,capture_output=True,text=True,start_new_session=True,timeout=55)
 if r.returncode:raise RuntimeError('Node RPC failed')
 d=json.loads(r.stdout)
 if 'error' in d:raise RuntimeError('Node operation failed')
 return d
def journal(host,result,source='check'):
 STATE.mkdir(mode=0o700,parents=True,exist_ok=True)
 report=result.get('report',{});services=report.get('services',result.get('services',{}));bad=result.get('failures',[])
 sample={'t':time.time(),'h':host,'source':source,'last_check':result.get('last_check'),'failures':bad,'services':services,'skipped':result.get('skipped')}
 for key in ('error','error_type','connection_error'):
  if result.get(key):sample[key]=str(result[key])[:1000]
 if report:sample['report']=report
 if source=='ping':sample.update({k:result.get(k) for k in ['sent','received','average_ms','error']})
 if source=='resources':sample['metrics']=result
 with (STATE/'history.lock').open('a+') as f:
  fcntl.flock(f,fcntl.LOCK_EX);p=STATE/'history.jsonl';cut=time.time()-72*3600
  rows=[]
  if p.exists():
   for line in p.read_text().splitlines():
    try:d=json.loads(line)
    except ValueError:continue
    if d.get('t',0)>=cut:rows.append(d)
  rows.append(sample);q=p.with_name('.history.jsonl.tmp');q.write_text(''.join(json.dumps(x,ensure_ascii=False)+'\n' for x in rows[-30000:]));q.chmod(0o600);q.replace(p)
def history():
 p=STATE/'history.jsonl';rows=[]
 if p.exists():
  for line in p.read_text().splitlines():
   try:rows.append(json.loads(line))
   except ValueError:pass
 return rows
def collect(action,hosts=ALL):
 def one(h):
  try:return h,rpc(h,action)
  except Exception:return h,{'error':'нет ответа служебной проверки'}
 with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:return dict(pool.map(one,hosts))
def latest_completed_status(host,state,rows):
 # Do not conceal a failed status RPC with a past successful measurement.
 if not isinstance(state.get('last_check'),(int,float)):return state
 best=dict(state);stamp=state['last_check']
 for row in rows:
  if row.get('h')!=host or row.get('source') not in ('check','scheduled'):continue
  if row.get('skipped') or row.get('error'):continue
  if not isinstance(row.get('failures'),list) or not row.get('services'):continue
  measured=row.get('last_check') or row.get('t')
  if not isinstance(measured,(int,float)) or measured<=stamp or measured>time.time()+60:continue
  stamp=measured;best.update(last_check=measured,failures=row['failures'],services=row['services'])
 return best
def summary(bot):
 metrics=collect('extras')
 def status(h):
  try:return h,bot.nodes.call(h,'status')
  except Exception:return h,{'failures':['связь с проверочным сервисом недоступна']}
 with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:states=dict(pool.map(status,HOSTS))
 measured_rows=history()
 lines=['🖥 Общая сводка серверов','Последний результат маршрутов; ресурсы измерены сейчас.','']
 for h in ALL:
  m=metrics[h]
  if m.get('error'):lines.append('⚠️ '+label(h)+': '+m['error']);continue
  journal(h,m,'resources');r=states.get(h,{'services':m['services'],'failures':[s for s,v in m['services'].items() if not v]})
  r=latest_completed_status(h,r,measured_rows)
  bad=r.get('failures',[]);until=read(STATE/'maintenance-central.json').get(h,{}).get('until',0)
  stamp=r.get('last_check');age='проверок ещё нет' if not stamp else str(max(0,int((time.time()-stamp)//60)))+' мин.'
  badge='🛠' if until>time.time() else '⚠️' if bad or (stamp and time.time()-stamp>4*3600) else '✅'
  svc=sum(bool(v) for v in m['services'].values());total=len(m['services'])
  lines.append(f"{badge} {label(h)}: службы {svc}/{total}; диск {m['disk_free_gb']:.1f} ГБ; RAM {m['memory_available_mb']} МБ; {age}")
  if bad:lines.append('  '+', '.join(bad)[:170])
  if until>time.time():lines.append('  обслуживание ещё '+str(int((until-time.time()+59)//60))+' мин.')
 try:lines.append('\n'+('🟢' if bot.nodes.call('nl','cdn-status')['enabled'] else '🔴')+' YANDEX CDN NL')
 except Exception:lines.append('\n⚠️ CDN NL: состояние неизвестно')
 bot.send('\n'.join(lines))
def resources(bot):
 data=collect('extras');lines=['⚙️ Ресурсы серверов (без изменения настроек)']
 for h in ALL:
  m=data[h]
  if m.get('error'):lines.append(label(h)+': '+m['error']);continue
  journal(h,m,'resources');lines.append(f"\n{label(h)}: CPU {m['load'][0]:.2f}/{m['cpu_count']} ядер; RAM свободно {m['memory_available_mb']}/{m['memory_total_mb']} МБ; диск {m['disk_free_gb']:.1f} ГБ ({m['disk_used_percent']}% занято); swap {m['swap_used_mb']} МБ")
  n=m.get('nginx',{})
  if n:lines.append('Nginx: connections='+str(n.get('worker_connections'))+'; лимит файлов='+str(n.get('file_limit'))+'; FD работников='+','.join(str(x['open_fds']) for x in n.get('workers',[])))
  if m['memory_available_mb']<100 or m['disk_free_gb']<1 or m['load'][0]>m['cpu_count']*1.5:lines.append('⚠️ Требует внимания: запас ресурсов небольшой.')
 bot.send('\n'.join(lines))
def show_history(bot):
 rows=[r for r in history() if r['t']>time.time()-86400];lines=['📈 История за 24 часа','Доля успешных проверок, не точный uptime. Частота маршрутов — раз в 2 часа.']
 for h in ALL:
  rs=[r for r in rows if r['h']==h and r['source'] in ['check','scheduled'] and not r.get('skipped')]
  # Do not count repeat reads of the same cached SPB/NL result as new measurements.
  seen=set();unique=[]
  for r in rs:
   key=r.get('last_check') or r['t']
   if key not in seen:seen.add(key);unique.append(r)
  rs=unique;bad=sum(bool(r['failures']) for r in rs)
  text=label(h)+': '+(f'{len(rs)-bad}/{len(rs)} успешно; неудачных {bad}' if rs else 'история проверок пока не накоплена')
  ps=[r for r in rows if r['h']==h and r['source']=='ping']
  if ps:
   p=ps[-1];a=p.get('average_ms');text+='; ping '+(f'{a:.2f} мс' if a is not None else 'нет ответа')
   if p.get('sent'):text+='; потеряно '+str(p['sent']-p.get('received',0))+'/'+str(p['sent'])
  lines.append(text)
 lines.append('\nИстория хранится 30 дней. Пропуск ICMP сам по себе не означает отказ VPN.')
 bot.send('\n'.join(lines))
def certs(bot):
 data=collect('certs');lines=['🔐 Сертификаты серверов','Локальные сертификаты — актуальные файлы; CDN — последний сохранённый результат TLS.']
 for h in ALL:
  d=data[h]
  if d.get('error'):lines.append('⚠️ '+label(h)+': '+d['error']);continue
  if not d.get('certificates'):lines.append(label(h)+': локальные сертификаты не обнаружены')
  for c in d.get('certificates',[]):
   stamp=c.get('checked_at');extra=('; TLS-кэш от '+datetime.datetime.fromtimestamp(stamp,datetime.timezone(datetime.timedelta(hours=3))).strftime('%d.%m %H:%M МСК')) if c.get('cached') and stamp else ''
   lines.append(('⚠️' if c['days']<=30 else '✅')+' '+label(h)+' '+c['subject'].replace('subject=','')+f": {c['days']:.1f} дней"+extra)
 bot.send('\n'.join(lines))
def maintenance_menu(bot):
 rows=[[{'text':label(h),'callback_data':'maintnode:'+h} for h in ALL[i:i+3]] for i in range(0,len(ALL),3)]
 bot.send('🛠 Выбери сервер. Обслуживание временно подавляет тревоги и ограниченное автоисправление, но не выключает VPN или службы.',{'inline_keyboard':rows})
def maintenance_callback(bot,q,kind,value):
 if kind=='maintnode':
  if value not in ALL:bot.answer(q.get('id'),'Недопустимый сервер');return
  bot.answer(q.get('id'),'Выбери длительность');rows=[[{'text':str(n)+' мин.','callback_data':'maintset:'+value+':'+str(n)} for n in [15,30,60]],[{'text':'Завершить обслуживание','callback_data':'maintset:'+value+':off'}]]
  bot.send('🛠 '+label(value)+': время обслуживания. После завершения бот запустит контрольную проверку.',{'inline_keyboard':rows});return
 if kind!='maintset':return
 host,sep,duration=value.partition(':')
 if host not in ALL or duration not in ['15','30','60','off']:bot.answer(q.get('id'),'Недопустимый запрос');return
 # Inline action messages expire and belong to the owner; no reboot or service stop is triggered.
 if time.time()-q.get('message',{}).get('date',0)>180:bot.answer(q.get('id'),'Меню устарело; открой заново');return
 bot.answer(q.get('id'),'Применяю');bot.executor.submit(set_maintenance,bot,host,duration)
def set_maintenance(bot,host,duration):
 try:d=rpc(host,'maint-'+duration)
 except Exception:bot.send('⚠️ '+label(host)+': обслуживание не подтверждено. Ничего не выключалось.');return
 with bot.lock:
  p=STATE/'maintenance-central.json';s=read(p)
  if duration=='off':s[host]={'until':0,'check_pending':True}
  else:s[host]={'until':d['until'],'check_pending':True}
  atomic(p,s)
 bot.send('🛠 '+label(host)+(': обслуживание на '+duration+' мин. Службы и VPN продолжают работать.' if duration!='off' else ': обслуживание завершено; запускаю контрольную проверку.'))
 if duration=='off':maintenance_tick(bot)
def maintenance_tick(bot):
 p=STATE/'maintenance-central.json'
 with bot.lock:
  s=read(p);due=[h for h,d in s.items() if d.get('until',0)<=time.time() and d.get('check_pending')]
  for h in due:s[h]['check_pending']=False
  if due:atomic(p,s)
 for h in due:
  try:
   rpc(h,'maint-off')
   r=bot.nodes.call(h,'check') if h in HOSTS else {'failures':[k for k,v in rpc(h,'extras')['services'].items() if not v]}
   journal(h,r,'check');bot.send(('⚠️' if r.get('failures') or r.get('skipped') else '✅')+' '+label(h)+': обслуживание завершено. '+('Контроль: '+', '.join(r.get('failures',[])) if r.get('failures') else 'Контрольная проверка прошла.' if not r.get('skipped') else 'Проверка занята; повтори вручную.'))
  except Exception:bot.send('⚠️ '+label(h)+': обслуживание завершено; контрольную проверку выполнить не удалось. Плановый мониторинг продолжает работу.')
def webdav():
 c=read(ROOT/'backup-webdav.json')
 if c.get('url')!='https://vikrk.netcraze.pro/webdav/':raise RuntimeError('Unexpected WebDAV destination')
 return c
def dav_req(method,url,data=None,headers=None):
 c=webdav();h={'Authorization':'Basic '+base64.b64encode((c['username']+':'+c['password']).encode()).decode()};h.update(headers or {})
 class Redirect(urllib.request.HTTPRedirectHandler):
  def redirect_request(self,*args,**kwargs):raise RuntimeError('WebDAV redirect refused')
 op=urllib.request.build_opener(urllib.request.ProxyHandler({}),Redirect())
 return op.open(urllib.request.Request(url,data=data,method=method,headers=h),timeout=90)
def upload(path,url):
 with path.open('rb') as f:
  with dav_req('PUT',url,f,{'Content-Length':str(path.stat().st_size),'Content-Type':'application/octet-stream'}) as r:
   if r.status not in [200,201,204]:raise RuntimeError('Upload rejected')
def download(url,path):
 with dav_req('GET',url) as r,path.open('wb') as f:shutil.copyfileobj(r,f)
 path.chmod(0o600)
def verify_archive(path,work):
 with tarfile.open(path,'r:gz') as t:
  manifest=json.load(t.extractfile('rvkomi-backup-manifest.json'))
  dbs=[m for m in t.getmembers() if m.name=='etc/x-ui/x-ui.db']
  if dbs:
   p=work/'restore-test.db'
   with t.extractfile(dbs[-1]) as src,p.open('wb') as dest:shutil.copyfileobj(src,dest)
   with sqlite3.connect('file:'+str(p)+'?mode=ro',uri=True) as c:
    if c.execute('pragma integrity_check').fetchone()[0]!='ok':raise RuntimeError('SQLite snapshot corrupt')
   p.unlink()
 return manifest
RETENTION_SECONDS=3*86400
BACKUP_NAME=re.compile(r'^(spb|nl|dns|www|space|latvia|fin|telegramm)-(\d{8}T\d{6}Z)\.tar\.gz\.enc(\.json)?$')
def retention_candidates(hrefs,root,hosts,protected,now=None):
    now=time.time() if now is None else now;cutoff=now-RETENTION_SECONDS
    rootpath=urllib.parse.unquote(urllib.parse.urlsplit(root).path).rstrip('/')+'/'
    out={}
    for href in hrefs:
        parsed=urllib.parse.urlsplit(href)
        if parsed.netloc and parsed.netloc!=urllib.parse.urlsplit(root).netloc:continue
        path=urllib.parse.unquote(parsed.path)
        if path.rsplit('/',1)[0]+'/' != rootpath:continue
        name=path.rsplit('/',1)[-1];match=BACKUP_NAME.fullmatch(name)
        if not match or match.group(1) not in hosts or name in protected:continue
        try:stamp=datetime.datetime.strptime(match.group(2),'%Y%m%dT%H%M%SZ').replace(tzinfo=datetime.timezone.utc).timestamp()
        except ValueError:continue
        if stamp<cutoff:out[name]=stamp
    return out

def prune_backups(result):
    successful={h:r for h,r in result.get('hosts',{}).items() if r.get('ok') and r.get('restore_verified')}
    if not successful:return {'days':3,'deleted_archives':0,'deleted_metadata':0,'skipped':'no-new-verified-backup'}
    root=webdav()['url']+'rvkomi-backups/'
    protected={name for r in successful.values() for name in [r['file'],r['file']+'.json']}
    with dav_req('PROPFIND',root,headers={'Depth':'1'}) as response:
        data=response.read(4*1024*1024+1)
    if len(data)>4*1024*1024:raise RuntimeError('WebDAV listing too large; retention skipped')
    listing=ET.fromstring(data);hrefs=[r.findtext('{DAV:}href','') for r in listing.findall('{DAV:}response')]
    candidates=retention_candidates(hrefs,root,set(successful),protected)
    report={'days':3,'deleted_archives':0,'deleted_metadata':0,'errors':[]}
    allnames={urllib.parse.unquote(urllib.parse.urlsplit(h).path).rsplit('/',1)[-1] for h in hrefs}
    def delete(name,kind):
        try:
            with dav_req('DELETE',root+name) as response:
                if response.status not in [200,204]:raise RuntimeError('Deletion rejected')
            report[kind]+=1;return True
        except urllib.error.HTTPError as e:
            if e.code==404:return True
            report['errors'].append({'file':name,'error':'HTTP '+str(e.code)});return False
        except Exception as e:
            report['errors'].append({'file':name,'error':type(e).__name__});return False
    failed=set()
    for name in sorted(candidates,key=lambda n:(candidates[n],n)):
        if name.endswith('.json'):continue
        if not delete(name,'deleted_archives'):failed.add(name)
        elif name+'.json' in candidates:delete(name+'.json','deleted_metadata');allnames.discard(name+'.json')
    # Remove orphan metadata only if old and its host has a newly verified copy.
    for name in candidates:
        if name.endswith('.json') and name in allnames and name[:-5] not in failed and name[:-5] not in allnames:
            delete(name,'deleted_metadata')
    return report

def backup_run(bot=None):
 STATE.mkdir(mode=0o700,parents=True,exist_ok=True)
 with (STATE/'backup.lock').open('a+') as lock:
  try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  except BlockingIOError:
   if bot:bot.send('💾 Создание копий уже выполняется.')
   return {'skipped':'running'}
  start=time.time();stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ');root=webdav()['url']+'rvkomi-backups/'
  result={'started':start,'finished':None,'destination':'роутер Keenetic / rvkomi-backups','encrypted':True,'hosts':{}}
  atomic(STATE/'backup-state.json',result)
  try:
   try:
    with dav_req('MKCOL',root) as r:pass
   except urllib.error.HTTPError as e:
    if e.code!=405:raise
    with dav_req('PROPFIND',root,headers={'Depth':'0'}) as r:
     if r.status!=207:raise RuntimeError('Backup collection missing')
   key=ROOT/'backup-recovery.key'
   if not key.exists():raise RuntimeError('Recovery key missing')
   secret=key.read_bytes().strip()
   staging=STATE/'backup-staging';staging.mkdir(mode=0o700,exist_ok=True)
   for host in ALL:
    try:
     with tempfile.TemporaryDirectory(dir=staging,prefix=host+'-') as td:
      td=Path(td);plain=td/'backup.tar.gz';args,env=ssh_job(host,'backup-export')
      with plain.open('wb') as f:r=subprocess.run(args,env=env,stdin=subprocess.DEVNULL,stdout=f,stderr=subprocess.PIPE,start_new_session=True,timeout=150)
      if r.returncode:raise RuntimeError('Node backup export failed')
      verify_archive(plain,td)
      enc=td/'backup.enc';r=subprocess.run(['openssl','enc','-aes-256-cbc','-pbkdf2','-iter','200000','-md','sha256','-salt','-pass','file:'+str(key),'-in',str(plain),'-out',str(enc)],capture_output=True,timeout=60)
      if r.returncode:raise RuntimeError('Encryption failed')
      mac=hmac.new(secret,enc.read_bytes(),hashlib.sha256).hexdigest();sha=hashlib.sha256(enc.read_bytes()).hexdigest();filename=host+'-'+stamp+'.tar.gz.enc';url=root+filename
      upload(enc,url)
      # Download, authenticate, decrypt and validate a separate copy; never restore over a live server.
      fetched=td/'download.enc';download(url,fetched)
      if not hmac.compare_digest(hmac.new(secret,fetched.read_bytes(),hashlib.sha256).hexdigest(),mac):raise RuntimeError('Downloaded backup authentication failed')
      restored=td/'restore.tar.gz';r=subprocess.run(['openssl','enc','-d','-aes-256-cbc','-pbkdf2','-iter','200000','-md','sha256','-pass','file:'+str(key),'-in',str(fetched),'-out',str(restored)],capture_output=True,timeout=60)
      if r.returncode:raise RuntimeError('Decryption test failed')
      verify_archive(restored,td)
      meta={'host':host,'created':stamp,'file':filename,'sha256':sha,'hmac_sha256':mac,'bytes':enc.stat().st_size,'encryption':'AES-256-CBC + PBKDF2-SHA256 200000 + HMAC-SHA256','restore_test':'download, HMAC, decrypt, tar and SQLite integrity checked'}
      mp=td/'metadata.json';atomic(mp,meta);upload(mp,url+'.json')
      result['hosts'][host]={'ok':True,'file':filename,'bytes':meta['bytes'],'sha256':sha,'hmac_sha256':mac,'restore_verified':True,'time':time.time()}
    except Exception as e:result['hosts'][host]={'ok':False,'error':str(e) if isinstance(e,RuntimeError) else type(e).__name__,'time':time.time()}
    atomic(STATE/'backup-state.json',result)
  except Exception as e:result['error']=('WebDAV HTTP '+str(e.code)) if isinstance(e,urllib.error.HTTPError) else type(e).__name__
  if not result.get('error'):
   try:result['retention']=prune_backups(result)
   except Exception as e:result['retention']={'days':3,'error':('WebDAV HTTP '+str(e.code)) if isinstance(e,urllib.error.HTTPError) else type(e).__name__}
  result['finished']=time.time();atomic(STATE/'backup-state.json',result)
  if bot:bot.send(format_backup(result))
  # Retention is scoped to our archives, after new copies have been verified.
  return result
def format_backup(d):
 if not d:return '📦 Резервные копии ещё не создавались.'
 lines=['📦 Резервные копии → роутер Keenetic','Архивы зашифрованы; ключ хранится отдельно.']
 if not d.get('finished'):lines.append('⏳ Создание копий выполняется.')
 if d.get('error'):lines.append('⚠️ '+d['error'])
 for h,r in d.get('hosts',{}).items():lines.append(('✅' if r['ok'] else '⚠️')+' '+label(h)+(': '+str(round(r['bytes']/2**20,2))+' МБ; скачивание и тест восстановления прошли' if r['ok'] else ': '+r['error']))
 retention=d.get('retention',{})
 if retention:
  lines.append('Очистка старше 3 дней: архивов '+str(retention.get('deleted_archives',0))+', метаданных '+str(retention.get('deleted_metadata',0))+'.')
  if retention.get('error') or retention.get('errors'):lines.append('⚠️ Очистка завершилась с ошибками; часть старых файлов сохранена.')
 if d.get('finished'):lines.append('Завершено: '+datetime.datetime.fromtimestamp(d['finished'],datetime.timezone(datetime.timedelta(hours=3))).strftime('%d.%m %H:%M МСК'))
 lines.append('Ежедневно в 04:00 МСК. Это копии конфигурации, не образ диска. Копии старше 72 часов удаляются после проверки новой копии соответствующего сервера.')
 return '\n'.join(lines)
def handle(bot,cmd):
 if cmd=='summary':summary(bot)
 elif cmd=='resources':resources(bot)
 elif cmd=='history':show_history(bot)
 elif cmd=='certificates':certs(bot)
 elif cmd=='maintenance':maintenance_menu(bot)
 elif cmd=='backup':
  nonce=secrets.token_hex(16)
  with bot.lock:bot.state['backup_pending']={'nonce':nonce,'expires':time.time()+120};bot.save()
  msg=bot.send('💾 Создать зашифрованные копии конфигураций всех восьми серверов и отправить на ваш роутер? Проверю обратное скачивание и целостность. Службы не перезапускаются.',{'inline_keyboard':[[{'text':'Создать копии','callback_data':'backupconfirm:'+nonce},{'text':'Отмена','callback_data':'backupcancel:'+nonce}]]})
  with bot.lock:
   if bot.state.get('backup_pending',{}).get('nonce')==nonce:bot.state['backup_pending']['message_id']=msg['message_id'];bot.save()
 elif cmd=='backup_status':bot.send(format_backup(read(STATE/'backup-state.json')))
def backup_callback(bot,q,kind,nonce):
 with bot.lock:
  p=bot.state.get('backup_pending',{})
  if p.get('nonce')!=nonce or p.get('message_id')!=q.get('message',{}).get('message_id'):bot.answer(q.get('id'),'Запрос уже использован');return
  bot.state.pop('backup_pending',None);bot.save()
 bot.remove_buttons(p.get('message_id'))
 if kind=='backupcancel':bot.answer(q.get('id'),'Отменено');return
 if p['expires']<time.time():bot.answer(q.get('id'),'Подтверждение истекло');return
 bot.answer(q.get('id'),'Создаю копии');bot.send('💾 Копирование началось. Это может занять несколько минут.');bot.executor.submit(backup_run,bot)
def certificate_alerts(bot):
 data=collect('certs');p=STATE/'certificate-alert-state.json';state=read(p)
 for h,d in data.items():
  if d.get('error'):continue
  for c in d.get('certificates',[]):
   if c.get('cached') and time.time()-c.get('checked_at',0)>3*86400:continue
   tier=next((x for x in [0,7,14,30] if c['days']<=x),None)
   if tier is None:continue
   key=h+':'+c.get('fingerprint',c['subject'])+':'+str(tier)
   if key in state:continue
   bot.send('🔐 ⚠️ '+label(h)+' '+c['subject'].replace('subject=','')+f": до окончания {c['days']:.1f} дней. Проверь автопродление.")
   state[key]=time.time();atomic(p,state)
 return {'hosts':len(data),'warning_events':len(state)}
def scheduled_record(bot,host,result):
 journal(host,result,'scheduled')
def main():
 import argparse
 a=argparse.ArgumentParser();a.add_argument('mode',choices=['backup','certificates','resources']);arg=a.parse_args()
 tc=load_tc();cred=read(ROOT/'telegram.json');api=tc.API(cred)
 class Notify:
  nodes=tc.Nodes()
  def send(self,text):return api.call('sendMessage',{'chat_id':int(cred['chat_id']),'text':text[:3900]},timeout=20)
 bot=Notify()
 if arg.mode=='backup':
  r=backup_run(bot)
  if r.get('error') or any(not x.get('ok') for x in r.get('hosts',{}).values()):raise SystemExit(1)
 elif arg.mode=='certificates':print(json.dumps(certificate_alerts(bot)))
 elif arg.mode=='resources':resources(bot)
if __name__=='__main__':main()

