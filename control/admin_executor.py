#!/usr/bin/python3
"""Forced-command executor. No shell, arbitrary paths, code, reboot or SSH/firewall edits."""
import os,json,re,sys,time,pathlib,hashlib,sqlite3,subprocess,tempfile,fcntl
ROOT=pathlib.Path('/var/lib/rvkomi-ai-admin')
CFG=pathlib.Path('/usr/local/x-ui/bin/config.json'); DB=pathlib.Path('/etc/x-ui/x-ui.db'); XRAY='/usr/local/x-ui/bin/xray-linux-amd64'
DOMAIN=re.compile(r'^(?:domain:|full:)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$')
def run(args,timeout=30):
 return subprocess.run(args,capture_output=True,text=True,timeout=timeout,cwd='/usr/local/x-ui/bin' if pathlib.Path('/usr/local/x-ui/bin').exists() else '/',env={**os.environ,'XRAY_LOCATION_ASSET':'/usr/local/x-ui/bin'})
def active(unit):return run(['systemctl','is-active','--quiet',unit]).returncode==0
POLICY=pathlib.Path('/etc/rvkomi-watchdog/ai-admin-policy.json')
def policy():return json.loads(POLICY.read_text())
def allowed():return policy()['services']
def loaded(unit):return run(['systemctl','show',unit,'--property=LoadState','--value']).stdout.strip()=='loaded'

def load():
 con=sqlite3.connect(str(DB),timeout=20)
 rows=con.execute("select id,value from settings where key='xrayTemplateConfig'").fetchall()
 if len(rows)!=1:raise ValueError('template-not-unique')
 ident,text=rows[0];return con,ident,text,json.loads(text),json.loads(CFG.read_text())
def digest(text,live):return hashlib.sha256((text+'\n'+json.dumps(live,sort_keys=True)).encode()).hexdigest()
def describe():
 result={'services':[u for u in allowed() if loaded(u)],'service_states':{u:('active' if active(u) else 'inactive') for u in allowed() if loaded(u)},'routing':False}
 if policy().get('adguard_filters',{}).get('enabled'):
  import adguard_filters
  result['filters']=adguard_filters.describe()
 if policy().get('dns_rewrites',{}).get('enabled'):
  import dns_admin
  result['dns']=dns_admin.describe()
 if policy().get('sni',{}).get('enabled'):
  import sni_admin
  result['sni']=sni_admin.describe()
 if policy().get('routing') and DB.exists() and CFG.exists():
  try:con,ident,text,c,live=load()
  except ValueError:return result
  con.close();result.update(routing=True,digest=digest(text,live),rules=[])
  for i,r in enumerate(c.get('routing',{}).get('rules',[])):
   if r.get('domain') and r.get('outboundTag') not in (None,'direct','blocked','api') and r.get('enabled',True):result['rules'].append({'index':i,'domains':r['domain'],'outbound':r['outboundTag'],'inbound':r.get('inboundTag',[])})
 return result
def validate_plan(p):
 if isinstance(p,dict) and p.get('action') in ('filter_add','filter_remove','filter_replace','subscription_add','subscription_remove','subscription_enable','subscription_disable'):
  import adguard_filters
  adguard_filters.validate(p);return p
 if isinstance(p,dict) and p.get('action') in ('dns_add','dns_remove'):
  import dns_admin
  dns_admin.validate(p);return p
 if isinstance(p,dict) and p.get('action') in ('sni_add','sni_remove','sni_target_set'):
  if not policy().get('sni',{}).get('enabled'):raise ValueError('sni-not-enabled')
  import sni_admin
  if not sni_admin.FILE.exists():raise ValueError('sni-not-available')
  sni_admin.validate(p);return p
 if not isinstance(p,dict) or p.get('action') not in ('route_add','restart_service'):raise ValueError('unsupported-action')
 if p['action']=='restart_service':
  if set(p)!={'action','service'} or p['service'] not in allowed():raise ValueError('service-not-allowed')
 else:
  if not policy().get('routing'):raise ValueError('routing-not-allowed')
  if set(p)!={'action','rule','domains','digest'}:raise ValueError('unexpected-fields')
  if type(p['rule'])!=int or p['rule']<0:raise ValueError('bad-rule')
  if not re.fullmatch('[0-9a-f]{64}',str(p['digest'])):raise ValueError('bad-digest')
  if not isinstance(p['domains'],list) or not 1<=len(p['domains'])<=60:raise ValueError('domain-limit')
  if any(not isinstance(d,str) or len(d)>260 or not DOMAIN.fullmatch(d) for d in p['domains']):raise ValueError('bad-domain')
 return p

def preflight(service):
 if service=='nginx':return run(['nginx','-t']).returncode==0
 if service=='x-ui':return run([XRAY,'run','-test','-config',str(CFG)]).returncode==0
 if service=='xray':
  return run(['xray','run','-test','-config','/usr/local/etc/xray/config.json']).returncode==0
 if not loaded(service):return False
 check=policy().get('preflight',{}).get(service)
 if check:return run(check).returncode==0
 return True


def xray_alive():
 for proc in pathlib.Path('/proc').iterdir():
  try:
   if not proc.name.isdigit() or (proc/'exe').resolve()!=pathlib.Path(XRAY):continue
   args=(proc/'cmdline').read_bytes().decode().split('\0')
   for flag in ('-c','-config'):
    if flag in args:
     config=pathlib.Path(args[args.index(flag)+1])
     if not config.is_absolute():config=(proc/'cwd').resolve()/config
     if config.resolve()==CFG.resolve():return True
  except OSError:pass
 return False

def apply(p):
 validate_plan(p);ROOT.mkdir(mode=0o700,parents=True,exist_ok=True)
 with (ROOT/'lock').open('a+') as lock:
  fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  b=ROOT/(str(int(time.time()))+'-'+os.urandom(4).hex());b.mkdir(mode=0o700)
  (b/'request.json').write_text(json.dumps(p));(b/'request.json').chmod(0o600)
  if p['action'] in ('filter_add','filter_remove','filter_replace','subscription_add','subscription_remove','subscription_enable','subscription_disable'):
   import adguard_filters
   return adguard_filters.apply(p,b)
  if p['action'] in ('dns_add','dns_remove'):
   import dns_admin
   return dns_admin.apply(p,b)
  if p['action'] in ('sni_add','sni_remove','sni_target_set'):
   import sni_admin
   return sni_admin.apply(p,b)
  if p['action']=='restart_service':
   unit=p['service']
   if not loaded(unit):raise ValueError('service-not-installed')
   if not preflight(unit):raise ValueError('preflight-failed')
   r=run(['systemctl','restart',unit],timeout=60);time.sleep(3)
   return {'ok':r.returncode==0 and active(unit),'action':'restart_service','service':unit,'backup':str(b)}
  con,ident,text,c,live=load()
  if digest(text,live)!=p['digest']:con.close();raise ValueError('config-changed-create-new-proposal')
  rules=c['routing']['rules'];i=p['rule']
  if i>=len(rules):raise ValueError('rule-missing')
  rule=rules[i]
  if not rule.get('domain') or rule.get('outboundTag') in (None,'direct','blocked','api') or not rule.get('enabled',True):raise ValueError('rule-not-allowed')
  lr=[r for r in live['routing']['rules'] if r.get('domain')==rule['domain'] and r.get('outboundTag')==rule['outboundTag'] and r.get('inboundTag',[])==rule.get('inboundTag',[])]
  if len(lr)!=1:raise ValueError('live-template-mismatch')
  original=set(rule['domain']);added=[]
  for d in p['domains']:
   if d not in rule['domain']:rule['domain'].append(d);lr[0]['domain'].append(d);added.append(d)
  if not added:con.close();return {'ok':True,'noop':True,'added':[]}
  backupcon=sqlite3.connect(str(b/'x-ui.db'));con.backup(backupcon);backupcon.close();(b/'x-ui.db').chmod(0o600)
  (b/'template.json').write_text(text);(b/'template.json').chmod(0o600)
  (b/'config.json').write_bytes(CFG.read_bytes());(b/'config.json').chmod(0o600)
  candidate=b/'candidate.json';candidate.write_text(json.dumps(live));candidate.chmod(0o600)
  if run([XRAY,'run','-test','-config',str(candidate)]).returncode:con.close();raise ValueError('candidate-validation-failed')
  newtext=json.dumps(c,ensure_ascii=False);con.execute('BEGIN IMMEDIATE')
  changed=con.execute('update settings set value=? where id=? and value=?',(newtext,ident,text));assert changed.rowcount==1;con.commit()
  ok=False
  try:
   restarted=run(['systemctl','restart','x-ui'],timeout=60);time.sleep(4)
   generated=json.loads(CFG.read_text());matches=[r for r in generated['routing']['rules'] if r.get('outboundTag')==rule['outboundTag'] and r.get('inboundTag',[])==rule.get('inboundTag',[]) and all(d in r.get('domain',[]) for d in rule['domain'])]
   ok=restarted.returncode==0 and active('x-ui') and bool(matches) and preflight('x-ui')
   if ok:ok=xray_alive()
  except Exception:ok=False
  if not ok:
   con.execute('BEGIN IMMEDIATE');restored=con.execute('update settings set value=? where id=? and value=?',(text,ident,newtext));con.commit()
   rollback=False
   if restored.rowcount==1:
    try:rollback=run(['systemctl','restart','x-ui'],timeout=60).returncode==0 and active('x-ui')
    except Exception:pass
   con.close();return {'ok':False,'rolled_back':rollback,'backup':str(b)}
  con.close();return {'ok':True,'added':added,'outbound':rule['outboundTag'],'backup':str(b),'validation':'xray-test-and-process-active'}

def main():
 if os.geteuid()!=0 or os.environ.get('SSH_ORIGINAL_COMMAND')!='rpc':raise ValueError('forced-rpc-only')
 raw=sys.stdin.buffer.read(16001)
 if len(raw)>16000:raise ValueError('request-too-large')
 req=json.loads(raw)
 if req=={'op':'describe'}:return describe()
 if set(req)=={'op','plan'} and req['op']=='apply':return apply(req['plan'])
 raise ValueError('unsupported-request')
if __name__=='__main__':
 try:print(json.dumps(main(),ensure_ascii=False))
 except Exception as e:print(json.dumps({'ok':False,'error':str(e) if isinstance(e,ValueError) else type(e).__name__}));sys.exit(1)
