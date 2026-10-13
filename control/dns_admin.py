"""Only owner-confirmed explicit DNS rewrites to the owner-configured relay; no arbitrary rules."""
import pathlib,json,re,hashlib,copy,os,subprocess,tempfile,time,ipaddress
import yaml
FILE=pathlib.Path('/opt/AdGuardHome/AdGuardHome.yaml')
POLICY=pathlib.Path('/etc/rvkomi-watchdog/ai-admin-policy.json')
BIN='/opt/AdGuardHome/AdGuardHome'
DOMAIN=re.compile(r'^domain:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$')
def policy():return json.loads(POLICY.read_text())

def target():
 p=policy().get('dns_rewrites',{})
 if not p.get('enabled'):raise ValueError('dns-rewrites-not-enabled')
 ip=ipaddress.IPv4Address(p.get('target_ipv4',''))
 if not ip.is_global:raise ValueError('dns-target-must-be-public-ipv4')
 return str(ip)
def read():
 if FILE.is_symlink():raise ValueError('config-symlink-not-allowed')
 text=FILE.read_text();d=yaml.safe_load(text)
 if not isinstance(d,dict) or not isinstance(d.get('user_rules'),list) or not all(isinstance(x,str) for x in d['user_rules']):raise ValueError('unexpected-adguard-config')
 return text,d
def digest(d):return hashlib.sha256(json.dumps(d,sort_keys=True,ensure_ascii=False,separators=(',',':')).encode()).hexdigest()
def rule(domain):return '||'+domain.split(':',1)[1]+'^$dnsrewrite='+target()
def domains(rules):
 t=target();pattern=re.compile(r'^\|\|((?:[a-z0-9-]+\.)+[a-z0-9-]+)\^\$dnsrewrite='+re.escape(t)+r'$')
 return sorted(set('domain:'+m[1] for r in rules if (m:=pattern.fullmatch(r))))
def describe():
 _,d=read();return {'target_ipv4':target(),'domains':domains(d['user_rules']),'digest':digest(d),'max_domains':10,'operations':['dns_add','dns_remove'],'scope':'explicit user_rules dnsrewrite to owner-configured relay only'}
def validate(p):
 target()
 if not isinstance(p,dict) or set(p)!={'action','domains','digest'} or p['action'] not in ('dns_add','dns_remove'):raise ValueError('bad-dns-plan')
 ds=p['domains']
 if not isinstance(ds,list) or not 1<=len(ds)<=10 or len(set(ds))!=len(ds) or any(not isinstance(x,str) or len(x)>253 or (not DOMAIN.fullmatch(x) or re.fullmatch(r'domain:[0-9.]+',x)) for x in ds):raise ValueError('bad-dns-domains')
 if not isinstance(p['digest'],str) or not re.fullmatch('[a-f0-9]{64}',p['digest']):raise ValueError('bad-dns-digest')
 return p
def candidate(text,d,p):
 validate(p)
 if digest(d)!=p['digest']:raise ValueError('config-changed-create-new-proposal')
 rules=list(d['user_rules']);existing=domains(rules)
 for domain in p['domains']:
  exact=rule(domain)
  if p['action']=='dns_remove':
   if domain not in existing:raise ValueError('dns-rule-not-present')
   rules=[r for r in rules if r!=exact]
  else:
   if domain in existing:raise ValueError('dns-rule-already-present')
   # Do not silently override a different existing rewrite of the same domain.
   prefix='||'+domain.split(':',1)[1]+'^'
   if any(r.startswith(prefix) and '$dnsrewrite=' in r and r!=exact for r in rules):raise ValueError('conflicting-dnsrewrite')
   rules.append(exact)
 node=yaml.compose(text);entry=next(((k,v) for k,v in node.value if k.value=='user_rules'),None)
 if not entry or entry[0].start_mark.column!=0 or not isinstance(entry[1],yaml.SequenceNode):raise ValueError('unsupported-user-rules-layout')
 k,v=entry;new=text[:k.start_mark.index]+'user_rules:\n'+yaml.safe_dump(rules,allow_unicode=True,sort_keys=False)+text[v.end_mark.index:]
 desired=copy.deepcopy(d);desired['user_rules']=rules
 if yaml.safe_load(new)!=desired:raise ValueError('unrelated-config-change')
 return new,desired

def run(args,timeout=30):return subprocess.run(args,capture_output=True,text=True,timeout=timeout)
def active():return run(['systemctl','is-active','--quiet','AdGuardHome']).returncode==0
def config_test(path):return run([BIN,'--check-config','-c',str(path),'-w',str(FILE.parent)],20).returncode==0
def atomic_write(text):
 st=FILE.stat();fd,name=tempfile.mkstemp(prefix='.rvkomi-dns-',dir=FILE.parent)
 try:
  os.fchmod(fd,st.st_mode & 0o777);os.fchown(fd,st.st_uid,st.st_gid)
  with os.fdopen(fd,'w') as f:f.write(text);f.flush();os.fsync(f.fileno())
  os.replace(name,FILE)
 finally:
  if os.path.exists(name):os.unlink(name)
def resolve(domain):
 r=run(['dig','@127.0.0.1',domain,'A','+short','+time=3','+tries=1'],8)
 ips=[]
 for line in r.stdout.splitlines():
  try:ips.append(str(ipaddress.IPv4Address(line.strip())))
  except ValueError:pass
 return r.returncode==0,ips

def apply(p,backup):
 validate(p);text,d=read();new,desired=candidate(text,d,p)
 if not active():raise ValueError('adguard-not-active-no-change')
 backup=pathlib.Path(backup);backup.mkdir(mode=0o700,parents=True,exist_ok=True)
 check=backup/'AdGuardHome.candidate.yaml';check.write_text(new);check.chmod(0o600)
 if not config_test(check):raise ValueError('candidate-config-test-failed')
 _,latest=read()
 if digest(latest)!=p['digest']:raise ValueError('config-changed-create-new-proposal')
 stopped=False;changed=False;before=None
 try:
  if run(['systemctl','stop','AdGuardHome'],35).returncode!=0:raise ValueError('adguard-stop-failed')
  stopped=True;before,current=read();new,desired=candidate(before,current,p)
  original=backup/'AdGuardHome.before.yaml';original.write_text(before);original.chmod(0o600)
  check.write_text(new);check.chmod(0o600)
  if not config_test(check):raise ValueError('final-config-test-failed')
  atomic_write(new);changed=True
  if run(['systemctl','start','AdGuardHome'],35).returncode!=0:raise ValueError('adguard-start-failed')
  time.sleep(2)
  if not active():raise ValueError('adguard-not-active-after-change')
  _,actual=read()
  if actual!=desired:raise ValueError('config-verification-failed')
  ok,ips=resolve('example.org')
  if not ok or not ips:raise ValueError('baseline-dns-resolution-failed')
  if p['action']=='dns_add':
   for domain in p['domains']:
    ok,ips=resolve(domain.split(':',1)[1])
    if not ok or target() not in ips:raise ValueError('new-dns-answer-not-confirmed')
  if actual.get('querylog')!=d.get('querylog') or actual.get('statistics')!=d.get('statistics'):raise ValueError('retention-changed')
  return {'ok':True,'action':p['action'],'domains':p['domains'],'target_ipv4':target(),'backup':str(backup),'validation':'config-test, service-active, persisted-rules, DNS-response','retention_unchanged':True,'other_settings_unchanged':True}
 except Exception as e:
  rolled_back=False
  if changed and before is not None:
   try:
    if run(['systemctl','stop','AdGuardHome'],35).returncode!=0:raise ValueError('rollback-stop-failed')
    atomic_write(before);started=run(['systemctl','start','AdGuardHome'],35).returncode==0;time.sleep(2)
    _,restored=read();rolled_back=started and active() and restored==yaml.safe_load(before)
   except Exception:rolled_back=False
  elif stopped:
   try:rolled_back=run(['systemctl','start','AdGuardHome'],35).returncode==0 and active()
   except Exception:pass
  return {'ok':False,'rolled_back':rolled_back,'error':str(e) if isinstance(e,ValueError) else type(e).__name__,'backup':str(backup)}
