"""Confirmed user-rule and HTTPS subscription edits; fixed config path, no shell."""
import pathlib,json,re,copy,unicodedata,urllib.parse,socket,ssl,http.client,ipaddress,tempfile,time,hashlib
import yaml,dns_admin as dns
ACTIONS=('filter_add','filter_remove','filter_replace','subscription_add','subscription_remove','subscription_enable','subscription_disable')
def enabled():
 p=dns.policy().get('adguard_filters',{})
 if not p.get('enabled'):raise ValueError('adguard-filters-not-enabled')
 return p
def line(s):
 if not isinstance(s,str) or not s.strip() or len(s)>1024 or any(unicodedata.category(c) in ('Cc','Cf') for c in s):raise ValueError('invalid-filter-line')
 if s!=s.strip():raise ValueError('filter-line-leading-trailing-space')
 return s
def url(s):
 if not isinstance(s,str) or len(s)>2048 or any(ord(c)<33 for c in s):raise ValueError('invalid-subscription-url')
 u=urllib.parse.urlsplit(s)
 if u.scheme!='https' or not u.hostname or u.username or u.password or u.fragment or u.port not in (None,443):raise ValueError('public-https-subscriptions-only')
 try:
  if not ipaddress.ip_address(u.hostname).is_global:raise ValueError('private-subscription-address')
 except ValueError as e:
  if str(e)=='private-subscription-address':raise
  if not re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9-]+',u.hostname):raise ValueError('invalid-subscription-host')
 return u
class PinnedHTTPS(http.client.HTTPSConnection):
 def connect(self):
  addresses={r[4][0] for r in socket.getaddrinfo(self.host,self.port,type=socket.SOCK_STREAM)}
  if not addresses or any(not ipaddress.ip_address(ip).is_global for ip in addresses):raise ValueError('subscription-resolves-to-private-network')
  raw=socket.create_connection((sorted(addresses)[0],self.port),timeout=12)
  self.sock=self._context.wrap_socket(raw,server_hostname=self.host)
def download(address):
 limit=min(int(enabled().get('max_download_bytes',10485760)),10485760);current=address
 for _ in range(4):
  u=url(current);c=PinnedHTTPS(u.hostname,443,timeout=12,context=ssl.create_default_context())
  try:
   c.request('GET',urllib.parse.urlunsplit(('', '',u.path or '/',u.query,'')),headers={'User-Agent':'rvkomi-confirmed-filter-admin/1','Accept-Encoding':'identity'})
   response=c.getresponse()
   if response.status in (301,302,303,307,308):
    current=urllib.parse.urljoin(current,response.getheader('Location',''));url(current);continue
   if response.status!=200:raise ValueError('subscription-download-not-200')
   content=response.read(limit+1)
   if len(content)>limit:raise ValueError('subscription-too-large')
   text=content.decode('utf-8-sig')
   if '<html' in text[:2000].lower() or '<!doctype html' in text[:2000].lower() or '\x00' in text or not any(x.strip() and not x.lstrip().startswith(('!','#','[')) for x in text.splitlines()):raise ValueError('subscription-not-a-filter-list')
   return content
  finally:c.close()
 raise ValueError('too-many-subscription-redirects')
def describe():
 enabled();_,d=dns.read();return {'digest':dns.digest(d),'rules':[{'index':i,'text':r} for i,r in enumerate(d['user_rules'])][:500], 'subscriptions':[{'id':r['id'],'url':r['url'],'name':r.get('name',''),'enabled':bool(r.get('enabled'))} for r in d.get('filters',[])], 'max_lines':20,'operations':list(ACTIONS),'scope':'user_rules and filters only; no upstream, retention, users or listener changes'}
def validate(p):
 enabled()
 if not isinstance(p,dict) or p.get('action') not in ACTIONS or not re.fullmatch('[a-f0-9]{64}',str(p.get('digest',''))):raise ValueError('invalid-filter-plan')
 a=p['action']
 if a in ('filter_add','filter_remove'):
  if set(p)!={'action','lines','digest'} or not isinstance(p['lines'],list) or not 1<=len(p['lines'])<=20:raise ValueError('filter-line-limit')
  for s in p['lines']:line(s)
  if len(set(p['lines']))!=len(p['lines']):raise ValueError('duplicate-filter-lines')
 elif a=='filter_replace':
  if set(p)!={'action','old','new','digest'}:raise ValueError('invalid-filter-replacement')
  line(p['old']);line(p['new'])
 elif a=='subscription_add':
  if set(p)!={'action','url','digest'}:raise ValueError('invalid-subscription-add')
  url(p['url'])
 else:
  if set(p)!={'action','id','digest'} or type(p['id'])!=int or p['id']<0:raise ValueError('invalid-subscription-id')
 return p
def patch_field(text,key,value):
 root=yaml.compose(text);pair=next(((k,v) for k,v in root.value if k.value==key),None)
 if not pair or pair[0].start_mark.column!=0 or not isinstance(pair[1],yaml.SequenceNode):raise ValueError('unsupported-config-layout')
 k,v=pair;fragment=yaml.safe_dump({key:value},allow_unicode=True,sort_keys=False);return text[:k.start_mark.index]+fragment+text[v.end_mark.index:]
def candidate(text,d,p):
 validate(p)
 if dns.digest(d)!=p['digest']:raise ValueError('config-changed-create-new-proposal')
 desired=copy.deepcopy(d);a=p['action'];key='user_rules' if a.startswith('filter_') else 'filters'
 value=desired[key]
 if a=='filter_add':
  if any(s in value for s in p['lines']):raise ValueError('filter-line-already-present')
  value.extend(p['lines'])
 elif a=='filter_remove':
  if any(s not in value for s in p['lines']):raise ValueError('filter-line-not-present')
  desired[key]=[s for s in value if s not in p['lines']]
 elif a=='filter_replace':
  if value.count(p['old'])!=1 or p['new'] in value:raise ValueError('filter-replacement-not-unique')
  value[value.index(p['old'])]=p['new']
 elif a=='subscription_add':
  if any(r['url']==p['url'] for r in value):raise ValueError('subscription-already-present')
  ident=max([r['id'] for r in value]+[r['id'] for r in d.get('whitelist_filters',[])]+[0])+1
  value.append({'enabled':True,'url':p['url'],'name':'ИИ: '+url(p['url']).hostname,'id':ident})
 else:
  matches=[r for r in value if r['id']==p['id']]
  if len(matches)!=1:raise ValueError('subscription-not-unique')
  if a=='subscription_remove':desired[key]=[r for r in value if r['id']!=p['id']]
  else:matches[0]['enabled']=a=='subscription_enable'
 new=patch_field(text,key,desired[key])
 if yaml.safe_load(new)!=desired:raise ValueError('unrelated-config-change')
 return new,desired

def dns_response():
 r=dns.run(['dig','@127.0.0.1','example.org','A','+time=3','+tries=1','+noall','+comments'],8)
 # A deliberately blocked response is valid; do not require an unblocked IP.
 return r.returncode==0 and bool(re.search(r'status: (?:NOERROR|NXDOMAIN)',r.stdout))
def apply(p,backup):
 validate(p);text,before=dns.read();new,desired=candidate(text,before,p)
 if not dns.active():raise ValueError('adguard-not-active')
 # Only after confirmation: prefetch the newly added/enabled list with public-address pinning.
 fetched=None;ident=p.get('id')
 if p['action']=='subscription_add':
  fetched=download(p['url']);ident=next(r['id'] for r in desired['filters'] if r['url']==p['url'])
 elif p['action']=='subscription_enable':
  rec=next(r for r in desired['filters'] if r['id']==p['id']);fetched=download(rec['url']);ident=p['id']
 backup=pathlib.Path(backup);backup.mkdir(mode=0o700,parents=True,exist_ok=True);check=backup/'AdGuardHome.candidate.yaml';check.write_text(new);check.chmod(0o600)
 if not dns.config_test(check):raise ValueError('candidate-config-test-failed')
 stopped=False;changed=False;original=None;filterfile=None;oldfilter=None;hadfilter=False
 try:
  if dns.run(['systemctl','stop','AdGuardHome'],35).returncode:raise ValueError('adguard-stop-failed')
  stopped=True;original,current=dns.read();new,desired=candidate(original,current,p)
  (backup/'AdGuardHome.before.yaml').write_text(original);(backup/'AdGuardHome.before.yaml').chmod(0o600)
  check.write_text(new)
  if not dns.config_test(check):raise ValueError('final-config-test-failed')
  if ident is not None:
   filterfile=(dns.FILE.parent/'data/filters')/(str(ident)+'.txt');assert not filterfile.is_symlink();hadfilter=filterfile.exists();oldfilter=filterfile.read_bytes() if hadfilter else None
   if hadfilter:(backup/'filter.before.txt').write_bytes(oldfilter);(backup/'filter.before.txt').chmod(0o600)
   if fetched is not None:filterfile.write_bytes(fetched);filterfile.chmod(0o600)
  dns.atomic_write(new);changed=True
  if dns.run(['systemctl','start','AdGuardHome'],35).returncode:raise ValueError('adguard-start-failed')
  time.sleep(2);_,actual=dns.read()
  if not dns.active() or actual!=desired or not dns_response():raise ValueError('filter-postcheck-failed')
  if actual.get('querylog')!=before.get('querylog') or actual.get('statistics')!=before.get('statistics'):raise ValueError('retention-changed')
  return {'ok':True,'action':p['action'],'backup':str(backup),'validation':'config-test, persisted-rules/subscriptions, active-service, DNS-response','retention_unchanged':True,'other_settings_unchanged':True}
 except Exception as e:
  rolled_back=False
  if changed:
   try:
    if dns.run(['systemctl','stop','AdGuardHome'],35).returncode:raise ValueError('rollback-stop-failed')
    dns.atomic_write(original)
    if filterfile:
     if hadfilter:filterfile.write_bytes(oldfilter)
     else:filterfile.unlink(missing_ok=True)
    started=dns.run(['systemctl','start','AdGuardHome'],35).returncode==0;time.sleep(2);_,restored=dns.read();rolled_back=started and dns.active() and restored==yaml.safe_load(original)
   except Exception:pass
  elif stopped:
   if filterfile:
    if hadfilter:filterfile.write_bytes(oldfilter)
    else:filterfile.unlink(missing_ok=True)
   rolled_back=dns.run(['systemctl','start','AdGuardHome'],35).returncode==0 and dns.active()
  return {'ok':False,'rolled_back':rolled_back,'error':str(e) if isinstance(e,ValueError) else type(e).__name__,'backup':str(backup)}
