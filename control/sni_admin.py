"""Owner-configured relay only: add/remove domain allowlist entries; explicit per-domain backends allowed; listeners/resolvers/default never change."""
import pathlib,re,json,hashlib,os,tempfile,subprocess,socket,ssl,ipaddress
RELAY_IP=''
RELAY_PORT=443
MAP_VARIABLE=''
FILE=pathlib.Path('/etc/nginx/modules-enabled/99-rvkomi-sni-relay.conf')
PROBE=pathlib.Path('/etc/rvkomi-probe/config.json')
MAP=re.compile(r'(?ms)^\s*map\s+\$ssl_preread_server_name\s+\$fin_sni_backend\s*\{(?P<body>.*?)^\s*\}')
ENTRY=re.compile(r'(?m)^[ \t]*(?P<key>\.?[a-z0-9.-]+)[ \t]+"(?P<target>\$ssl_preread_server_name:443|[a-z0-9.-]+:[0-9]{1,5})";[ \t]*$')
DOMAIN=re.compile(r'^(?:domain:|full:)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$')
def load():
 text=FILE.read_text();match=re.search(r'(?ms)^\s*map\s+\$ssl_preread_server_name\s+\$'+re.escape(MAP_VARIABLE)+r'\s*\{(?P<body>.*?)^\s*\}',text)
 if not match or not re.search(r'\bhostnames\s*;',match['body']):raise ValueError('sni-map-format-not-supported')
 probe=PROBE.read_text();return text,match,probe

def digest(text,probe):return hashlib.sha256((text+'\n'+probe).encode()).hexdigest()
def label(key):return 'domain:'+key[1:] if key.startswith('.') else 'full:'+key
def backend(value,resolve=False):
 if value=='original:443':return '$ssl_preread_server_name:443'
 if not isinstance(value,str) or value.count(':')!=1:raise ValueError('bad-sni-target')
 host,port=value.split(':');
 if not re.fullmatch('[0-9]{1,5}',port) or not 1<=int(port)<=65535 or not re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',host):raise ValueError('bad-sni-target')
 try:
  ip=ipaddress.ip_address(host)
  if not ip.is_global or str(ip)==RELAY_IP:raise ValueError('private-or-self-sni-target')
 except ValueError as e:
  if str(e)=='private-or-self-sni-target':raise
  if re.fullmatch('[0-9.]+',host):raise ValueError('invalid-sni-ip')
 if resolve:
  ips={r[4][0] for r in socket.getaddrinfo(host,int(port),family=socket.AF_INET,type=socket.SOCK_STREAM)}
  if not ips or any(not ipaddress.ip_address(ip).is_global or ip==RELAY_IP for ip in ips):raise ValueError('private-or-self-sni-target')
 return value

def describe():
 if not FILE.exists():return None
 text,match,probe=load();entries=[{'domain':label(m['key']),'target':'original:443' if m['target']=='$ssl_preread_server_name:443' else m['target']} for m in ENTRY.finditer(match['body'])]
 return {'digest':digest(text,probe),'domains':[e['domain'] for e in entries],'entries':entries,'relay_ip':RELAY_IP,'port':RELAY_PORT,'operations':['sni_add','sni_remove','sni_target_set'],'scope':'explicit domains and public host:port only; no default/listener/resolver edits'}
def validate(p):
 if not isinstance(p,dict) or p.get('action') not in ('sni_add','sni_remove','sni_target_set'):raise ValueError('bad-sni-plan')
 required={'action','domains','digest','target'} if p['action']=='sni_target_set' else {'action','domains','digest'}
 if set(p)!=required:raise ValueError('bad-sni-plan-fields')
 if not re.fullmatch('[0-9a-f]{64}',str(p['digest'])):raise ValueError('bad-sni-digest')
 ds=p['domains']
 if not isinstance(ds,list) or not 1<=len(ds)<=10 or any(not isinstance(d,str) or len(d)>253 or not DOMAIN.fullmatch(d) or re.fullmatch(r'(?:domain:|full:)[0-9.]+',d) for d in ds):raise ValueError('bad-sni-domains')
 if p['action']=='sni_target_set':
  if len(ds)!=1:raise ValueError('one-sni-target-per-plan')
  backend(p['target'])

def write(path,text):
 mode=path.stat().st_mode&0o777;fd,tmp=tempfile.mkstemp(prefix='.sni.',dir=path.parent);os.fchmod(fd,mode)
 with os.fdopen(fd,'w') as f:f.write(text)
 os.replace(tmp,path)
def cmd(args):return subprocess.run(args,capture_output=True,timeout=30).returncode==0
def tls(domain):
 with socket.create_connection((RELAY_IP,RELAY_PORT),timeout=6) as raw:
  with ssl.create_default_context().wrap_socket(raw,server_hostname=domain) as s:return bool(s.version())
def candidate(p,text,match,probe):
 validate(p)
 if digest(text,probe)!=p['digest']:raise ValueError('sni-config-changed-create-new-proposal')
 keys=[m['key'] for m in ENTRY.finditer(match['body'])];changes=[];body=match['body']
 for domain in p['domains']:
  prefix,name=domain.split(':',1);key='.'+name if prefix=='domain' else name
  if p['action'] in ('sni_add','sni_target_set'):
   target=backend(p['target']) if p['action']=='sni_target_set' else '$ssl_preread_server_name:443'
   if key not in keys:body+='        '+key+' "'+target+'";\n';keys.append(key);changes.append(domain)
   elif p['action']=='sni_target_set':
    matches=[m for m in ENTRY.finditer(body) if m['key']==key]
    if len(matches)!=1:raise ValueError('sni-entry-not-unique')
    if matches[0]['target']!=target:
     body=ENTRY.sub(lambda m:m[0].replace('"'+m['target']+'"','"'+target+'"') if m['key']==key else m[0],body);changes.append(domain)
  else:
   if key not in keys:raise ValueError('sni-domain-not-present')
   body=ENTRY.sub(lambda m:'' if m['key']==key else m[0],body);keys.remove(key);changes.append(domain)
 if not keys:raise ValueError('cannot-remove-all-sni-domains')
 new=text[:match.start('body')]+body+text[match.end('body'):]
 cfg=json.loads(probe);monitor=cfg['sni_relay_checks']['domains']
 def covered(name):return any(name==k.lstrip('.') or (k.startswith('.') and name.endswith(k)) for k in keys)
 if p['action'] in ('sni_add','sni_target_set'):
  for d in changes:
   name=d.split(':',1)[1]
   if name not in monitor:monitor.append(name)
 else:cfg['sni_relay_checks']['domains']=[d for d in monitor if covered(d)]
 if len(cfg['sni_relay_checks']['domains'])>30:raise ValueError('sni-postcheck-domain-limit')
 tests=[d.split(':',1)[1] for d in changes] if p['action'] in ('sni_add','sni_target_set') else cfg['sni_relay_checks']['domains'][:2]
 return new,cfg,changes,tests

def apply(p,backup):
 validate(p);text,match,probe=load()
 if p['action']=='sni_target_set':backend(p['target'],resolve=True)
 new,cfg,changes,tests=candidate(p,text,match,probe)
 if not changes:return {'ok':True,'noop':True}
 if not tests:raise ValueError('no-safe-postcheck-targets')
 for name,value in [('sni-relay.conf',text),('probe.json',probe)]:
  f=backup/name;f.write_text(value);f.chmod(0o600)
 write(FILE,new)
 try:
  if not cmd(['nginx','-t']):raise ValueError('nginx-validation-failed')
  if not cmd(['systemctl','reload','nginx']):raise ValueError('nginx-reload-failed')
  for name in tests:
   if not tls(name):raise ValueError('sni-tls-postcheck-failed')
  write(PROBE,json.dumps(cfg,ensure_ascii=False,indent=2)+'\n')
 except Exception:
  write(FILE,text);write(PROBE,probe)
  restored=cmd(['nginx','-t']) and cmd(['systemctl','reload','nginx'])
  return {'ok':False,'rolled_back':restored,'error':'sni-validation-or-tls-check-failed','backup':str(backup)}
 return {'ok':True,'action':p['action'],'changed':changes,'target':p.get('target','original:443'),'tls_checked':tests,'backup':str(backup),'reload':'nginx-graceful','listeners_resolver_default_unchanged':True}
