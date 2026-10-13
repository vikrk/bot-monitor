"""Router RPC: describe and restart only explicitly listed Entware services."""
import pathlib,json,os,sys,subprocess,time,fcntl
ROOT=pathlib.Path('/opt/etc/rvkomi-ai-admin')
SERVICES={}  # Explicitly provisioned by portable_admin from the owner's profile.
def run(args,timeout=130):return subprocess.run(args,capture_output=True,text=True,timeout=timeout)
def state(name):
 r=run(['/opt/bin/sh',SERVICES[name],'status'],timeout=12)
 return {'active':r.returncode==0 and 'inactive' not in r.stdout and ('active' in r.stdout or 'running' in r.stdout),'status':r.stdout.strip()[:400]}
def describe():
 names=[n for n,p in SERVICES.items() if pathlib.Path(p).is_file()]
 return {'services':names,'service_states':{n:state(n) for n in names},'routing':False,'router':True,'uptime_seconds':int(float(pathlib.Path('/proc/uptime').read_text().split()[0]))}
def apply(plan):
 if not isinstance(plan,dict) or set(plan)!={'action','service'} or plan.get('action')!='restart_service' or plan.get('service') not in SERVICES:raise ValueError('unsupported-router-action')
 name=plan['service'];path=SERVICES[name]
 if not pathlib.Path(path).is_file():raise ValueError('service-not-installed')
 before=state(name)
 with (ROOT/'apply.lock').open('a') as lock:
  fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  if run(['/opt/bin/sh','-n',path],timeout=10).returncode:raise ValueError('init-script-invalid')
  result=run(['/opt/bin/sh',path,'restart']);time.sleep(3);after=state(name)
  answer={'ok':result.returncode==0 and after['active'],'action':'restart_service','service':name,'before':before,'after':after,'exit':result.returncode}
  with (ROOT/'audit.jsonl').open('a') as f:f.write(json.dumps({'time':time.time(),'result':answer})+'\n')
  (ROOT/'audit.jsonl').chmod(0o600)
  return answer
def main():
 if os.geteuid()!=0 or os.environ.get('SSH_ORIGINAL_COMMAND')!='rpc':raise ValueError('forced-rpc-only')
 raw=sys.stdin.buffer.read(16001)
 if len(raw)>16000:raise ValueError('request-too-large')
 req=json.loads(raw)
 if req=={'op':'describe'}:return describe()
 if isinstance(req,dict) and set(req)=={'op','plan'} and req['op']=='apply':return apply(req['plan'])
 raise ValueError('unsupported-request')
if __name__=='__main__':
 try:print(json.dumps(main(),ensure_ascii=False))
 except Exception as exc:print(json.dumps({'ok':False,'error':type(exc).__name__}));sys.exit(1)
