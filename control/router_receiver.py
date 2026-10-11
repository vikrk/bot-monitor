#!/usr/bin/python3
import http.server,json,time,hmac,os,threading
from pathlib import Path
ROOT=Path('/etc/rvkomi-watchdog'); STATE=Path('/var/lib/rvkomi-watchdog'); LOCK=threading.Lock()
TOKEN=json.loads((ROOT/'router-agent.json').read_text())['token']
def read(p):
 try:return json.loads(p.read_text())
 except (OSError,ValueError):return {}
def atomic(p,d):
 t=p.with_suffix('.new');t.write_text(json.dumps(d,ensure_ascii=False));t.chmod(0o600);os.replace(t,p)
class Handler(http.server.BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def reply(self,status,data):
  b=json.dumps(data).encode();self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Cache-Control','no-store');self.send_header('Content-Length',str(len(b)));self.end_headers();self.wfile.write(b)
 def auth(self):return hmac.compare_digest(self.headers.get('Authorization',''),'Bearer '+TOKEN)
 def do_GET(self):
  if not self.auth():self.reply(403,{'error':'denied'});return
  if self.path!='/task':self.reply(404,{});return
  with LOCK:
   c=read(STATE/'router-task.json');r=read(STATE/'router-state.json');r['last_heartbeat']=time.time();atomic(STATE/'router-state.json',r)
  task=c.get('id') if time.time()-c.get('requested',0)<600 else None
  self.reply(200,{'task_id':task,'yandex_enabled':read(STATE/'router-settings.json').get('yandex_enabled',False),'server_time':time.time()})
 def do_POST(self):
  if not self.auth():self.reply(403,{'error':'denied'});return
  if self.path!='/report':self.reply(404,{});return
  try:
   n=int(self.headers.get('Content-Length','0'))
   if not 0<n<=65536:raise ValueError()
   d=json.loads(self.rfile.read(n));assert isinstance(d,dict)
   if d.get('version')!=1 or not isinstance(d.get('resources'),dict):raise ValueError()
   if not isinstance(d.get('checks',{}),dict) or len(d.get('checks',{}))>16:raise ValueError()
   with LOCK:
    d['received']=time.time();d['last_heartbeat']=time.time();atomic(STATE/'router-state.json',d)
   self.reply(200,{'ok':True})
  except Exception:self.reply(400,{'error':'invalid-report'})
if __name__=='__main__':http.server.ThreadingHTTPServer(('127.0.0.1',19891),Handler).serve_forever()

