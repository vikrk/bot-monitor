#!/usr/bin/python3
"""NL-hosted read-only checks of DNS/WWW/SPACE/LATVIA/FIN. Alerts only; never repairs."""
import concurrent.futures,fcntl,importlib.util,json,time
from pathlib import Path
import advanced
BASE=Path('/usr/local/lib/rvkomi-watchdog');ROOT=Path('/etc/rvkomi-watchdog');STATE=Path('/var/lib/rvkomi-watchdog')
def policy(previous,failures):
 old=previous.get('counters',{});counters={k:old.get(k,0)+1 for k in failures}
 persistent=sorted(k for k,v in counters.items() if v>=3)
 oldsig=previous.get('signature',[])
 return {'counters':counters,'signature':persistent or (oldsig if failures else [])},('failure' if persistent and persistent!=oldsig else 'recovery' if oldsig and not failures else None)
def main():
 s=importlib.util.spec_from_file_location('tc',BASE/'telegram-control.py');tc=importlib.util.module_from_spec(s);s.loader.exec_module(tc)
 import fleet,generic_control
 if fleet.enabled():return generic_control.monitor(tc)
 credentials=json.loads((ROOT/'telegram.json').read_text());api=tc.API(credentials);owner=int(credentials['chat_id']);nodes=tc.Nodes()
 STATE.mkdir(mode=0o700,parents=True,exist_ok=True)
 with (STATE/'extra-monitor.lock').open('a+') as lock:
  try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  except BlockingIOError:print(json.dumps({'skipped':'running'}));return
  path=STATE/'extra-monitor-state.json'
  try:state=json.loads(path.read_text())
  except FileNotFoundError:state={'hosts':{},'notifications':[]}
  def check(h):
   if advanced.read(STATE/'maintenance-central.json').get(h,{}).get('until',0)>time.time():return h,{'skipped':'maintenance'}
   try:
    r=nodes.call(h,'check');advanced.scheduled_record(None,h,r);return h,r
   except Exception as exc:
    result={'last_check':time.time(),'failures':['ssh-or-check-unavailable'],'error_type':type(exc).__name__,'error':'SSH/RPC check unavailable'}
    advanced.scheduled_record(None,h,result)
    return h,result
  summary={}
  with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
   for host,result in pool.map(check,tc.HOSTS):
    if result.get('skipped'):summary[host]={'skipped':result['skipped']};continue
    seen=set(state.get('seen_repair_events',[]))
    for repair in result.get('repair_events',[]):
     if repair.get('id') and repair['id'] not in seen:
      state['notifications'].append('🔧 '+host.upper()+': автоисправление '+str(repair.get('action'))+' — '+str(repair.get('outcome'))+'. ОС не перезагружалась.')
      seen.add(repair['id'])
    state['seen_repair_events']=sorted(seen)[-250:]
    failures=result.get('failures',['invalid-check-response']);new,event=policy(state['hosts'].get(host,{}),failures)
    new['last_check']=time.time();new['last_failures']=failures;state['hosts'][host]=new;summary[host]={'failures':failures}
    if event=='failure':state['notifications'].append('⚠️ '+host.upper()+': 3 подряд неудачные проверки: '+', '.join(new['signature'])+'. Подробности автоисправлений приходят отдельными сообщениями; ОС не перезагружается. DNS/CDN отражается отдельно.')
    elif event=='recovery':state['notifications'].append('✅ '+host.upper()+': проверки восстановились. Причины восстановления и автоисправления отражаются отдельно.')
  for host,data in advanced.collect('extras').items():
   if not data.get('error'):advanced.journal(host,data,'resources')
  with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ping_pool:
   for ping in ping_pool.map(tc.ping_target,tc.PING_TARGETS):
    host=next((h for h in tc.HOSTS if advanced.label(h)==ping['label']),None)
    if host:advanced.journal(host,ping,'ping')
  if not state.get('announced'):
   state['notifications'].append('✅ DNS, WWW, SPACE, LATVIA и FIN добавлены в мониторинг и команды проверки. Для этих пяти узлов нет reboot и автоисправления. Первые результаты: '+', '.join(h.upper()+(' OK' if not r.get('failures') and not r.get('skipped') else ' требует проверки') for h,r in summary.items()))
   state['announced']=True
  state['notifications']=state['notifications'][-30:];tc.atomic(path,state)
  kept=[]
  for idx,text in enumerate(state['notifications']):
   active=advanced.read(STATE/'maintenance-central.json')
   if any(d.get('until',0)>time.time() and (h.upper()+':') in text for h,d in active.items()):continue
   try:api.call('sendMessage',{'chat_id':owner,'text':text[:3900]},timeout=12)
   except RuntimeError:kept.extend(state['notifications'][idx:]);break
  state['notifications']=kept;tc.atomic(path,state)
  print(json.dumps({'checks':summary,'queued_notifications':len(kept),'read_only':True}))
if __name__=='__main__':
 try:main()
 except Exception as e:print(json.dumps({'monitor_error':type(e).__name__}));raise SystemExit(1)

