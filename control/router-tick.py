Attempting to perform the InitializeDefaultDrives operation on the 'FileSystem' provider failed.
#!/usr/bin/python3
import importlib.util,sys,json
from pathlib import Path
BASE=Path('/usr/local/lib/rvkomi-watchdog');sys.path.insert(0,str(BASE))
import home_monitor
s=importlib.util.spec_from_file_location('tc',BASE/'telegram-control.py');tc=importlib.util.module_from_spec(s);s.loader.exec_module(tc)
c=json.loads(Path('/etc/rvkomi-watchdog/telegram.json').read_text())
class Bot:
 nodes=tc.Nodes()
 def send(self,text):return tc.API(c).call('sendMessage',{'chat_id':int(c['chat_id']),'text':text[:3900]})
home_monitor.tick(Bot())

