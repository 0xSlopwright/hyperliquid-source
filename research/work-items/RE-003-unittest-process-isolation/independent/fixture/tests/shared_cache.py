import atexit,json,os,sys
from pathlib import Path
buffers={}
shared=bytearray(262144)
def event(kind, **extra):
 data={"event":kind,"pid":os.getpid(),"ppid":os.getppid(),"optimize":sys.flags.optimize,"dont_write_bytecode":sys.flags.dont_write_bytecode,"registered":sorted(buffers),"retained_bytes":len(shared)+sum(len(x)for x in buffers.values()),**extra}
 with Path(os.environ["UTISO_PEER_EVENTS"]).open("a")as f:f.write(json.dumps(data,sort_keys=True)+"\n")
event("helper_import")
atexit.register(lambda:event("process_exit"))
