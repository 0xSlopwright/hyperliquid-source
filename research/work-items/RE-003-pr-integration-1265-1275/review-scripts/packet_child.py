import importlib,sys
from pathlib import Path
if __name__=='__main__':
 sys.path.insert(0,str(Path.cwd()/'tools'))
 tool=importlib.import_module(sys.argv[1])
 if hasattr(tool,'WORKERS'):tool.WORKERS=2
 raise SystemExit(tool.main(['--out',sys.argv[2]]))
