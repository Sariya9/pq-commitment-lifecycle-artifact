"""Compile and run the local-cancellation harness from retained input copies."""
import argparse,hashlib,json,platform,shutil,subprocess,time
from types import SimpleNamespace
from pathlib import Path
HERE=Path(__file__).resolve().parent
p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True)
p.add_argument('--openssl-prefix',type=Path,default=Path('/opt/homebrew/opt/openssl@3.6'));a=p.parse_args()
a.out.mkdir(parents=True,exist_ok=False);out=a.out.resolve()
src=out/'overlap_state.c';shutil.copy2(HERE/'overlap_state.c',src)
fixtures=out/'fixtures';fixtures.mkdir()
for n in ['server.crt','server.key','ca.crt']:shutil.copy2(HERE/'fixtures'/n,fixtures/n)
cc=shutil.which('cc');assert cc,'C compiler missing'
exe=out/'overlap_state'
compile_cmd=[cc,'-std=c11','-O1','-Wall','-Wextra','-o',str(exe),str(src),f'-I{a.openssl_prefix}/include',f'-L{a.openssl_prefix}/lib',f'-Wl,-rpath,{a.openssl_prefix}/lib','-lssl','-lcrypto']
run_cmd=[str(exe),str(fixtures/'server.crt'),str(fixtures/'server.key'),str(fixtures/'ca.crt')]
record={'source_sha256':hashlib.sha256(src.read_bytes()).hexdigest(),'fixtures':{q.name:hashlib.sha256(q.read_bytes()).hexdigest() for q in fixtures.iterdir()},'compile_command':compile_cmd,'run_command':run_cmd,'platform':platform.platform(),'expected':[{'preserve':86400,'restore':0},{'preserve':0,'restore':0},{'preserve':0,'restore':0},{'preserve':0,'restore':86400},{'preserve':86400,'restore':86400},{'preserve':0,'restore':0}]}
start=time.monotonic()
for name,command in [('compile',compile_cmd),('run',run_cmd)]:
 record['running_stage']=name
 (out/'manifest.json').write_text(json.dumps(record,indent=2)+'\n')
 try:
  result=subprocess.run(command,text=True,capture_output=True,timeout=60)
 except subprocess.TimeoutExpired as error:
  def decoded(value):return value.decode(errors='replace') if isinstance(value,bytes) else value or ''
  result=SimpleNamespace(returncode=124,stdout=decoded(error.stdout),stderr=decoded(error.stderr))
  record[name+'_timeout']=True
 (out/(name+'.stdout.log')).write_text(result.stdout);(out/(name+'.stderr.log')).write_text(result.stderr)
 record[name+'_exit']=result.returncode;record['elapsed_s']=round(time.monotonic()-start,3)
 (out/'manifest.json').write_text(json.dumps(record,indent=2)+'\n')
 print(name,result.returncode,result.stdout,flush=True)
 if result.returncode:raise SystemExit('Incomplete or failed harness; inspect saved logs')
assert result.stdout.count('CASE PASS')==6 and 'PASS: deterministic overlap' in result.stdout
