"""Bounded overlap pilot. Runs sequentially; expected false is a scientific result."""
import argparse, json, sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from verify import run_model
V='VERIFIED';F='FALSIFIED'
Q=['acceptance_time_policy','resumed_acceptance_time_policy','start_time_policy',
   'abort_does_not_erase','full_acceptance_reachable','resume_reachable',
   'checked_then_commit_then_classical','ticket_delivered_after_commit',
   'abort_erases_other_connection']
CASES={'start':(['START_POLICY'],[F,F,V,V,V,V,V,V,F]),
       'split':(['SPLIT_POLICY'],[F,F,V,V,V,V,V,V,F]),
       'atomic':(['ATOMIC_POLICY'],[V,V,V,V,V,V,F,V,F]),
       'restore-abort':(['ATOMIC_POLICY','RESTORE_ON_ABORT'],[F,F,F,F,V,V,V,V,V])}
p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);p.add_argument('--case',choices=CASES,action='append');p.add_argument('--query',choices=Q,action='append');p.add_argument('--timeout',type=float,default=60);p.add_argument('--heuristic',default='I');a=p.parse_args()
a.out.mkdir(parents=True,exist_ok=False)
(a.out/'expectations.json').write_text(json.dumps({'queries':Q,'cases':CASES},indent=2)+'\n')
rows=[]
for name,(flags,expect) in CASES.items():
 if a.case and name not in a.case:continue
 for q,want in zip(Q,expect):
  if a.query and q not in a.query:continue
  r=run_model(Path(__file__).with_name('overlap_policy.spthy'),a.out/name/q,lemmas=[q],flags=flags,heuristic=a.heuristic,timeout=a.timeout)
  got=r['results'][0]['verdict'] if r['status']=='OK' else None
  rows.append(dict(case=name,query=q,expected=want,result=r,expectation_met=got==want))
  (a.out/'results.json').write_text(json.dumps(rows,indent=2)+'\n')
  print(name,q,r['status'],got,'expected',want,flush=True)
  if got!=want:raise SystemExit('Unexpected/incomplete pilot result; inspect retained output.')
