"""Sequential predeclared controls for the bounded cache transaction component."""
import argparse
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from verify import run_model
HERE = Path(__file__).resolve().parent
parser = argparse.ArgumentParser()
parser.add_argument('--out', required=True, type=Path)
parser.add_argument('--timeout', type=float, default=120)
parser.add_argument('--heuristic', default='S')
parser.add_argument('--only-case', action='append', default=[])
parser.add_argument('--only-query', action='append', default=[])
args = parser.parse_args()
args.out.mkdir(parents=True, exist_ok=False)
source = (HERE/'cache_transaction.spthy').read_text()
old = "Eq(verify(sig,<'cv',$S,~n,value,key,cert>,key),true)"
assert source.count(old) == 1
mutant = HERE/'cache_transaction_no_cv.spthy'
# Keep the common authentication/clearing observations when deleting the check.
mutant.write_text(source.replace(old+'\n , ', ''))
queries = ['clearing_has_matching_server', 'abort_preserves_established_cache',
           'establishment_reachable', 'legitimate_withdrawal_reachable',
           'aborted_withdrawal_retains_protection', 'reconnect_after_abort_reachable']
cases = [dict(name='safe', model='cache_transaction.spthy', flags=[], expected=['VERIFIED']*6),
         dict(name='early', model='cache_transaction.spthy', flags=['EARLY_CLEAR'],
              expected=['FALSIFIED','FALSIFIED','VERIFIED','VERIFIED','FALSIFIED','FALSIFIED']),
         dict(name='no_cv', model=mutant.name, flags=[],
              expected=['FALSIFIED','VERIFIED','VERIFIED','VERIFIED','VERIFIED','VERIFIED'])]
(args.out/'expectations.json').write_text(json.dumps(cases,indent=2)+'\n')
if set(args.only_case)-{c['name'] for c in cases}: parser.error('unknown case')
if set(args.only_query)-set(queries): parser.error('unknown query')
rows = []
for case in cases:
    if args.only_case and case['name'] not in args.only_case: continue
    selected = []
    for query, expected in zip(queries, case['expected']):
        if args.only_query and query not in args.only_query: continue
        r = run_model(HERE/case['model'], args.out/case['name']/query, lemmas=[query],
                      flags=case['flags'], timeout=args.timeout, heuristic=args.heuristic)
        actual = {q['query']:q['verdict'] for q in r['results']}
        matches = r['status']=='OK' and actual.get(query)==expected
        selected.append(dict(query=query, result=r, expectation_met=matches))
        (args.out/(case['name']+'.json')).write_text(json.dumps(selected,indent=2)+'\n')
        print(case['name'],query,r['status'],actual,'expectation_met',matches,flush=True)
        if not matches: raise SystemExit('Unexpected or incomplete run. Inspect before continuing.')
    rows.append(dict(case=case, runs=selected))
    (args.out/'results.json').write_text(json.dumps(rows,indent=2)+'\n')
