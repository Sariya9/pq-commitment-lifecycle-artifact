"""Evaluate the declared observations independently on every primary-graph edge."""
import argparse,json,hashlib
from collections import deque
from pathlib import Path
import explore as model

def observe(before,action,after):
    cache,full,resume,generation,_=before
    actor,_,verb=action.partition(': ')
    if not verb.startswith(('accept','abort','issue')):return 0
    resumed=actor=='R'
    s=resume if resumed else next(x for x in full if x[model.ID]==actor)
    cls=s[model.CLS];mask=0
    if verb.startswith('accept'):
        if cls=='classical':
            if generation>0:mask|=1<<(1 if resumed else 0)
            if s[model.SNAP]=='pq' and s[model.START]>0:mask|=1<<2
            if generation==0:mask|=1<<(10 if resumed else 9)
            if not resumed and s[model.CHECKVIEW]=='none' and s[model.CHECK]<generation:mask|=1<<6
        elif cls=='pq':mask|=1<<(5 if resumed else 4)
    elif verb.startswith('abort'):
        if cache!=after[0]:mask|=1<<3
        if not resumed and s[model.SNAP]=='none' and cache=='pq' and after[0]=='none' and generation>s[model.START]:mask|=1<<8
    elif verb.startswith('issue') and cls=='classical' and s[model.ACCEPT]<generation:
        mask|=1<<7
    return mask

def check(before,action,after):
    wanted=before[4]|observe(before,action,after)
    assert after[4]==wanted,(action,after[4],wanted)

def audit(profile):
    initial=model.pack('none',(model.conn() for _ in range(3)),model.conn(mode='resume'),0,0)
    # Negative control: a false observation on the first edge must be rejected.
    action,child=next(model.successors(initial,profile))
    bad=(*child[:4],child[4]^(1<<0))
    try:check(initial,action,bad)
    except AssertionError:pass
    else:raise AssertionError('observer failed its corruption control')
    todo=deque([initial]);seen={initial};edges=0
    while todo:
        before=todo.popleft()
        for action,after in model.successors(before,profile):
            check(before,action,after);edges+=1
            if after not in seen:seen.add(after);todo.append(after)
    return {'states':len(seen),'checked_edges':edges,'status':'MATCH'}

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    if a.out.exists():p.error('output already exists')
    report={'scope':'Independent edge predicates over the primary finite graph; not a TLS proof',
            'explorer_sha256':hashlib.sha256(Path(model.__file__).read_bytes()).hexdigest(),
            'observer_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'profiles':{name:audit(name) for name in model.EXPECTED}}
    a.out.parent.mkdir(parents=True,exist_ok=True)
    with a.out.open('x') as f:json.dump(report,f,indent=2);f.write('\n')
    print(json.dumps(report,indent=2))
