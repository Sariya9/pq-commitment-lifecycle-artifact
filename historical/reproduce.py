"""Sequential, bounded reproduction of the selected retained paper evidence."""
import hashlib
import json
from pathlib import Path
import platform
import shutil
import subprocess
import sys

PROJECT = Path('/Users/sammo/Downloads/Research/pq_auth_negotiation')
OUT = Path(__file__).resolve().parent / 'reproduction'
OUT.mkdir(exist_ok=False)
PYTHON = sys.executable
PREFIX = Path('/opt/homebrew/opt/openssl@3.6')
record = {'date': '25 October 2026', 'python': sys.version,
          'platform': platform.platform(), 'commands': [], 'checks': {}}

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def run(name, command, cwd=PROJECT, timeout=120):
    log = OUT / 'commands' / name
    log.mkdir(parents=True, exist_ok=False)
    row = {'command': list(map(str, command)), 'cwd': str(cwd), 'timeout_s': timeout}
    try:
        result = subprocess.run(row['command'], cwd=cwd, capture_output=True,
                                text=True, timeout=timeout)
        row['returncode'] = result.returncode
        (log / 'stdout.log').write_text(result.stdout)
        (log / 'stderr.log').write_text(result.stderr)
    except subprocess.TimeoutExpired as error:
        row['returncode'] = 124
        for stream in ['stdout', 'stderr']:
            value = getattr(error, stream) or ''
            if isinstance(value, bytes):
                value = value.decode(errors='replace')
            (log / (stream + '.log')).write_text(value)
    record['commands'].append(row)
    (OUT / 'manifest.json').write_text(json.dumps(record, indent=2) + '\n')
    assert row['returncode'] == 0, (name, row)
    print(name, 'PASS', flush=True)

def snapshot(name, source):
    dest = OUT / name / source.name
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, dest)
    assert sha(dest) == sha(source)
    return dest

for name, command in [('python', [PYTHON, '--version']),
                      ('tamarin', ['tamarin-prover', '--version']),
                      ('maude', ['maude', '--version']),
                      ('openssl', [PREFIX / 'bin/openssl', 'version', '-a'])]:
    run(name, command)

models = PROJECT / 'model/overlap_policy'
primary = snapshot('finite', models / 'runs/2026-09-26-finite/explore.py')
run('finite', [PYTHON, primary, '--self-test', '--out', primary.parent / 'results.json'])
ref = snapshot('reference', models / 'reference_check.py')
snapshot('reference', models / 'overlap_policy.spthy')
run('reference-self-test', [PYTHON, ref, '--self-test'])
run('reference', [PYTHON, ref, '--out', ref.parent / 'results.json'])
audit = snapshot('edge-audit', models / 'audit_monitors.py')
snapshot('edge-audit', primary)
run('edge-audit', [PYTHON, audit, '--out', audit.parent / 'results.json'])

for name, historic, options in [
    ('lifecycle', '2026-09-26-lifecycle-final', []),
    ('response-control', '2026-09-26-lifecycle-response-control',
     ['--enforce-start-offer', '--no-pq-omission'])]:
    source = snapshot(name, models / 'runs' / historic / 'lifecycle_check.py')
    run(name, [PYTHON, source, '--self-test', *options,
               '--out', source.parent / 'results.json'])
    fresh = json.loads((source.parent / 'results.json').read_text())
    old = json.loads((models / 'runs' / historic / 'results.json').read_text())
    assert fresh['all_expectations_met']
    assert fresh['profiles'] == old['profiles']
    record['checks'][name] = 'Exact states, transitions, verdicts and traces reproduced'

sys.path.insert(0, str(PROJECT))
from verify import run_model
selected = json.loads((PROJECT / 'model/cache_transaction/runs/reconciled-2026-09-10.json').read_text())
completed = [r for r in selected if r['status'] == 'OK']
assert len(completed) == 15
for index, old in enumerate(completed):
    name = 'cache_transaction_no_cv.spthy' if old['case'] == 'no_cv' else 'cache_transaction.spthy'
    source = PROJECT / 'model/cache_transaction' / name
    assert sha(source) == old['source_sha256']
    result = run_model(source, OUT / 'tamarin' / f'{index:02d}-{old["case"]}',
                       lemmas=[old['query']], flags=['EARLY_CLEAR'] if old['case'] == 'early' else [],
                       heuristic='S', timeout=120)
    assert result['status'] == 'OK' and result['results'] == old['results'], result
    print('tamarin', old['case'], old['query'], result['results'][0]['verdict'], flush=True)
record['checks']['tamarin'] = '15 exact source hashes and selected verdict/step records reproduced'

run('overlap-runner-test', [PYTHON, PROJECT / 'experiments/overlap_state/test_runner.py'])
run('overlap-runtime', [PYTHON, PROJECT / 'experiments/overlap_state/run.py',
                       '--out', OUT / 'overlap-runtime'])

finished = snapshot('finished/finished_state', PROJECT / 'experiments/finished_state/finished_state.c')
for name in ['server.crt', 'server.key', 'ca.crt']:
    snapshot('finished/testbed', PROJECT / 'experiments/testbed' / name)
exe = finished.parent / 'finished_state'
run('finished-compile', ['cc', '-std=c11', '-O1', '-Wall', '-Wextra', '-o', exe, finished,
                       f'-I{PREFIX}/include', f'-L{PREFIX}/lib',
                       f'-Wl,-rpath,{PREFIX}/lib', '-lssl', '-lcrypto'])
run('finished-runtime', [exe], cwd=finished.parent, timeout=60)
assert 'PASS: only the SSL_is_init_finished policy' in (OUT / 'commands/finished-runtime/stdout.log').read_text()

fresh = json.loads((primary.parent / 'results.json').read_text())
old = json.loads((models / 'runs/2026-09-26-finite/results.json').read_text())
assert fresh['profiles'] == old['profiles']
reference = json.loads((ref.parent / 'results.json').read_text())
assert reference['status'] == 'COMPLETE' and reference['all_expectations_met']
for profile, data in fresh['profiles'].items():
    want = {r['query']: r['outcome'] for r in data['properties']}
    got = {r['query']: r['outcome'] for r in reference['profiles'][profile]['verdicts']}
    assert want == got
edges = json.loads((audit.parent / 'results.json').read_text())
assert sum(r['checked_edges'] for r in edges['profiles'].values()) == 308794
record['checks'].update(finite='44 exact primary results and traces reproduced; reference agrees',
                        edges='308794 edges checked with corruption negative control',
                        runtime='Five Finished cases and six overlap cases passed')
record['source_manifest'] = {str(p.relative_to(OUT)): sha(p) for p in OUT.rglob('*')
                             if p.is_file() and p.suffix in ['.py', '.spthy', '.c', '.crt', '.key']}
record['status'] = 'COMPLETE'
(OUT / 'manifest.json').write_text(json.dumps(record, indent=2) + '\n')
print('ALL SELECTED REPRODUCTION CHECKS PASSED', flush=True)
