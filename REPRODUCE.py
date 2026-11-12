"""Check the evidence manifest or reproduce the selected checks after extraction."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def check_manifest(root, entries):
    for name, expected in entries.items():
        path = (root / name).resolve()
        if not path.is_relative_to(root.resolve()) or not path.is_file():
            raise ValueError('Missing or unsafe member: ' + name)
        if digest(path) != expected:
            raise ValueError('Member hash mismatch: ' + name)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument('--check', action='store_true', help='verify bytes without running experiments')
    parser.add_argument('--run', action='store_true')
    parser.add_argument('--out', type=Path)
    parser.add_argument('--openssl-prefix', type=Path, default=Path('/opt/homebrew/opt/openssl@3.6'))
    args = parser.parse_args()
    root = args.root.resolve()
    manifest = json.loads((root / 'MANIFEST.json').read_text())
    check_manifest(root, manifest)
    bad = dict(manifest)
    bad[next(iter(bad))] = '0' * 64
    try:
        check_manifest(root, bad)
    except ValueError:
        pass
    else:
        raise AssertionError('corrupted-hash control was accepted')
    print('PASS: all', len(manifest), 'members verified; corrupt hash rejected', flush=True)
    if not args.run:
        return
    if args.out is None:
        parser.error('--run requires --out')
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    current = root / 'current'
    python = sys.executable
    record = {'status': 'INCOMPLETE', 'root': str(root), 'python': sys.version,
              'command': sys.argv, 'commands': [], 'checks': {}}

    def run(name, command, cwd=current, timeout=120):
        logs = out / 'commands' / name
        logs.mkdir(parents=True, exist_ok=False)
        row = {'command': list(map(str, command)), 'cwd': str(cwd), 'timeout_s': timeout}
        try:
            result = subprocess.run(row['command'], cwd=cwd, capture_output=True,
                                    text=True, timeout=timeout)
            stdout, stderr, code = result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired as error:
            def decoded(value):
                return value.decode(errors='replace') if isinstance(value, bytes) else value or ''
            stdout, stderr, code = decoded(error.stdout), decoded(error.stderr), 124
            row['timeout'] = True
        except OSError as error:
            stdout, stderr, code = '', str(error), 127
        (logs / 'stdout.log').write_text(stdout)
        (logs / 'stderr.log').write_text(stderr)
        row['returncode'] = code
        record['commands'].append(row)
        (out / 'manifest.json').write_text(json.dumps(record, indent=2) + '\n')
        if code:
            raise SystemExit('Incomplete ' + name + '; see retained logs')
        print(name, 'PASS', flush=True)
        return stdout

    for name, command in [('tamarin-version', ['tamarin-prover', '--version']),
                          ('maude-version', ['maude', '--version']),
                          ('openssl-version', [args.openssl_prefix / 'bin/openssl', 'version', '-a'])]:
        run(name, command)
    model = current / 'model/overlap_policy'
    run('finite', [python, model / 'explore.py', '--self-test', '--out', out / 'finite.json'])
    run('reference-self-test', [python, model / 'reference_check.py', '--self-test'])
    run('reference', [python, model / 'reference_check.py', '--out', out / 'reference.json'])
    run('edge-audit', [python, model / 'audit_monitors.py', '--out', out / 'edge-audit.json'])
    for name, historic, options in [
        ('lifecycle', '2026-09-26-lifecycle-final', []),
        ('restricted-lifecycle', '2026-09-26-lifecycle-response-control',
         ['--enforce-start-offer', '--no-pq-omission'])]:
        source = root / 'original/model/overlap_policy/runs' / historic / 'lifecycle_check.py'
        run(name, [python, source, '--self-test', *options, '--out', out / (name + '.json')])
        report = json.loads((out / (name + '.json')).read_text())
        assert report['status'] == 'COMPLETE' and report['all_expectations_met']
    run('offer-control', [python, model / 'offer_control.py', '--out', out / 'offer-control'])
    sys.path.insert(0, str(current))
    from verify import run_model
    selected = json.loads((current / 'model/cache_transaction/runs/reconciled-2026-09-10.json').read_text())
    selected = [row for row in selected if row['status'] == 'OK']
    assert len(selected) == 15
    for index, old in enumerate(selected):
        source = current / 'model/cache_transaction' / (
            'cache_transaction_no_cv.spthy' if old['case'] == 'no_cv' else 'cache_transaction.spthy')
        assert digest(source) == old['source_sha256']
        result = run_model(source, out / 'tamarin' / f'{index:02d}-{old["case"]}',
                           lemmas=[old['query']], flags=['EARLY_CLEAR'] if old['case'] == 'early' else [],
                           heuristic='S', timeout=120)
        assert result['status'] == 'OK' and result['results'] == old['results'], result
        print('tamarin', old['case'], old['query'], 'PASS', flush=True)
    overlap = current / 'experiments/overlap_state'
    run('overlap-runner-self-test', [python, overlap / 'test_runner.py'])
    run('overlap-runtime', [python, overlap / 'run.py', '--out', out / 'overlap-runtime',
                            '--openssl-prefix', args.openssl_prefix])
    run('policy-consumption', [python, overlap / 'run_consumption.py',
                               '--out', out / 'policy-consumption',
                               '--openssl-prefix', args.openssl_prefix])
    work = out / 'finished'
    source = work / 'finished_state'
    fixtures = work / 'testbed'
    source.mkdir(parents=True)
    fixtures.mkdir()
    shutil.copy2(current / 'experiments/finished_state/finished_state.c', source / 'source.c')
    for name in ['server.crt', 'server.key', 'ca.crt']:
        shutil.copy2(current / 'experiments/testbed' / name, fixtures / name)
    exe = source / 'finished_state'
    run('finished-compile', [shutil.which('cc') or 'cc', '-std=c11', '-O1', '-Wall', '-Wextra',
                             '-o', exe, source / 'source.c',
                             f'-I{args.openssl_prefix}/include', f'-L{args.openssl_prefix}/lib',
                             f'-Wl,-rpath,{args.openssl_prefix}/lib', '-lssl', '-lcrypto'])
    stdout = run('finished-runtime', [exe], cwd=source, timeout=60)
    assert stdout.count('CASE PASS') == 5
    finite = json.loads((out / 'finite.json').read_text())
    reference = json.loads((out / 'reference.json').read_text())
    edges = json.loads((out / 'edge-audit.json').read_text())
    assert reference['status'] == 'COMPLETE' and reference['all_expectations_met']
    for profile, data in finite['profiles'].items():
        assert {r['query']: r['outcome'] for r in data['properties']} == {
            r['query']: r['outcome'] for r in reference['profiles'][profile]['verdicts']}
    assert sum(r['checked_edges'] for r in edges['profiles'].values()) == 308794
    check_manifest(root, manifest)
    record['status'] = 'COMPLETE'
    record['checks'] = {'symbolic_queries': 15, 'primary_outcomes': 44,
                        'lifecycle_outcomes': 14, 'restricted_lifecycle_outcomes': 14,
                        'offer_control_outcomes': 44, 'monitor_edges': 308794,
                        'finished_cases': 5, 'overlap_cases': 6,
                        'consumption_probes': 8, 'active_cache_failure_controls': 2}
    (out / 'manifest.json').write_text(json.dumps(record, indent=2) + '\n')
    print('PASS: selected portable recipe complete; original packaged inputs unchanged', flush=True)

if __name__ == '__main__':
    main()
