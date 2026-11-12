"""Run the bounded cache-consumption follow-up on local memory BIOs only."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--out', type=Path, required=True)
parser.add_argument('--openssl-prefix', type=Path, default=Path('/opt/homebrew/opt/openssl@3.6'))
args = parser.parse_args()
args.out.mkdir(parents=True, exist_ok=False)
out = args.out.resolve()
prefix = args.openssl_prefix
openssl = prefix / 'bin/openssl'
expected = [
    ['loss-preserve', 86400, 'ECDSA', 'REJECT'],
    ['loss-restore', 0, 'ECDSA', 'ACCEPT'],
    ['loss-preserve-PQ', 86400, 'ML-DSA-65', 'ACCEPT'],
    ['loss-restore-PQ', 0, 'ML-DSA-65', 'ACCEPT'],
    ['withdraw-preserve', 0, 'ECDSA', 'ACCEPT'],
    ['withdraw-restore', 86400, 'ECDSA', 'REJECT'],
    ['withdraw-preserve-PQ', 0, 'ML-DSA-65', 'ACCEPT'],
    ['withdraw-restore-PQ', 86400, 'ML-DSA-65', 'ACCEPT'],
]
record = {'date': '25 October 2026', 'expected_probes': expected,
          'expected_active_failures': {'chain': 20, 'hostname': 62},
          'scope': 'Cache-dependent signature offers in laboratory policy probes; no network attacker or conforming post-zero availability claim.',
          'commands': [], 'status': 'INCOMPLETE'}

def run(stage, command):
    row = {'stage': stage, 'command': list(map(str, command)), 'timeout_s': 60}
    try:
        result = subprocess.run(row['command'], capture_output=True, text=True, timeout=60)
        stdout, stderr, code = result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired as error:
        def decoded(value):
            return value.decode(errors='replace') if isinstance(value, bytes) else value or ''
        stdout, stderr, code = decoded(error.stdout), decoded(error.stderr), 124
        row['timeout'] = True
    (out / (stage + '.stdout.log')).write_text(stdout)
    (out / (stage + '.stderr.log')).write_text(stderr)
    row['returncode'] = code
    record['commands'].append(row)
    (out / 'manifest.json').write_text(json.dumps(record, indent=2) + '\n')
    if code:
        raise SystemExit(f'Incomplete {stage}; inspect retained logs')
    return stdout

for name in ['policy_consumption.c', 'overlap_state.c']:
    shutil.copy2(HERE / name, out / name)
pq = out / 'pq-fixtures'
pq.mkdir()
for name in ['server.crt', 'server.key', 'ca.crt', 'manifest.json']:
    shutil.copy2(HERE / 'fixtures' / name, pq / name)
run('version', [openssl, 'version', '-a'])
run('pq-validity', [openssl, 'x509', '-in', pq / 'server.crt', '-checkend', '0', '-noout'])
ec = out / 'ec-fixtures'
ec.mkdir()
(ec / 'server.ext').write_text('subjectAltName=DNS:localhost\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n')
with tempfile.TemporaryDirectory() as temp:
    ca_key = Path(temp) / 'ca.key'
    run('ec-ca-key', [openssl, 'genpkey', '-algorithm', 'EC', '-pkeyopt',
                      'ec_paramgen_curve:P-256', '-out', ca_key])
    run('ec-ca', [openssl, 'req', '-new', '-x509', '-key', ca_key,
                  '-subj', '/CN=Policy-consumption laboratory CA', '-days', '365',
                  '-addext', 'basicConstraints=critical,CA:TRUE',
                  '-addext', 'keyUsage=critical,keyCertSign,cRLSign', '-out', ec / 'ca.crt'])
    run('ec-key', [openssl, 'genpkey', '-algorithm', 'EC', '-pkeyopt',
                  'ec_paramgen_curve:P-256', '-out', ec / 'server.key'])
    run('ec-csr', [openssl, 'req', '-new', '-key', ec / 'server.key',
                  '-subj', '/CN=unused.invalid', '-out', ec / 'server.csr'])
    run('ec-cert', [openssl, 'x509', '-req', '-in', ec / 'server.csr',
                   '-CA', ec / 'ca.crt', '-CAkey', ca_key, '-set_serial', '1',
                   '-days', '365', '-extfile', ec / 'server.ext', '-out', ec / 'server.crt'])
exe = out / 'policy_consumption'
run('compile', [shutil.which('cc') or 'cc', '-std=c11', '-O1', '-Wall', '-Wextra',
                '-o', exe, out / 'policy_consumption.c',
                f'-I{prefix}/include', f'-L{prefix}/lib', f'-Wl,-rpath,{prefix}/lib',
                '-lssl', '-lcrypto'])
stdout = run('run', [exe, pq / 'server.crt', pq / 'server.key', pq / 'ca.crt',
                      ec / 'server.crt', ec / 'server.key', ec / 'ca.crt'])
rows = re.findall(r'^PROBE (\S+) cache=(\d+) peer=(\S+) sigalgs=(\S+) result=(ACCEPT|REJECT)', stdout, re.M)
actual = [[name, int(cache), peer, outcome] for name, cache, peer, schemes, outcome in rows]
assert actual == expected, actual
failures = dict((name, int(code)) for name, code in
                re.findall(r'^ACTIVE-FAILURE (\S+) cache=86400/86400 verification=(\d+)', stdout, re.M))
assert failures == record['expected_active_failures']
assert 'PASS: eight policy-consumption probes and two active-cache failure controls' in stdout
record['probes'] = [dict(name=name, cache=int(cache), peer=peer, sigalgs=schemes, outcome=outcome)
                    for name, cache, peer, schemes, outcome in rows]
record['source_sha256'] = {name: hashlib.sha256((out / name).read_bytes()).hexdigest()
                           for name in ['policy_consumption.c', 'overlap_state.c']}
record['fixtures_sha256'] = {str(p.relative_to(out)): hashlib.sha256(p.read_bytes()).hexdigest()
                            for root in [pq, ec] for p in root.iterdir() if p.is_file()}
record['status'] = 'COMPLETE'
(out / 'manifest.json').write_text(json.dumps(record, indent=2) + '\n')
print(stdout)
