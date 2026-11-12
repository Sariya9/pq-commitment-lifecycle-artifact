"""Bounded full-response offer control; leaves the original explorer unchanged."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent

def load_model(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    source_path = HERE / 'explore.py'
    source = source_path.read_text()
    (args.out / 'explore.py').write_text(source)
    (args.out / 'offer_control.py').write_bytes(Path(__file__).read_bytes())
    source_hash = hashlib.sha256(source.encode()).hexdigest()
    assert source_hash == '4c0fc0e9a6ec11dfaae6a4a0d5a5115dc243d23aba1134e9d9198bf4afead78a'
    old = '            for answer in CLASSES:\n'
    assert source.count(old) == 1
    restricted = source.replace(old, old +
        '                if snap == "pq" and answer == "classical":\n'
        '                    continue\n')
    snapshot = args.out / 'explore_restricted.py'
    snapshot.write_text(restricted)
    baseline = load_model(source_path, 'original_offer_model')
    model = load_model(snapshot, 'restricted_offer_model')
    # A PQ full start excludes a classical reply; PSK origins stay independent.
    for snap, expected in [('pq', {'pq'}), ('none', {'pq', 'classical'})]:
        full = model.conn('F0', snap, 'waiting', start=1)
        state = model.pack(snap, (full,), model.conn(mode='resume'), 1, 0)
        original_answers = {child[1][0][model.CLS]
                            for _, child in baseline.successors(state, 'atomic')}
        assert original_answers == {'pq', 'classical'}
        answers = {child[1][0][model.CLS] for _, child in model.successors(state, 'atomic')}
        assert answers == expected
    resume = model.conn('R', 'pq', 'waiting', 'classical', 'resume', start=1)
    state = model.pack('pq', (), resume, 1, 0)
    assert any(child[2][model.CLS] == 'classical'
               for _, child in model.successors(state, 'atomic'))
    expectation = {
        'aggregate_outcomes': 'The original eleven outcomes per profile should remain unchanged.',
        'restore_start_witness': 'Must no longer use a classical full response to a PQ-only start.',
        'PSK': 'A classical-origin resumption can still violate the selected start-origin contract.',
    }
    (args.out / 'expectations.json').write_text(json.dumps(expectation, indent=2) + '\n')
    report = {'scope': 'Three full attempts and one secure-origin resumption; no expiry or withdrawal.',
              'date': '25 October 2026', 'command': sys.argv, 'python': sys.version,
              'runner_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'baseline_sha256': source_hash,
              'restricted_sha256': hashlib.sha256(restricted.encode()).hexdigest(),
              'change': 'Only classical full replies to a recorded PQ snapshot are excluded.',
              'expectations': expectation, 'profiles': {}}
    for profile in model.EXPECTED:
        row = model.explore(profile)
        assert all(not q['differs'] for q in row['properties']), profile
        for q in row['properties']:
            trace = q['shortest_action_trace'] or []
            snapshots = {}
            for action in trace:
                actor = action.partition(':')[0]
                if ': start full ' in action:
                    snapshots[actor] = 'pq' if 'snapshot=pq' in action else 'none'
                if ': honest classical response' in action and actor != 'R':
                    assert snapshots.get(actor) != 'pq', trace
            # Re-evaluate every decisive schedule against the restricted transition relation.
            current = model.pack('none', (model.conn() for _ in range(3)),
                                 model.conn(mode='resume'), 0, 0)
            for action in trace:
                children = [child for label, child in model.successors(current, profile)
                            if label == action]
                assert len(children) == 1, action
                current = children[0]
        report['profiles'][profile] = row
        print(profile, row['states'], 'states', row['transitions'], 'edges', flush=True)
    start = next(q for q in report['profiles']['restore-abort']['properties']
                 if q['query'] == 'start_time_policy')
    assert start['outcome'] == model.F
    assert 'R: accept [classical]' in start['shortest_action_trace']
    report['status'] = 'COMPLETE'
    report['aggregate_expectations_met'] = True
    (args.out / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: all 44 aggregate outcomes retained; start witness uses the PSK interface.')

if __name__ == '__main__':
    main()
