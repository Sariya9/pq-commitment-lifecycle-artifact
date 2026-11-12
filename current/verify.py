#!/usr/bin/env python3
"""Sequential, logged verification for this project's .spthy and .pv models.

A completed false query is a result, not a tool failure. Consumers must compare
the recorded verdict to their predeclared expectation before claiming success.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import subprocess
import time


def verdicts(output, suffix, lemmas=()):
    if suffix == '.pv':
        return [dict(query=query, verdict=(value or 'CANNOT BE PROVED').upper())
                for query, value in re.findall(
                    r'^RESULT (?!\(even )(.+?) (?:is (true|false)|cannot be proved)\.$',
                    output, re.M)]
    return [dict(query=name, verdict=value.upper(), steps=int(steps))
            for name, value, steps in re.findall(
                r'^\s{2}(\w+) \((?:all-traces|exists-trace)\): '
                r'(verified|falsified)[^\n]*?\((\d+) steps?\)', output, re.M)
            if not lemmas or name in lemmas]


def run_model(model, destination, *, lemmas=(), flags=(), heuristic='I', timeout=120,
              parse_only=False, binary=None):
    """One process group at a time; retain input, command, both streams and status."""
    model, destination = Path(model).resolve(), Path(destination)
    flags = tuple(flags)
    destination.mkdir(parents=True, exist_ok=False)
    source = model.read_bytes()
    snapshot = destination / model.name
    snapshot.write_bytes(source)
    tool = binary or ('proverif' if model.suffix == '.pv' else 'tamarin-prover')
    executable = shutil.which(tool)
    args = [executable or tool]
    if model.suffix == '.spthy':
        args += [f'-D={f}' for f in flags]
        if not parse_only:
            args += [f'--prove={name}' for name in lemmas] if lemmas else ['--prove']
            args += [f'--heuristic={heuristic}']
    args += [str(snapshot.resolve())]
    if model.suffix == '.spthy':
        args += ['+RTS', '-N2', '-M6G', '-RTS']
    record = dict(source=str(model), sha256=hashlib.sha256(source).hexdigest(),
                  command=args, flags=list(flags), heuristic=heuristic,
                  timeout_s=timeout, parse_only=parse_only)
    if executable:
        record['tool_sha256'] = hashlib.sha256(Path(executable).read_bytes()).hexdigest()
    (destination / 'command.txt').write_text(shlex.join(args) + '\n')
    start = time.monotonic()
    stdout = stderr = ''
    status, code = 'TOOL_MISSING', None
    if executable:
        proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, start_new_session=True, cwd=model.parent)
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
            status = 'OK' if proc.returncode == 0 else 'TOOL_ERROR'
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            stdout, stderr = proc.communicate()
            status = 'TIMEOUT'
        code = proc.returncode
    output = stdout + '\n' + stderr
    results = verdicts(output, model.suffix, lemmas)
    if status == 'OK':
        if re.search(r'wellformedness checks? (?:failed|fail)', output, re.I):
            status = 'WELLFORMEDNESS_ERROR'
        elif re.search(r'(?m)^(?:Error:|Fatal error:)', output):
            status = 'PARSE_ERROR'
        elif parse_only:
            if 'All wellformedness checks were successful' not in output:
                status = 'PARSE_UNCONFIRMED'
        else:
            expected = (len(lemmas) if lemmas else
                        len(re.findall(r'^lemma\s+\w+', source.decode(), re.M)))
            if model.suffix == '.pv':
                # These files use one query per declaration. A change to grouped
                # queries must update this count rather than silently omit results.
                expected = len(re.findall(r'^query\b', source.decode(), re.M))
            if not results or len(results) != expected:
                status = 'MISSING_RESULTS'
            elif any(r['verdict'] == 'CANNOT BE PROVED' for r in results):
                status = 'INCONCLUSIVE'
    record.update(status=status, returncode=code, elapsed_s=round(time.monotonic()-start, 3),
                  results=results)
    (destination / 'stdout.log').write_text(stdout)
    (destination / 'stderr.log').write_text(stderr)
    (destination / 'result.json').write_text(json.dumps(record, indent=2) + '\n')
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('models', type=Path, nargs='+')
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--lemma', action='append', default=[])
    parser.add_argument('--flags', default='')
    parser.add_argument('--heuristic', default='I')
    parser.add_argument('--timeout', type=float, default=120)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    runs = []
    for i, model in enumerate(args.models):
        run = run_model(model, args.out/f'{i:02d}-{model.stem}', lemmas=args.lemma,
                        flags=filter(None, args.flags.split(',')),
                        heuristic=args.heuristic, timeout=args.timeout)
        runs.append(run)
        (args.out/'results.json').write_text(json.dumps(runs, indent=2) + '\n')
        print(model.name, run['status'], [r['verdict'] for r in run['results']], flush=True)
        if run['status'] != 'OK':
            return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
