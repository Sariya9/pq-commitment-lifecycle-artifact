#!/usr/bin/env python3
"""Small finite-state cross-check for overlap_policy.spthy."""
import argparse, json
from collections import deque
from pathlib import Path

V, F = "VERIFIED", "FALSIFIED"
ID, SNAP, PHASE, CLS, MODE, START, CHECK, CHECKVIEW, ACCEPT, TICKET = range(10)
CLASSES = ("classical", "pq")
READY = ("ready", "ready0", "ready+")
QUERIES = (
    ("acceptance_time_policy", "all", 0),
    ("resumed_acceptance_time_policy", "all", 1),
    ("start_time_policy", "all", 2),
    ("abort_does_not_erase", "all", 3),
    ("full_acceptance_reachable", "exists", 4),
    ("resume_reachable", "exists", 5),
    ("checked_then_commit_then_classical", "exists", 6),
    ("ticket_delivered_after_commit", "exists", 7),
    ("abort_erases_other_connection", "exists", 8),
    ("full_classical_reachable_before_commit", "exists", 9),
    ("resume_classical_reachable_before_commit", "exists", 10),
)
EXPECTED = {
    "start": (F, F, V, V, V, V, V, V, F, V, V),
    "split": (F, F, V, V, V, V, V, V, F, V, V),
    "atomic": (V, V, V, V, V, V, F, V, F, V, V),
    "restore-abort": (F, F, F, F, V, V, V, V, V, V, V),
}
def conn(cid="-", snap="-", phase="idle", cls="-", mode="full",
         start=-1, check=-1, checkview="-", accept=-1, ticket="-"):
    return cid, snap, phase, cls, mode, start, check, checkview, accept, ticket
def pack(cache, full, resume, generation, bits):
    # Full IDs use start order; unobserved slot/ticket identities are abstracted.
    full = tuple(sorted(full, key=lambda x: (x[ID] == "-", x[ID])))
    return cache, full, resume, generation, bits
def replace(items, i, value):
    return items[:i] + (value,) + items[i + 1:]
def allowed(cache, cls):
    return cache == "none" or cls == "pq"
def successors(state, profile):
    cache, full, resume, generation, bits = state
    started = sum(x[PHASE] != "idle" for x in full)
    if started < len(full):
        i = next(i for i, x in enumerate(full) if x[PHASE] == "idle")
        cid = f"F{started}"
        y = conn(cid, cache, "waiting", mode="full", start=generation)
        yield f"{cid}: start full [snapshot={cache}]", pack(
            cache, replace(full, i, y), resume, generation, bits)
    for i, x in enumerate(full):
        cid, snap, phase, cls, mode, start, check, checkview, accept, ticket = x
        if phase == "waiting":
            for answer in CLASSES:
                if snap == "pq" and answer == "classical":
                    continue
                y = conn(cid, snap, "checking", answer, mode, start, ticket=ticket)
                yield f"{cid}: honest {answer} response", pack(
                    cache, replace(full, i, y), resume, generation, bits)
        elif phase == "checking":
            view = snap if profile == "start" else cache
            if allowed(view, cls):
                ready = "ready0" if cls == "classical" and view == "none" else "ready"
                y = conn(cid, snap, ready, cls, mode, start, generation, view,
                         ticket=ticket)
                yield f"{cid}: policy check [{view}]", pack(
                    cache, replace(full, i, y), resume, generation, bits)
        elif phase in READY:
            atomic = profile in ("atomic", "restore-abort")
            if not atomic or allowed(cache, cls):
                b = bits
                if cls == "classical":
                    b |= (1 << 0) if generation > 0 else 0
                    b |= (1 << 2) if snap == "pq" and start > 0 else 0
                    b |= (1 << 6) if checkview == "none" and check < generation else 0
                    b |= (1 << 9) if generation == 0 else 0
                    y = conn(cid, snap, "accepted", cls, mode, start, check,
                             checkview, generation, "pending")
                    nf, nc, ng = replace(full, i, y), cache, generation
                else:
                    b |= 1 << 4
                    ng = generation + 1
                    raised = tuple(conn(z[ID], z[SNAP],
                        "ready+" if z[PHASE] == "ready0" else z[PHASE], z[CLS],
                        z[MODE], z[START], z[CHECK], z[CHECKVIEW], z[ACCEPT],
                        "late" if z[TICKET] == "pending" else z[TICKET]) for z in full)
                    y = conn(cid, snap, "accepted", cls, mode, start, check,
                             checkview, ng, "pending")
                    nf, nc = replace(raised, i, y), "pq"
                yield f"{cid}: accept full [{cls}]", pack(nc, nf, resume, ng, b)
            after = snap if profile == "restore-abort" else cache
            b = bits | ((1 << 3) if after != cache else 0)
            b |= (1 << 8) if (snap == "none" and cache == "pq" and
                              generation > start and after == "none") else 0
            y = conn(cid, snap, "aborted", cls, mode, start, check, checkview,
                     accept, ticket)
            yield f"{cid}: abort [{cache}->{after}]", pack(
                after, replace(full, i, y), resume, generation, b)
        elif phase == "accepted" and ticket in ("pending", "late"):
            b = bits | ((1 << 7) if cls == "classical" and
                        ticket == "late" and accept < generation else 0)
            y = conn(cid, snap, phase, cls, mode, start, check, checkview,
                     accept, "issued")
            yield f"{cid}: issue {cls} ticket", pack(
                cache, replace(full, i, y), resume, generation, b)
    if resume[PHASE] == "idle":
        for origin in full:
            if origin[TICKET] == "issued":
                y = conn("R", cache, "waiting", origin[CLS], "resume", generation)
                yield f"R: start from {origin[ID]} {origin[CLS]} ticket [snapshot={cache}]", pack(
                    cache, full, y, generation, bits)
    elif resume[PHASE] == "waiting":
        y = conn("R", resume[SNAP], "checking", resume[CLS], "resume", resume[START])
        yield f"R: honest {resume[CLS]} response", pack(cache, full, y, generation, bits)
    elif resume[PHASE] == "checking":
        view = resume[SNAP] if profile == "start" else cache
        if allowed(view, resume[CLS]):
            ready = "ready0" if resume[CLS] == "classical" and view == "none" else "ready"
            y = conn("R", resume[SNAP], ready, resume[CLS], "resume",
                     resume[START], generation, view)
            yield f"R: policy check [{view}]", pack(cache, full, y, generation, bits)
    elif resume[PHASE] in READY:
        atomic = profile in ("atomic", "restore-abort")
        if not atomic or allowed(cache, resume[CLS]):
            b = bits
            if resume[CLS] == "classical":
                b |= (1 << 1) if generation > 0 else 0
                b |= (1 << 2) if resume[SNAP] == "pq" and resume[START] > 0 else 0
                b |= (1 << 10) if generation == 0 else 0
            else:
                b |= 1 << 5
            y = conn("R", resume[SNAP], "accepted", resume[CLS], "resume",
                     resume[START], resume[CHECK], resume[CHECKVIEW], generation)
            yield f"R: accept [{resume[CLS]}]", pack(cache, full, y, generation, b)
        after = resume[SNAP] if profile == "restore-abort" else cache
        b = bits | ((1 << 3) if after != cache else 0)
        y = conn("R", resume[SNAP], "aborted", resume[CLS], "resume",
                 resume[START], resume[CHECK], resume[CHECKVIEW], resume[ACCEPT])
        yield f"R: abort [{cache}->{after}]", pack(after, full, y, generation, b)
def trace(state, parent):
    actions = []
    while parent[state][0] is not None:
        previous, action = parent[state]
        actions.append(action)
        state = previous
    return list(reversed(actions))
def explore(profile, slots=3):
    initial = pack("none", (conn() for _ in range(slots)), conn(mode="resume"), 0, 0)
    queue, parent, hits = deque([initial]), {initial: (None, None)}, {}
    transitions = 0
    while queue:
        state = queue.popleft()
        for action, child in successors(state, profile):
            transitions += 1
            if child not in parent:
                parent[child] = state, action
                queue.append(child)
            new = child[4] & ~state[4]
            for _, _, bit in QUERIES:
                if new & (1 << bit) and bit not in hits:
                    hits[bit] = child
    properties = []
    for (name, kind, bit), expected in zip(QUERIES, EXPECTED[profile]):
        found = bit in hits
        outcome = (F if found else V) if kind == "all" else (V if found else F)
        properties.append({"query": name, "kind": kind, "outcome": outcome,
            "role": "structural_sanity" if bit == 3 else "property_or_control",
            "expected": expected, "expectation_source": "run.py" if bit < 9 else "control",
            "differs": outcome != expected,
            "shortest_action_trace": trace(hits[bit], parent) if found else None})
    return {"states": len(parent), "transitions": transitions, "properties": properties}


def self_test():
    split = explore("split", 2)["properties"]
    restore = explore("restore-abort", 2)["properties"]
    assert split[6]["outcome"] == V and split[0]["outcome"] == F
    assert restore[8]["outcome"] == V and restore[3]["outcome"] == F

    # Monitor regressions: history alone is not a PQ snapshot; only classical
    # delayed tickets and full-session aborts satisfy the corresponding queries.
    def after(state, prefix):
        matches = [child for action, child in successors(state, "restore-abort")
                   if action.startswith(prefix)]
        assert len(matches) == 1
        return matches[0]
    x = conn("F0", "none", "ready0", "classical", start=1, check=1, checkview="none")
    state = pack("none", (x,), conn(mode="resume"), 1, 0)
    assert not after(state, "F0: accept")[4] & (1 << 2)
    for cls in CLASSES:
        x = conn("F0", "none", "accepted", cls, accept=1, ticket="late")
        state = pack("pq", (x,), conn(mode="resume"), 2, 0)
        assert bool(after(state, "F0: issue")[4] & (1 << 7)) == (cls == "classical")
    r = conn("R", "none", "ready", "classical", "resume", start=1)
    assert not after(pack("pq", (), r, 2, 0), "R: abort")[4] & (1 << 8)
    x = conn("F0", "none", "ready", "pq", start=2)
    assert not after(pack("pq", (x,), conn(mode="resume"), 2, 0), "F0: abort")[4] & (1 << 8)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
    if not args.out:
        if args.self_test:
            return
        parser.error("--out is required unless --self-test is used")
    if args.out.exists():
        parser.error(f"refusing to overwrite {args.out}")
    result = {
        "scope": "Independent finite abstraction; neither Tamarin nor complete TLS.",
        "assumptions": {
            "sessions": "three full slots and one resumption slot at one endpoint",
            "responses": "honest already-valid classical or PQ responses; cryptography omitted",
            "policy": "start uses the snapshot; split uses current state at check; atomic rechecks at final",
            "tickets": "one optional ticket per accepted full origin; issuance may be delayed",
            "abort": "enabled only when ready; baseline preserves cache and restore-abort restores snapshot",
            "abort_query": "abort_does_not_erase is structural sanity; policy traces assess later acceptance",
            "monitor": "install generation plus per-session start, check and acceptance generations",
            "identity": "full IDs are alpha-normalised by start order; unused-slot names and same-class resumption-ticket identities are abstracted",
        },
        "profiles": {},
    }
    for name in EXPECTED:
        result["profiles"][name] = explore(name)
        print(name, result["profiles"][name]["states"], "states", flush=True)
    result["differences_from_run_py"] = [f"{profile}:{p['query']}"
        for profile, row in result["profiles"].items() for p in row["properties"]
        if p["expectation_source"] == "run.py" and p["differs"]]
    result["control_differences"] = [f"{profile}:{p['query']}"
        for profile, row in result["profiles"].items() for p in row["properties"]
        if p["expectation_source"] == "control" and p["differs"]]
    args.out.parent.mkdir(parents=True, exist_ok=True)
    try:
        with args.out.open("x", encoding="utf-8") as handle:
            json.dump(result, handle, indent=2)
            handle.write("\n")
    except FileExistsError:
        parser.error(f"refusing to overwrite {args.out}")


if __name__ == "__main__":
    main()
