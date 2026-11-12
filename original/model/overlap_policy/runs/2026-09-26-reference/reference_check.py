#!/usr/bin/env python3
"""Concrete finite checker: honest valid responses, IDs never quotiented."""
import argparse
import hashlib
import json
from collections import deque
from pathlib import Path
NONE, PQ = 0, 1
CLASSICAL = 0
UNUSED, STARTED, RESPONDED, READY, DONE = range(5)
NO_TICKET, PENDING_C, PENDING_PQ, ISSUED_C, ISSUED_PQ = range(5)
UNKNOWN = -1
BLANK = (UNUSED, UNKNOWN, UNKNOWN, NONE, 0, UNKNOWN, UNKNOWN, UNKNOWN)
SAFETY = (
    "acceptance_time_policy",
    "resumed_acceptance_time_policy",
    "start_time_policy",
    "abort_does_not_erase",
)
EXISTS = (
    "full_acceptance_reachable",
    "resume_reachable",
    "checked_then_commit_then_classical",
    "ticket_delivered_after_commit",
    "abort_erases_other_connection",
    "full_classical_reachable_before_commit",
    "resume_classical_reachable_before_commit",
)
QUERIES = tuple((q, "all") for q in SAFETY) + tuple((q, "exists") for q in EXISTS)
V, F = "VERIFIED", "FALSIFIED"
EXPECTED = {
    "start": (F, F, V, V, V, V, V, V, F, V, V),
    "split": (F, F, V, V, V, V, V, V, F, V, V),
    "atomic": (V, V, V, V, V, V, F, V, F, V, V),
    "restore-abort": (F, F, F, F, V, V, V, V, V, V, V),
}
PROFILES = {
    "start": (True, False, False),
    "split": (False, False, False),
    "atomic": (False, True, False),
    "restore-abort": (False, True, True),
}
class BudgetExceeded(Exception):
    def __init__(self, states, transitions):
        self.states, self.transitions = states, transitions
def replace(items, index, value):
    return items[:index] + (value,) + items[index + 1:]
def allowed(cache, cls):
    return cache == NONE or cls == PQ
def acceptance_marks(mode, session, generation):
    _, cls, _, start_cache, _, check_cache, check_gen, _ = session
    violations = witnesses = 0
    if cls == CLASSICAL:
        if generation:
            violations |= 1 << (0 if mode == "full" else 1)
        if start_cache == PQ:
            violations |= 1 << 2
        if mode == "full" and check_cache == NONE and check_gen < generation:
            witnesses |= 1 << 2
        if generation == 0:
            witnesses |= 1 << (5 if mode == "full" else 6)
    if cls == PQ:
        witnesses |= 1 << (0 if mode == "full" else 1)
    return violations, witnesses
def issuance_marks(origin_session, generation):
    return int(origin_session[1] == CLASSICAL and origin_session[7] < generation) << 3
def successors(state, profile):
    cache, generation, full, resume, tickets, violations, witnesses = state
    start_view, final_recheck, restore = PROFILES[profile]
    for slot, session in enumerate(full):
        phase, cls, origin, snapshot, start_gen, check_cache, check_gen, accept_gen = session
        if phase == UNUSED:
            updated = (STARTED, UNKNOWN, slot, cache, generation, UNKNOWN, UNKNOWN, UNKNOWN)
            yield cache, generation, replace(full, slot, updated), resume, tickets, violations, witnesses
        elif phase == STARTED:
            for response_class in (CLASSICAL, PQ):
                updated = (RESPONDED, response_class, origin, snapshot, start_gen,
                           UNKNOWN, UNKNOWN, UNKNOWN)
                yield cache, generation, replace(full, slot, updated), resume, tickets, violations, witnesses
        elif phase == RESPONDED:
            view = snapshot if start_view else cache
            if allowed(view, cls):
                updated = (READY, cls, origin, snapshot, start_gen, view, generation, UNKNOWN)
                yield cache, generation, replace(full, slot, updated), resume, tickets, violations, witnesses
        elif phase == READY:
            if not final_recheck or allowed(cache, cls):
                add_v, add_w = acceptance_marks("full", session, generation)
                updated = (DONE, cls, origin, snapshot, start_gen, check_cache,
                           check_gen, generation)
                new_cache, new_generation = cache, generation
                if cls == PQ:
                    new_cache, new_generation = PQ, generation + 1
                pending = PENDING_C if cls == CLASSICAL else PENDING_PQ
                yield (new_cache, new_generation, replace(full, slot, updated), resume,
                       replace(tickets, slot, pending), violations | add_v, witnesses | add_w)
            after = snapshot if restore else cache
            add_v = int(after != cache) << 3
            add_w = int(snapshot == NONE and cache == PQ and after == NONE and generation > start_gen) << 4
            updated = (DONE, cls, origin, snapshot, start_gen, check_cache,
                       check_gen, UNKNOWN)
            yield (after, generation, replace(full, slot, updated), resume, tickets,
                   violations | add_v, witnesses | add_w)
    for origin, ticket in enumerate(tickets):
        if ticket in (PENDING_C, PENDING_PQ):
            issued = ISSUED_C if ticket == PENDING_C else ISSUED_PQ
            add_w = issuance_marks(full[origin], generation)
            yield (cache, generation, full, resume, replace(tickets, origin, issued),
                   violations, witnesses | add_w)
    phase, cls, origin, snapshot, start_gen, check_cache, check_gen, accept_gen = resume
    if phase == UNUSED:
        for ticket_origin, ticket in enumerate(tickets):
            if ticket in (ISSUED_C, ISSUED_PQ):
                ticket_class = CLASSICAL if ticket == ISSUED_C else PQ
                updated = (STARTED, ticket_class, ticket_origin, cache, generation,
                           UNKNOWN, UNKNOWN, UNKNOWN)
                yield cache, generation, full, updated, tickets, violations, witnesses
    elif phase == STARTED:
        updated = (RESPONDED, cls, origin, snapshot, start_gen, UNKNOWN, UNKNOWN, UNKNOWN)
        yield cache, generation, full, updated, tickets, violations, witnesses
    elif phase == RESPONDED:
        view = snapshot if start_view else cache
        if allowed(view, cls):
            updated = (READY, cls, origin, snapshot, start_gen, view, generation, UNKNOWN)
            yield cache, generation, full, updated, tickets, violations, witnesses
    elif phase == READY:
        if not final_recheck or allowed(cache, cls):
            add_v, add_w = acceptance_marks("resume", resume, generation)
            updated = (DONE, cls, origin, snapshot, start_gen, check_cache,
                       check_gen, generation)
            yield (cache, generation, full, updated, tickets,
                   violations | add_v, witnesses | add_w)
        after = snapshot if restore else cache
        add_v = int(after != cache) << 3
        updated = (DONE, cls, origin, snapshot, start_gen, check_cache, check_gen, UNKNOWN)
        yield after, generation, full, updated, tickets, violations | add_v, witnesses
def explore(profile, max_states, max_transitions):
    initial = (NONE, 0, (BLANK,) * 3, BLANK, (NO_TICKET,) * 3, 0, 0)
    queue, seen = deque((initial,)), {initial}
    transitions = reached_v = reached_w = 0
    while queue:
        state = queue.popleft()
        reached_v |= state[5]
        reached_w |= state[6]
        for next_state in successors(state, profile):
            transitions += 1
            if transitions > max_transitions:
                raise BudgetExceeded(len(seen), transitions)
            if next_state not in seen:
                if len(seen) >= max_states:
                    raise BudgetExceeded(len(seen), transitions)
                seen.add(next_state)
                queue.append(next_state)
    return len(seen), transitions, reached_v, reached_w
def results_for(profile, violations, witnesses):
    rows = []
    for index, ((query, kind), expected) in enumerate(zip(QUERIES, EXPECTED[profile])):
        reached = bool((violations if kind == "all" else witnesses) &
                       (1 << (index if kind == "all" else index - len(SAFETY))))
        outcome = (F if reached else V) if kind == "all" else (V if reached else F)
        rows.append({"query": query, "kind": kind, "outcome": outcome,
                     "expected": expected, "matches_expected": outcome == expected})
    return rows
def self_test():
    delayed_pq = (DONE, PQ, 0, NONE, 0, NONE, 0, 0)
    assert issuance_marks(delayed_pq, 1) == 0
    started_none = (READY, CLASSICAL, 0, NONE, 1, NONE, 1, UNKNOWN)
    violations, _ = acceptance_marks("full", started_none, 1)
    assert not violations & (1 << 2)
    ready = (READY, CLASSICAL, 0, NONE, 0, NONE, 0, UNKNOWN)
    state = (PQ, 1, (ready, BLANK, BLANK), BLANK, (NO_TICKET,) * 3, 0, 0)
    preserved = [x for x in successors(state, "atomic") if x[2][0][0] == DONE]
    assert preserved and all(not x[6] & (1 << 4) for x in preserved)
    restored = [x for x in successors(state, "restore-abort") if x[2][0][0] == DONE]
    assert any(x[0] == NONE and x[6] & (1 << 4) for x in restored)
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path)
    parser.add_argument("--max-states", type=int, default=2_000_000,
                        help="per-profile state budget")
    parser.add_argument("--max-transitions", type=int, default=10_000_000,
                        help="per-profile transition budget")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test(); return
    if args.out is None or args.max_states < 1 or args.max_transitions < 1:
        parser.error("--out and positive budgets are required")
    if args.out.exists():
        parser.error(f"refusing to overwrite {args.out}")
    source = Path(__file__).with_name("overlap_policy.spthy")
    report = {
        "status": "COMPLETE",
        "source": str(source),
        "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "budget_per_profile": {"states": args.max_states, "transitions": args.max_transitions},
        "assumptions": [
            "three concrete full slots 0, 1, 2 and one resumption slot",
            "honest already-valid responses and private-channel interface",
            "one optional delayed ticket per accepted full origin; origin retained",
            "no expiry or withdrawal; PQ full acceptance alone installs",
        ],
        "profiles": {},
    }
    try:
        for profile in PROFILES:
            states, transitions, violations, witnesses = explore(
                profile, args.max_states, args.max_transitions)
            verdicts = results_for(profile, violations, witnesses)
            report["profiles"][profile] = {
                "status": "COMPLETE", "states": states, "transitions": transitions,
                "safety_violations_reached": [q for i, q in enumerate(SAFETY)
                                               if violations & (1 << i)],
                "existence_witnesses_reached": [q for i, q in enumerate(EXISTS)
                                                 if witnesses & (1 << i)],
                "verdicts": verdicts,
            }
    except BudgetExceeded as error:
        report["status"] = "RESOURCE_LIMIT"
        report["incomplete_profile"] = profile
        report["observed_at_limit"] = {"states": error.states,
                                       "transitions": error.transitions}
    report["all_expectations_met"] = report["status"] == "COMPLETE" and all(
        row["matches_expected"] for data in report["profiles"].values()
        for row in data["verdicts"])
    args.out.parent.mkdir(parents=True, exist_ok=True)
    try:
        with args.out.open("x") as output:
            json.dump(report, output, indent=2)
            output.write("\n")
    except FileExistsError:
        parser.error(f"refusing to overwrite {args.out}")
    if report["status"] != "COMPLETE":
        raise SystemExit(2)
if __name__ == "__main__":
    main()
