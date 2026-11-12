#!/usr/bin/env python3
"""Bounded cache-lifecycle checker for completed updates and stale aborts."""
import argparse, hashlib, json
from collections import deque
from pathlib import Path
NONE, PQ = range(2)
UNUSED, STARTED, RESPONDED, READY, ACCEPTED, BLOCKED, ABORTED = range(7)
UNKNOWN, CLASSICAL_ABSENT, PQ_ABSENT, PQ_COMMIT, PQ_ZERO4 = range(-1, 4)
RESPONSES = (CLASSICAL_ABSENT, PQ_ABSENT, PQ_COMMIT, PQ_ZERO4)
RESPONSE_NAMES = {
    CLASSICAL_ABSENT: "classical/absent", PQ_ABSENT: "pq/absent[robustness-control:noncompliant-participating-server]",
    PQ_COMMIT: "pq/commit[4-byte-nonzero]", PQ_ZERO4: "pq/zero[4-byte]"}
BLANK = (UNUSED, UNKNOWN, NONE)
V, F = "VERIFIED", "FALSIFIED"
QUERIES = (
    ("actual_cache_equals_authoritative_history", "all"),
    ("no_classical_acceptance_while_h_active_before_accept", "all"),
    ("classical_blocking_state_reachable", "exists"),
    ("legitimate_withdrawal_reachable", "exists"),
    ("omission_after_commit_keeps_active_cache", "exists"),
    ("stale_abort_drops_pq", "exists"),
    ("stale_abort_resurrects_withdrawn_pq", "exists"),
)
EXPECTED = {"preserve": (V, V, F, V, V, F, F),
            "restore": (F, F, V, V, V, V, V)}
class BudgetExceeded(Exception):
    def __init__(self, states, transitions, hits):
        self.states, self.transitions, self.hits = states, transitions, hits
def replace(items, index, value):
    return items[:index] + (value,) + items[index + 1:]
def label(value):
    return "pq" if value == PQ else "none"
def successors(state, profile, enforce_offer=False, omit_control=True):
    actual, history, sessions = state
    started = sum(session[0] != UNUSED for session in sessions)
    if started < len(sessions):
        session = (STARTED, UNKNOWN, actual)
        yield (f"F{started}: begin [snapshot={label(actual)}]", "begin",
               (actual, history, replace(sessions, started, session)))
    for index, (phase, response, snapshot) in enumerate(sessions):
        sid = f"F{index}"
        if phase == STARTED:
            for answer in RESPONSES:
                if not omit_control and answer == PQ_ABSENT:continue
                if enforce_offer and snapshot == PQ and answer == CLASSICAL_ABSENT:continue
                session = (RESPONDED, answer, snapshot)
                yield (f"{sid}: receive authenticated {RESPONSE_NAMES[answer]}", "receive",
                       (actual, history, replace(sessions, index, session)))
        elif phase == RESPONDED:
            if response == CLASSICAL_ABSENT and actual == PQ:
                session = (BLOCKED, response, snapshot)
                action = f"{sid}: current-policy check blocks classical [actual=pq]"
                yield action, "block_classical", (
                    actual, history, replace(sessions, index, session))
            else:
                session = (READY, response, snapshot)
                action = f"{sid}: current-policy check passes [actual={label(actual)}]"
                yield action, "ready", (actual, history, replace(sessions, index, session))
        elif phase == READY:
            if response == CLASSICAL_ABSENT and actual == PQ:
                session = (BLOCKED, response, snapshot)
                action = f"{sid}: atomic final recheck blocks classical [actual=pq]"
                yield action, "block_classical", (
                    actual, history, replace(sessions, index, session))
            else:
                after_actual, after_history = actual, history
                event = "accept_omit"
                if response == CLASSICAL_ABSENT:
                    event = "accept_classical"
                elif response == PQ_COMMIT:
                    after_actual = after_history = PQ
                    event = "accept_commit"
                elif response == PQ_ZERO4:
                    after_actual = after_history = NONE
                    event = "accept_withdraw"
                session = (ACCEPTED, response, snapshot)
                action = f"{sid}: accept {RESPONSE_NAMES[response]} [{label(actual)}->{label(after_actual)}]"
                yield action, event, (
                    after_actual, after_history, replace(sessions, index, session))
            after = snapshot if profile == "restore" else actual
            session = (ABORTED, response, snapshot)
            action = f"{sid}: abort [{label(actual)}->{label(after)}]"
            yield action, "abort", (after, history, replace(sessions, index, session))
def trace(state, parent):
    actions = []
    while parent[state][0] is not None:
        state, action = parent[state]
        actions.append(action)
    return list(reversed(actions))
def observations(before, event, after):
    actual, history, _ = before
    next_actual, next_history, _ = after
    found = []
    if next_actual != next_history:
        found.append("actual_cache_equals_authoritative_history")
    if event == "accept_classical" and history == PQ:
        found.append("no_classical_acceptance_while_h_active_before_accept")
    if next_actual == PQ and next_history == NONE:
        found.append("classical_blocking_state_reachable")
    if (event == "accept_withdraw" and actual == history == PQ
            and next_actual == next_history == NONE):
        found.append("legitimate_withdrawal_reachable")
    if (event == "accept_omit" and actual == history == PQ
            and next_actual == next_history == PQ):
        found.append("omission_after_commit_keeps_active_cache")
    if (event == "abort" and actual == history == PQ
            and next_actual == NONE and next_history == PQ):
        found.append("stale_abort_drops_pq")
    if (event == "abort" and actual == history == NONE
            and next_actual == PQ and next_history == NONE):
        found.append("stale_abort_resurrects_withdrawn_pq")
    return found
def explore(profile, max_states, max_transitions, enforce_offer=False, omit_control=True):
    initial = (NONE, NONE, (BLANK,) * 3)
    queue, parent, hits = deque([initial]), {initial: (None, None)}, {}
    transitions = 0
    while queue:
        state = queue.popleft()
        for action, event, child in successors(state, profile, enforce_offer, omit_control):
            transitions += 1
            if transitions > max_transitions:
                raise BudgetExceeded(len(parent), transitions, hits)
            path = None
            for query in observations(state, event, child):
                if query not in hits:
                    path = path or trace(state, parent) + [action]
                    note = (["monitor: a new classical attempt would fail the declared current-policy guard"]
                            if query == "classical_blocking_state_reachable" else [])
                    hits[query] = path + note
            if child not in parent:
                if len(parent) >= max_states:
                    raise BudgetExceeded(len(parent), transitions, hits)
                parent[child] = state, action
                queue.append(child)
    verdicts = []
    for (query, kind), expected in zip(QUERIES, EXPECTED[profile]):
        if not omit_control and query == "omission_after_commit_keeps_active_cache":expected = F
        reached = query in hits
        outcome = (F if reached else V) if kind == "all" else (V if reached else F)
        verdicts.append({"query": query, "kind": kind, "outcome": outcome,
                         "expected": expected, "matches_expected": outcome == expected,
                         "shortest_decisive_trace": hits.get(query)})
    return {"status": "COMPLETE", "states": len(parent),
            "transitions": transitions, "verdicts": verdicts}
def self_test():
    ready_omit_none = (READY, PQ_ABSENT, NONE)
    state = (PQ, PQ, (ready_omit_none, BLANK, BLANK))
    preserve = [x for x in successors(state, "preserve") if x[1] == "abort"]
    restore = [x for x in successors(state, "restore") if x[1] == "abort"]
    assert preserve[0][2][:2] == (PQ, PQ)
    assert restore[0][2][:2] == (NONE, PQ)
    ready_omit_pq = (READY, PQ_ABSENT, PQ)
    state = (NONE, NONE, (ready_omit_pq, BLANK, BLANK))
    restored = [x for x in successors(state, "restore") if x[1] == "abort"][0]
    assert restored[2][:2] == (PQ, NONE)
    old_zero = (READY, PQ_ZERO4, NONE)
    state = (PQ, PQ, (old_zero, BLANK, BLANK))
    assert any(event == "accept_withdraw" for _, event, _ in successors(state, "preserve"))
    ready_classical = (READY, CLASSICAL_ABSENT, NONE)
    state = (PQ, PQ, (ready_classical, BLANK, BLANK))
    events = [event for _, event, _ in successors(state, "preserve")]
    assert "block_classical" in events and "accept_classical" not in events
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--max-states", type=int, default=500_000)
    parser.add_argument("--max-transitions", type=int, default=3_000_000)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--enforce-start-offer", action="store_true")
    parser.add_argument("--no-pq-omission", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        if args.out is None:
            return
    if args.out is None or args.max_states < 1 or args.max_transitions < 1:
        parser.error("--out and positive resource budgets are required")
    if args.out.exists():
        parser.error(f"refusing to overwrite {args.out}")
    source = Path(__file__)
    report = {
        "status": "COMPLETE",
        "source": str(source),
        "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "scope": "Independent bounded policy model, not complete TLS or an IETF interpretation.",
        "assumptions": {
            "bound": "one endpoint and at most three full attempts; IDs follow start order",
            "identity_quotient": "not-yet-started attempt identities are interchangeable",
            "responses": [RESPONSE_NAMES[x] for x in RESPONSES],
            "authentication": "responses are valid and authenticated; forgery is outside the model",
            "policy": "current actual cache is checked before ready and atomically before acceptance",
            "wire_operations": "absent, four-byte nonzero COMMIT, or four-byte ZERO; empty extension is distinct and excluded",
            "pq_absence": "authenticated robustness control for a noncompliant participating server; continuity-02 requires a PQ server to send four octets",
            "history_h": "H changes only on successfully completed PQ COMMIT or four-byte ZERO",
            "actual_cache": "C_actual may diverge from H only through faulty snapshot restoration",
            "acceptance_contract": "checks whether H is active immediately before acceptance, not whether a commitment was ever installed",
            "omission": "absent operation changes neither C_actual nor H",
            "withdrawal": "a successfully completed four-byte ZERO is authoritative in completion order, including when its attempt began before a later COMMIT",
            "abort": "ready abort either preserves current cache or faultily restores its start snapshot",
            "excluded": "PSK, expiry and a general interpretation of the analysed Internet-Draft",
            "availability_query": "state-level blocking condition only; no fairness or liveness theorem",
        },
        "response_controls": {"enforce_start_offer": args.enforce_start_offer, "pq_omission_enabled": not args.no_pq_omission},
        "budget_per_profile": {"states": args.max_states, "transitions": args.max_transitions},
        "profiles": {},
    }
    try:
        for profile in EXPECTED:
            report["profiles"][profile] = explore(
                profile, args.max_states, args.max_transitions, args.enforce_start_offer, not args.no_pq_omission)
    except BudgetExceeded as error:
        report["status"] = "RESOURCE_LIMIT"
        report["profiles"][profile] = {
            "status": "INCOMPLETE", "states": error.states,
            "transitions": error.transitions,
            "observed_shortest_traces": error.hits,
            "verdicts": None,
        }
    report["all_expectations_met"] = (None if report["status"] != "COMPLETE" else all(
        row["matches_expected"] for data in report["profiles"].values()
        for row in data["verdicts"]))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    try:
        with args.out.open("x", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2)
            handle.write("\n")
    except FileExistsError:
        parser.error(f"refusing to overwrite {args.out}")
    if report["status"] != "COMPLETE":
        raise SystemExit(2)
if __name__ == "__main__":
    main()
