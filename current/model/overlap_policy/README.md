# Overlapping-connection policy study

## Completed finite-state evidence

`explore.py` is an independent finite-state model of the policy transitions under honest already-valid responses. It is not a Tamarin proof or a full TLS model. The retained run in `runs/2026-09-26-finite` completed all four profiles with eleven outcomes each. It records 43,713 states for start snapshots, 32,383 for split checking, 27,253 for atomic checking with state-preserving abort and 43,663 for atomic checking with snapshot restoration. Counts include monitor histories and abstract unobserved slot/ticket identities.

Run the small self-test and complete exploration sequentially:

```sh
python3 model/overlap_policy/explore.py --self-test
python3 model/overlap_policy/explore.py --out verification_runs/overlap-finite-new.json
```

The output refuses to overwrite an existing result. Each violation or reached witness includes a shortest decisive action sequence in this finite transition system. The source snapshot, Python version, command, return code and source hash are retained alongside the results.

The finite model has three full-attempt slots and one resumption slot. It omits cryptographic forgery, expiry and legitimate withdrawal. Full IDs are alpha-normalised by start order. Unused slot names and resumption-ticket identities with the same origin class are abstracted because the current observations cannot distinguish them. Future ticket-specific queries would require retaining those identities.

Atomic checking plus an abort that leaves shared state unchanged satisfies both contracts within this graph. Start-time and split checking fail the stronger acceptance-time contract. Restoring an aborted connection's snapshot can overwrite another connection's commitment and defeat even an atomic acceptance check. This is a bounded policy-scheduling result and a familiar stale-snapshot hazard, not a novel cryptographic attack or a deployed exploit.

Both classical full and resumed acceptance before commitment remain reachable under every profile, as do the two PQ acceptance paths. The abort input/output equality is only structural sanity. The causal rollback witness and subsequent acceptance failures provide the substantive schedule evidence.

## Incomplete symbolic companion


This is a bounded experimental model, not a complete TLS proof. It has one endpoint, three full-handshake slots and one resumption slot. Pinned signing keys and private per-handshake channel-key facts supply an authenticated interface. Ticket issuance uses a confidential local-state interface. No party is compromised. Expiry, withdrawal, multiple endpoints, the TLS key schedule and certificate path building are absent.

The baseline never restores a connection-local policy snapshot to the shared cache on abort. Start-time, pre-completion and atomic acceptance-time profiles share observations. The final policy read and acceptance are one rule in the atomic profile. This atomicity is an implementation assumption, not a result about existing stacks. There is no initial-session ordering restriction.

The pilot distinguishes contracts: grandfathering an in-flight connection under its start-time policy is not a violation of that contract, although it can fail an acceptance-time contract. The restore-on-abort mutation tests overwriting a later commitment with a local snapshot. We do not claim this mutation describes a deployed client.

Run sequentially using `python3 model/overlap_policy/run.py --out <new-directory`. Each invocation records declared expectations before execution and retains failures/timeouts. Query verdicts must be interpreted with their exact observations. A protocol property compiled directly into a guard is not independently novel.

Initial S-heuristic searches are recorded separately. They are not positive evidence. The restore-abort expectations were corrected by manual trace reasoning before executing that configuration: a rollback can also defeat start-time policy and enable the check/commit/accept witness. No observed result was relabelled to match a prediction.

## Status on 26 September 2026

The universal policy and discriminating-witness searches timed out within 25–45 seconds per run. Those searches establish no Tamarin concurrency claim. The subsequently completed finite-state result is reported separately. Parse/wellformedness success is not a security result. A nested preprocessor selection failed for the start profile and was replaced with independent profile flags. Superseded inputs and timeouts remain in their original run folders.

The final pilot permits ticket issuance only from a completed full handshake and does not install or renew a commitment on PSK resumption. The private channel-key and ticket interfaces remain assumptions. The symbolic model still needs a completed discriminating witness and further work on global-state proof search. The separate finite-state results above are not transferred to it. The reviewer bundle includes these incomplete records to distinguish them from the completed finite-state run.


A ghost-counter variant generated by `count_cache_steps.py` caps cache accesses at 12. This is derived from three full slots plus one resumption slot, each with at most a start read, policy-check read and terminal read. It does not order sessions. The 60-second counted witness search remained incomplete, as did a 60-second breadth-first search of the original model. Their retained timeouts are not negative verdicts.


## Independent checks added in round 3

`reference_check.py` is a separate implementation with concrete full-slot IDs and individual ticket origins. It does not import the primary explorer. Its completed run in `runs/2026-09-26-reference` agrees on all eleven outcomes per profile. Its state counts are 75,958, 60,706, 53,674 and 79,282 respectively. Counts differ because the representations and history fields differ; matched verdicts are not a formal equivalence proof.

`audit_monitors.py` evaluates the event conditions separately on every primary-graph edge. Its completed run in `runs/2026-09-26-edge-audit` agrees with all monitor updates on 308,794 edges. The checker rejects an intentionally corrupted observation on a control edge. This tests the event monitors, not cryptographic assumptions.

```sh
python3 model/overlap_policy/reference_check.py --self-test
python3 model/overlap_policy/reference_check.py --out verification_runs/overlap-reference-new.json
python3 model/overlap_policy/audit_monitors.py --out verification_runs/overlap-monitor-new.json
```

The reference checker has explicit per-profile resource limits and emits no verdict for an incomplete profile. The source and observation checker snapshots, commands and outputs are retained separately. The parent corrected a missing post-abort-state condition in the initially unexecuted reference checker and added a negative regression before the first complete run.


## Completed withdrawal and lifecycle controls

`lifecycle_check.py` extends the finite policy study with authenticated positive updates and four-octet zero withdrawals. It compares the actual cache C with a reference history H updated only by completed PQ updates. Omission and cancellation leave H unchanged. This is a chosen completion-order adapter contract with at most three full attempts at one endpoint, no PSK and no expiry. It is not a universal interpretation of concurrent responses in the draft.

`runs/2026-09-26-lifecycle-final` records seven outcomes per profile. Preserve has 6,253 states and 16,406 transitions; restore has 6,781 states and 16,926 transitions. Preserve maintains C=H. Restore admits both erasure of a newer commitment and resurrection after withdrawal. The blocking query observes C=PQ with H=none, where the declared guard would reject a new classical attempt. It is not an executed fourth attempt or a liveness theorem. The PQ omission response is a deliberately non-compliant participating-server robustness control.

The response-restricted variant excludes PQ omission and classical responses to attempts started with a PQ cache snapshot, reflecting continuity-02 Section 3.5. Its record is `runs/2026-09-26-lifecycle-response-control`. Preserve has 2,905 states and 7,360 transitions; restore has 3,183 states and 7,630 transitions. Both restoration faults remain reachable. The omitted response's witness is unreachable in both profiles and the other twelve outcomes are unchanged. These checks do not establish a TLS refinement theorem.

```sh
python3 model/overlap_policy/lifecycle_check.py --self-test --out verification_runs/lifecycle-new.json
python3 model/overlap_policy/lifecycle_check.py --self-test --enforce-start-offer --no-pq-omission --out verification_runs/lifecycle-response-new.json
```

Run sequentially. Both outputs must have `status: COMPLETE` and `all_expectations_met: true`; an incomplete run supplies no universal verdict. The current script adds optional response controls after the original default run. Default profile counts, observations and traces must agree with the retained default snapshot; whole-file hashes or metadata need not be identical across those source revisions.
