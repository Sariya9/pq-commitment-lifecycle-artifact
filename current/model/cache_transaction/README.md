# Bounded cache-state experiment

This component tests cache-update provenance and preservation during explicit cancellation. It is not a complete TLS protocol model. It has one literal client/server pair, one endpoint, freshly generated uncompromised signing keys and a bounded phase sequence. The server is a symbolic signing oracle for response values supplied through the network. A matching server event establishes provenance, not independent operator intent.

`Cache` is linear. Parsing carries the current cache state into a pending transaction. Deferred policy changes it only after chain and CV verification; early policy clears on receipt of a zero value. The same `CacheCleared` event is emitted by both paths. Removing CV verification preserves all observation events.

`clearing_has_matching_server` binds the clear to a prior server event with the same identity, nonce, zero value, public key and certificate. `abort_preserves_established_cache` relates an established state at opening to its state after cancellation. The model represents cancellation after parsing or chain validation. It does not turn a failed validation check into an abort event, model cancellation after CV or model TLS Finished.

## Completed evidence, 10 September 2026

| Variant | Clearing provenance | Abort preservation | Establishment | Signed withdrawal response | Protected abort after zero |
|---|---|---|---|---|---|
| Deferred | Verified | Verified | Reachable | Reachable | Reachable |
| Early clear | Falsified | Falsified | Reachable | Reachable | Unreachable |
| CV check deleted | Falsified | Verified | Reachable | Reachable | Reachable |

These fifteen selected queries completed under heuristic S. The safe results are in `runs/2026-09-10-S-controls/safe.json`; the other ten are in `runs/2026-09-10-negative-controls`. Every completed verdict matched the expectation declared before its run.

The original safe reconnect-after-abort query timed out after 90 seconds. A
stronger query with phase observations subsequently produced a 34-step witness
in 54.635 seconds. The observations do not change protocol behaviour, and the
witness contains the sequence required by the original query. This establishes
existence of that execution, not universal reconnect safety.

The new input and run are `cache_transaction_phase_witness.spthy` and
`runs/2026-09-10-phase-witness`. A direct phase-labelled early-clear companion
also timed out at 90 seconds; the no-CV companion was not executed after that
stop. Neither is counted as a completed proof. The original fifteen-query
comparison and its earlier raw timeouts are unchanged. The base source SHA-256
is `c24165f05ef5f7d7fa31c74c957a36c7ea6d83e04829e8ec8dc3f691008286a4`.

## Reproduce the fifteen selected queries

From the project root, using a new output directory:

```sh
python3 model/cache_transaction/run.py --out model/cache_transaction/runs/new-selected --heuristic S --timeout 120 --only-query clearing_has_matching_server --only-query abort_preserves_established_cache --only-query establishment_reachable --only-query legitimate_withdrawal_reachable --only-query aborted_withdrawal_retains_protection
```

The runner processes one query at a time and stops on unexpected or incomplete results. `--only-case` can select `safe`, `early` or `no_cv`. Omitting query selection attempts the separate reconnect witness too. The runner never converts incomplete output into a falsification.

The existing result snapshots retain the actual inputs, commands, tool hashes, stdout/stderr and query verdicts. The phase bound, oracle behaviour and absence of classical-acceptance, concrete-port and PSK paths remain limitations. This component supports the cache-update part of the research argument, not the entire cross-connection composition claim.
