# Persistent post-quantum TLS commitments: evidence artifact

Evidence for the paper *Persistent Post-Quantum TLS Commitments across Failed
and Overlapping Handshakes* (Nazmus Salehin Sammo, Sariya Akhter Lura, Raza
Nowrozy and Savitri Bevinakoppa, Melbourne Institute of Technology), submitted
to ICETE 2027.

The paper studies the client-side commitment cache of the IETF draft
[PQC Continuity](https://datatracker.ietf.org/doc/draft-sheffer-tls-pqc-continuity/)
(revision 02). It asks what happens to the cache when TLS handshakes fail or
overlap, and tests two client adapters: one that leaves the cache alone when a
handshake is cancelled, and one with a deliberately injected stale write.

This is a laboratory study of an injected fault. Nothing here is a
vulnerability in the continuity proof-of-concept, in OpenSSL or in a deployed
client.

## Quick start

Check that every file matches the manifest (needs only Python 3):

```sh
python3 REPRODUCE.py --check
```

Re-run everything into a new directory:

```sh
python3 REPRODUCE.py --run --out /absolute/path/to/a/new-directory
```

The full run needs Tamarin 1.12.0, Maude 3.5.1, OpenSSL 3.6.3 with ML-DSA
support, Python 3 and a C compiler. Use `--openssl-prefix /path/to/openssl` if
OpenSSL is not at the Homebrew default. Nothing is installed and no remote
host is contacted.

## Where each result in the paper comes from

| Paper result | Source | Recorded output |
|---|---|---|
| Primary finite exploration, 44 outcomes | `current/model/overlap_policy/explore.py` | `fresh/finite/results.json` |
| Independent re-implementation | `current/model/overlap_policy/reference_check.py` | `fresh/reference/results.json` |
| Monitor check on 308,794 edges | `current/model/overlap_policy/audit_monitors.py` | `fresh/edge-audit/results.json` |
| Offer control | `current/model/overlap_policy/offer_control.py` | `review/offer-control/results.json` |
| Withdrawal-aware lifecycle results | `original/model/overlap_policy/runs/2026-09-26-lifecycle-final/lifecycle_check.py` | `fresh/lifecycle/results.json` |
| Response-restricted lifecycle results | `current/model/overlap_policy/lifecycle_check.py` | `fresh/response-control/results.json` |
| Five-connection OpenSSL sequence | `current/experiments/finished_state/finished_state.c` | `fresh/commands/finished-runtime/stdout.log` |
| Six-case overlap run | `current/experiments/overlap_state/overlap_state.c` | `fresh/overlap-runtime/run.stdout.log` |
| Policy-consumption probes | `current/experiments/overlap_state/policy_consumption.c` | `review/policy-consumption/run.stdout.log` |
| Symbolic cache results, 15 queries | `current/model/cache_transaction/*.spthy` | `fresh/tamarin/*/result.json` |

## Layout

- `current/` holds the entry points, models, harnesses and test fixtures.
- `original/` holds the first recorded runs (September 2026).
- `fresh/` holds the reproduction of 25 October 2026 from the same inputs.
- `review/` holds the offer control and the policy-consumption probes.
- `development/` keeps one incomplete early probe. It is not a result.
- `primary-sources/` holds retrieved copies of the documents the paper cites
  (the draft, RFCs, the tracker issue and pull request, OpenSSL source and
  documentation), with URLs and hashes in its `manifest.json`.
- `source-comparators/` lists other compared sources by URL and hash only.

`README.txt`, `EVIDENCE_INDEX.json` and `MANIFEST.json` are the original
bundle records. `MANIFEST.json` lists the SHA-256 of every original file; this
`README.md` was added for the repository and is not listed in it.

## Independent check

On 12 November 2026 the bundle was checked on a second machine (macOS, Python
3.13, OpenSSL 3.6.3). All manifest hashes verified. The finite explorers, the
lifecycle checks and the offer control reproduced the recorded states, verdicts
and traces exactly, and the three OpenSSL harnesses produced output identical
to the recorded logs. Tamarin was not installed on that machine, so the 15
symbolic results were compared with the recorded logs only.

## Notes

- Absolute paths inside recorded commands and logs are from the original runs
  and are kept unchanged so that the manifest still verifies. `REPRODUCE.py`
  uses relative paths.
- The keys under `fixtures/`, `testbed/` and `ec-fixtures/` are throwaway
  laboratory credentials for `localhost`. They protect nothing.
- The test certificates expire between July and October 2027. After that the
  OpenSSL harnesses need new fixtures.
- One symbolic query (`aborted_withdrawal_retains_protection` in the early-clear
  variant) took about 89 seconds of its 120 second budget in the recorded run
  and may time out on a slower machine.
- Third-party documents under `primary-sources/` remain under their own
  licences.

## Contact

Nazmus Salehin Sammo (corresponding author), GitHub
[@Salehin-Sammo](https://github.com/Salehin-Sammo). Repository maintained by
[@Sariya9](https://github.com/Sariya9).
