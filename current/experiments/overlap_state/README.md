# Interleaved TLS handshakes with local cancellation

This harness uses simultaneously live OpenSSL memory-BIO connections to the same localhost identity. It transfers complete TLS records without changing them and uses ordinary local cancellation. Two shadow application-policy fields consume the same handshake outcomes. The preserve adapter leaves shared state unchanged on cancellation. The deliberately faulty restore adapter writes the cancelled connection's initial snapshot. That write belongs to the test adapter, not stock OpenSSL.

Connection A pauses after CertificateVerify processing. On the tested OpenSSL 3.6.3 build, the observable state remains `TLS_ST_CR_CERT_VRFY` after `SSL_do_handshake` returns `SSL_ERROR_WANT_READ`. The harness requires a verified chain and hostname, an ML-DSA-65 peer key, an empty client input BIO, no Finished-message callback and no completed handshake. B then completes while A remains paused. Cancellation frees A's SSL objects without processing Finished.

The current six-case run uses dedicated SAN fixtures. The server has `DNS:localhost` in subjectAltName and `CN=unused.invalid`; `X509_CHECK_FLAG_NEVER_CHECK_SUBJECT` disables Common Name fallback. `fixtures/manifest.json` records the generation commands, certificate extensions and file hashes. These are public laboratory credentials, not production keys. The CA private key was not retained. Certificates have finite validity, so reproduction after expiry requires new equivalent test fixtures and a new evidence record.

| Case | Preserve adapter | Snapshot-restore adapter |
|---|---:|---:|
| B commits; A is cancelled | 86400 | 0 |
| B fails chain validation; A is cancelled | 0 | 0 |
| B commits; A completes its zero-valued update | 0 | 0 |
| Seed; B withdraws; A is cancelled | 0 | 86400 |
| Seed; B omits the extension; A is cancelled | 86400 | 86400 |
| Wrong reference identity rejected | 0 | 0 |

Seeded cases first establish 86400 through a separate successfully completed PQ handshake. Snapshot restoration can then resurrect a commitment that B has validly withdrawn, as well as erase a newer commitment in the unseeded case. Wrong-hostname verification fails before CV completion and any update. B's chain-failure control uses an empty test trust store.

Updates are ordered by successful completion in these adapters. An older attempt that completes later with a valid four-octet zero therefore clears the cache under this chosen contract. That is different from cancellation restoring a stale snapshot. The omitted-extension case is a robustness control using a deliberately non-compliant participating PQ server under continuity-02. Absence is not an empty extension or a four-octet zero. No later classical handshake or general availability property is tested.

Reproduce from the project root, one command at a time:

```sh
python3 experiments/overlap_state/test_runner.py
python3 experiments/overlap_state/run.py --out experiments/overlap_state/runs/new-run
```

The runner requires a new output directory and snapshots the C source and three fixtures. It retains their hashes, commands, exit codes and stdout/stderr, including partial output on timeout. The default prefix is the tested Homebrew `openssl@3.6`; use `--openssl-prefix` for another installation with ML-DSA support. `runs/2026-09-26-lifecycle-san` is the completed six-case SAN run. Earlier Common Name fixtures and three-case outputs in `runs/2026-09-26-cancel-checked` remain separate. The failed initial pause-state expectation and diagnostic probe are not positive evidence.

This establishes the tested TLS lifecycle and the effect of the two application-policy adapters. It is not a stock OpenSSL vulnerability, a full continuity implementation, a network attack or a refinement proof for the finite model.

Source cross-check: OpenSSL 3.6.3 verifies the signature in `tls_process_cert_verify` before returning `MSG_PROCESS_CONTINUE_READING` on this path. See the release-pinned [statem_lib.c](https://raw.githubusercontent.com/openssl/openssl/openssl-3.6.3/ssl/statem/statem_lib.c), especially the signature check around lines 545–567. The runtime assertions concern the tested synchronous memory-BIO configuration.
