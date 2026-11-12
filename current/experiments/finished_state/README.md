# Finished-state cache experiment

This controlled OpenSSL harness extends the in-memory method used by
`../testbed/exp2_ext_before_validation.c`. It compares three places where a
client could apply the `pq_cert_available` cache operation:

1. in the per-`CertificateEntry` parse callback;
2. after OpenSSL has processed a valid server `CertificateVerify`;
3. after `SSL_is_init_finished()` reports a completed handshake.

The cache is an in-memory test object that persists across five independent TLS
1.3 connections. It first receives a non-zero commitment through a successful
handshake. An omitted-extension control and three zero-value withdrawal cases then use the same cache:

| Case | Chain | Terminal state | Expected cache after the case: parser / after CV / after Finished |
|---|---|---|---|
| Prior commitment | trusted | handshake succeeds | `86400 / 86400 / 86400` |
| Extension omitted | trusted | handshake succeeds | `86400 / 86400 / 86400` |
| Invalid chain | untrusted | fails before CertificateVerify | `0 / 86400 / 86400` |
| Invalid Finished | trusted | fails after CertificateVerify | `0 / 0 / 86400` |
| Successful withdrawal | trusted | handshake succeeds | `0 / 0 / 0` |

The invalid-chain case deliberately leaves the client's trust store empty. It
is a controlled validation-failure case, not a claim about a realistic MITM.

The invalid-Finished case does not alter memory supplied to an OpenSSL message
callback. The harness uses separate memory BIOs and copies one complete TLS
record at a time. It pins `TLS_AES_128_GCM_SHA256`, captures the server handshake
traffic secret through OpenSSL's keylog callback and derives the handshake key
and IV with TLS 1.3 HKDF labels. It decrypts its own copy of the server Finished
record, flips one `verify_data` bit and re-encrypts the record with a valid GCM
tag. A valid injection preserves record protection while making Finished
authentication fail. The case passes only if CertificateVerify was processed
first and `SSL_is_init_finished()` remains false. This is harness-enabled
corruption for a controlled test. It is not a network attack.

The injector requires OpenSSL to emit Finished as one complete handshake message
in its own TLS record after the client has processed CertificateVerify. If that
boundary is absent, no bytes are changed and the case fails. The harness does not
guess from record contents or treat a different failure point as equivalent.
It also requires OpenSSL's fatal reason to be `SSL_R_DIGEST_CHECK_FAILED` and
stops the injector after the first changed Finished record.

Each case prints the cache before and after the handshake, certificate-validation
result and monotonic event numbers for extension parsing, CertificateVerify,
fault injection, Finished, `SSL_is_init_finished()` and terminal observation.
The program exits non-zero if the existing peer certificate is not ML-DSA-65, a
control does not reach its required state or any cache assertion differs from
the table.

## Prerequisites

- OpenSSL 3.6.3 headers and libraries at `/opt/homebrew/opt/openssl@3.6`.
- The unchanged files `../testbed/server.crt`, `../testbed/server.key` and
  `../testbed/ca.crt`.
- A C compiler. No Python package or new library is required.

The existing certificate and key files are read only. The harness creates no
certificate, key or log files.

## Build and run

Run these commands from this directory:

```sh
cc -std=c11 -O1 -Wall -Wextra -o finished_state finished_state.c \
  -I/opt/homebrew/opt/openssl@3.6/include \
  -L/opt/homebrew/opt/openssl@3.6/lib \
  -Wl,-rpath,/opt/homebrew/opt/openssl@3.6/lib \
  -lssl -lcrypto

./finished_state
```

## Observation record

The parent compiled and ran the five-case sequence on OpenSSL 3.6.3. All cases
passed. `runs/2026-09-10-presence-and-identity` retains the executed source, compile command, binary
hash, expected cache values and complete output.

The invalid-Finished case recorded CertificateVerify processing at event 3,
fault injection at event 4, Finished receipt at event 5 and no successful
handshake completion. It failed with `SSL_R_DIGEST_CHECK_FAILED` (reason 149).
The parser-time and CV-time caches were zero, while the completion-time cache
retained 86400. The succeeding legitimate withdrawal cleared that final cache.

This establishes a difference between update policies on this controlled
failure sequence. It does not show that a verified CV lacks server provenance,
that a network attacker can forge the injected record or that every TLS
implementation behaves identically.

The final run also checks the localhost reference identity. CV/completion
updates use the value received by the client parse callback, not the server's
configured value, and no update occurs when the extension is absent. The three
fields are shadow cache-update policies in one harness. They do not implement
later credential-selection enforcement. The earlier four-case run is retained
separately.
