# fin-auth

Authentication & sessions for Fin: JWT (HS256) encode/verify, password hashing
(PBKDF2-HMAC-SHA256), an in-memory session store, and CSRF token helpers.

The crypto-primitive/application-layer split is kept clean: every primitive
(HMAC, CSPRNG, constant-time comparison) comes from
[`fin-crypto`](https://github.com/M1778/fin-crypto); this module is the
application layer on top. JSON comes from
[`finson`](https://github.com/M1778/finson).

The convenience `password_hash` function now uses **600,000 PBKDF2-HMAC-SHA256
iterations** via `password_policy_default()`. Verification accepts bounded older
records for migration; `password_needs_rehash` identifies upgrades. The explicitly
named legacy policy retains 10,000 iterations for compatibility, not as a
production recommendation. `jwt_decode` checks only signature/header; use
`jwt_verify` to enforce claims.

## Installation and coordinated dependencies

This source revision requires coordinated dependencies pinned by full Git commit
in `finn.toml`:

- `fin-crypto@777990f2ef19ec7be6a69a628957ffb48da11974`: raw HMAC and native Windows RNG.
- `finson@3ec90fe94643404c06349ceb6fcc004ad89ca5c3`: strict JSON, duplicate-key
  rejection, input budgets, finite numbers, UTF-8 and embedded-NUL validation.
- Fin standard library: `strings`, `time`, `collection`.

These are existing pushed commits, not invented release tags. Finn accepts Git
revisions and the manifest pins the APIs used here. Installing the older
`fin-auth@0.1.0` tag does not install this hardening work; use the current source
revision. A tagged release remains separate from these source commits.

### Implementation notes

PBKDF2 uses raw HMAC bytes and native integer XOR; the allocating hex roundtrip
and data-dependent arithmetic XOR helper have been removed.
Explicit-length base64url helpers remain local because the standard string-based
encoder cannot encode binary digests. `crypt(3)` remains experimental and opt-in
through `auth_crypt::fin`, with `strncpy` copying its static result and `-lcrypt`
required on modern glibc.

## API reference

### Passwords

| Function | Description |
|---|---|
| `password_hash(password: string) <string>` | Default 600k iterations, random 16-byte salt; `$pbkdf2-sha256$<iter>$<salt>$<hash>` |
| `password_verify(password, hash_str) <bool>` | Default verification bounds; false on malformed records without aborting |
| `password_hash_with_policy(password, policy) <string>` | Configurable PBKDF2 cost; empty literal on invalid input/policy |
| `password_verify_with_policy(password, hash_str, policy) <bool>` | Validate full record and work bounds before deriving |
| `password_needs_rehash(hash_str, policy) <bool>` | True for malformed/unsupported records or cost below target; never requests downgrade |
| `password_policy_default() <PasswordPolicy>` | Hash=600,000; verification minimum=1, maximum=1,000,000 |
| `password_policy_legacy() <PasswordPolicy>` | Explicit legacy hash=10,000; verification minimum=1, maximum=1,000,000 |
| `auth_pbkdf2_hex(password, salt_b64, iterations) <string>` | Raw PBKDF2 diagnostic (interop testing) |
| `password_hash_crypt(password, setting) <CryptResult>` | **Experimental** `crypt(3)` FFI (e.g. `$6$` SHA-512 crypt) |

`PasswordPolicy` fields are `hash_iterations`, `min_verify_iterations`, and
`max_verify_iterations` (all `int`). Require `1 <= min <= hash <= max <= 1,000,000`.
Benchmark a suitable target and maximum on deployment hardware; the ceiling is
not a security recommendation or a substitute for login rate limiting. Passwords
are limited to 4,096 bytes; records to 96 bytes, with canonical positive decimal
iterations, exactly 16 salt bytes and 32 digest bytes. Whole-record validation
precedes all KDF work. After a **successful** verification, use `needs_rehash`
to migrate accepted older hashes. Setting a higher verification minimum rejects
older hashes instead of migrating them. Hash/diagnostic strings are caller-owned
on success (`free_str`); failure empty literals must not be freed.

### JWT (HS256)

| Function | Description |
|---|---|
| `jwt_encode(payload_json, secret) <string>` | Compact JWT with fixed `{"alg":"HS256","typ":"JWT"}` header |
| `jwt_decode(token, secret) <JwtResult>` | Signature/header check only; does not validate JSON, expiration, issuer, or audience |
| `jwt_verify(token, secret, policy: JwtPolicy, now_unix: double) <JwtResult>` | Signature plus strict object payload, required numeric `exp`, optional numeric `nbf`, required issuer/audience |
| `jwt_decode_unverified(token) <JwtResult>` | Parse without verifying — inspection only, never trust |
| `jwt_claim(payload_json, name) <JwtClaimResult>` | One claim, stringified via finson |
| `jwt_exp(payload_json) <double>` | Numeric `exp`, or -1 |
| `jwt_is_expired(payload_json, now_unix: double) <bool>` | `exp` check (double space — finc can't lower float→int casts) |

`jwt_decode` rejects `alg=none` and any non-HS256 header by comparing the
header segment against the fixed expected value (no algorithm confusion).
Semantically equivalent reordered headers remain unsupported intentionally.

`JwtPolicy` contains nonempty `issuer: string`, `audience: string`, and
`clock_skew_secs: double` in `[0, 300]`. `jwt_verify` requires a 32–4,096 byte
shared key (length does not guarantee entropy). Use a cryptographically random
key. It rejects duplicate claims, invalid JSON/UTF-8/NUL, missing/wrong-type
claims, mismatched issuer/audience, and nonfinite/out-of-range timestamps.
Audience may be a matching string or an all-string array containing it.
Dates/clock must lie in `[0, 2^53-1]`; fractional NumericDates are accepted.
Expiration rejects `now - skew >= exp`; not-before rejects `now + skew < nbf`.
A present `nbf` must precede `exp`. Compact inputs are limited to 65,536 bytes.
Success `payload_json` is caller-owned (`free_str`); failure fields are literals.

### Base64url

`auth_b64url_decode` requires the URL-safe alphabet, no padding, a possible
encoded length, and zero unused trailing bits. Its owned buffer must be freed
with `auth_free_bytes` on success **and failure** (`len == -1`). Decoding is
capped at 16,777,216 input characters. `auth_b64url_encode` accepts explicit
lengths up to 12,582,912 bytes and no greater than `data.length`; invalid bounds
return an allocated empty string without reading the buffer. Every encoder
result is caller-owned (`free_str`), including empty input and invalid bounds.

### Sessions

| Function | Description |
|---|---|
| `session_store_new() <&SessionStore>` / `session_free(store)` | Create/destroy |
| `session_create(store, user_id, ttl_secs) <string>` | 64-hex-char token |
| `session_get(store, token) <string>` | user_id, or `""` when unknown/expired |
| `session_user_id_copy(store, token) <string>` | Caller-owned copy of the user_id; free with `free_str` |
| `session_destroy(store, token) <bool>` | Invalidate |
| `session_sweep(store) <int>` | Drop expired; returns count removed |
| `session_create_at(store, user_id, ttl_secs, now_unix)` | Explicit-clock creation; invalid TTL/overflow returns empty literal |
| `session_get_at(store, token, now_unix)` | Explicit-clock lookup; expires at `now >= deadline` |
| `session_sweep_at(store, now_unix)` | Deterministic expiration sweep |

Clock arguments are `long` Unix seconds. Existing wrappers call the real clock.
Lookup/logout compare token bytes, so tokens reconstructed from cookies work.

**Ownership.** The store owns the token and user id it keeps: `session_create*`
copies both, so the caller may free or reuse its strings immediately. The
returned token from `session_create*` is caller-owned and must be freed with
`free_str`. The string returned by `session_get`/`session_get_at` is the
store's own copy — do **not** free it; use `session_user_id_copy` when the
caller needs a string it owns. `session_free` releases every string and the
backing buffers the store allocated. The store is still a linear scan, holds
everything in memory, and is not persistent or shareable between processes.

### CSRF

`csrf_token() <string>` — 64 hex chars from the CSPRNG.
`csrf_check(a, b) <bool>` — requires two canonical 64-character lowercase-hex
tokens before constant-time comparison; absent, empty, short, or malformed
values are rejected, even when both inputs are equal.

## Verification status

**VERIFIED 2026-10-21** — frozen finc 0.4.0 (contract 3), sibling coordinated
sources, Linux. Existing and hardening tests pass at `-O0` and `-O2`, including
12 malformed-record child processes that must exit normally with false results,
independent PBKDF2 vectors, cost/migration policy, canonical base64url, serialized
cookie lookup/logout, deadline sweeps, strict JWT claims/duplicates and skew.
One 600,000-iteration default hash measured **0.580 seconds at -O2** and
**8.323 seconds at -O0** on this environment (monotonic-clock timing around
hashing only). These are observations, not deployment latency guarantees.
The suite hashes once with the default and otherwise uses explicit lower-cost
policies/vectors. Existing optional `crypt(3)` tests and the example also run successfully.

**Leak-free under LeakSanitizer at `-O0` and `-O2`.** The suite builds with
`FIN_CC` pointing at a leak-sanitizer `cc` wrapper; it reports no leaks. The
session store's rewrite is what made this true: the previous `Collection`
backed store leaked 384 bytes of backing buffers that `session_free` could
never reclaim, and the suite leaked 882 bytes in total. It now leaks zero.

Reproduce from these checkouts (Bash; repeat with `-O2`):

```bash
ROOT=/home/M1778/fin-projects
"$ROOT/.toolchain/bin/finc" "$ROOT/fin-auth/tests/test_auth.fin" \
  --fin-libs "$ROOT/.toolchain/lib/std" \
  -I "$ROOT/fin-auth/src" -I "$ROOT/fin-crypto/src" -I "$ROOT/finson/src" \
  -O0 -o "$ROOT/fin-auth/test_auth"
"$ROOT/fin-auth/test_auth"
```

The malformed-input probes retain POSIX `fork`, `waitpid`, and `_exit` on Linux
and macOS. `FIN_TARGET_WINDOWS` instead validates all 12 malformed records
in-process: a regression that aborts fails the test executable. POSIX declarations
and the `clock_gettime` import are excluded from that Windows branch. The optional
hash benchmark uses Linux/macOS monotonic clock IDs; Windows skips timing but
still hashes and verifies the emitted 600,000-iteration policy metadata.

Native Linux, macOS and Windows, each on x86-64 and ARM64, passed this project's
O0/O2 suite in [native run 40034937084](https://github.com/M1778/fin-sdk/actions/runs/40034937084),
at auth revision `7b997f79b8fae031cbddfe54cce8ca59476a01af`. All thirteen
projects passed across all six hosts in that run.
It used externally verified compiler candidate `5360b051b8e82a4f10052c3dbb77bc66cc727cd7`
from Fin CI run `40028977601`, not a released compiler. Older published Fin
revision `1f7afd97` lacks target selectors and cannot select these native
branches correctly. Use a matching verified compiler/stdlib pair; no compiler
changes are included or managed in this library.

`auth_crypt::fin` is a separate optional POSIX/libcrypt module, never imported by
`auth::fin` or the core test suite. Windows users must not build its optional test
or link libcrypt. On supported POSIX hosts, run the crypt test by compiling
`tests/test_auth_crypt.fin` with `-c -o test_auth_crypt.o`, then linking with
`cc test_auth_crypt.o -lcrypt -lm -o test_auth_crypt.exe`. Platform crypt algorithm
availability can differ; the supplied SHA-512-crypt vector is validated on Linux.

## Remaining limitations

- Tagged releases remain separate; source dependencies are pinned to pushed commits.
- JWT: HS256 and one exact header only; no key rotation/JWKS or replay store.
- The explicitly named legacy password policy remains 10,000 iterations and is
  not appropriate for new production hashes. The default is 600,000; deployment
  benchmarking and login rate limiting remain application responsibilities.
- The diagnostic `auth_pbkdf2_hex` retains programmer assertions on invalid
  parameters; use the policy password APIs for untrusted authentication inputs.
- Sessions remain linear-scan, in-memory, single-threaded/single-process, without
  persistence or distribution. The store now owns its strings and frees them
  and its buffers in `session_free`; it is not a leak-free production store in
  any other sense.
- `crypt(3)` remains experimental and uses process-static storage; it may fail
  to link without libcrypt and is unsuitable for concurrent calls without locking.
- No claim of constant-time machine-code proof or process-wide leak freedom is made.

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## License

MIT — see [LICENSE](LICENSE).
