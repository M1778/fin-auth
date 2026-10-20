# fin-auth

Authentication & sessions for Fin: JWT (HS256) encode/verify, password hashing
(PBKDF2-HMAC-SHA256), an in-memory session store, and CSRF token helpers.

The crypto-primitive/application-layer split is kept clean: every primitive
(HMAC, CSPRNG, constant-time comparison) comes from
[`fin-crypto`](https://github.com/M1778/fin-crypto); this module is the
application layer on top. JSON comes from
[`finson`](https://github.com/M1778/finson).

```fin
import { password_hash, password_verify, jwt_encode, jwt_decode } from auth::fin;

let hash = password_hash("correct-horse-battery-staple"); // store this
if (password_verify(candidate, hash)) {
    let token = jwt_encode("{\"sub\":\"user-42\"}", "server-secret");
}
```

## Installation

With [finn](https://github.com/M1778/finn) (manifest: `finn.toml`):

```toml
[packages]
fin-auth = "M1778/fin-auth@0.1.0"
```

Then `import { ... } from auth::fin;`.

## Dependencies

- [`M1778/fin-crypto@0.1.1`](https://github.com/M1778/fin-crypto) — HMAC-SHA256,
  `random_bytes` / `random_hex`, `const_time_eq`.
- [`M1778/finson@0.1.0`](https://github.com/M1778/finson) — claim extraction
  from JWT payloads.
- Fin std: `bits`, `strings`, `time`, `collection`.

### Documented implementation notes

1. **Hex/base64url helpers are local, not duplicated crypto.** `fin-crypto`
   v0.1.0 returns HMAC as hex strings only (no raw-bytes API), and std
   `base64_encode` is `strlen`-limited (cannot encode binary). This module
   therefore carries `auth_hex_to_bytes` and explicit-length
   `auth_b64url_encode`/`auth_b64url_decode`. Proposed as fin-crypto/std
   additions; no cryptographic primitive is reimplemented.
2. **`crypt(3)` is experimental.** Bound with its exact C ABI
   (`char *crypt(const char *key, const char *salt)`), buffer copied via
   `snprintf` `%s`. On modern glibc `crypt` lives in `libcrypt`, not `libc`,
   so linking may fail — the PBKDF2 path is the supported default.

## API reference

### Passwords

| Function | Description |
|---|---|
| `password_hash(password: string) <string>` | PBKDF2-HMAC-SHA256, 10k iterations, random 16-byte salt; `$pbkdf2-sha256$<iter>$<salt>$<hash>` |
| `password_verify(password, hash_str) <bool>` | Constant-time verify; false on malformed input |
| `auth_pbkdf2_hex(password, salt_b64, iterations) <string>` | Raw PBKDF2 diagnostic (interop testing) |
| `password_hash_crypt(password, setting) <CryptResult>` | **Experimental** `crypt(3)` FFI (e.g. `$6$` SHA-512 crypt) |

### JWT (HS256)

| Function | Description |
|---|---|
| `jwt_encode(payload_json, secret) <string>` | Compact JWT with fixed `{"alg":"HS256","typ":"JWT"}` header |
| `jwt_decode(token, secret) <JwtResult>` | Verify signature (constant-time) + header `alg`; returns payload JSON |
| `jwt_decode_unverified(token) <JwtResult>` | Parse without verifying — inspection only, never trust |
| `jwt_claim(payload_json, name) <JwtClaimResult>` | One claim, stringified via finson |
| `jwt_exp(payload_json) <double>` | Numeric `exp`, or -1 |
| `jwt_is_expired(payload_json, now_unix: double) <bool>` | `exp` check (double space — finc can't lower float→int casts) |

`jwt_decode` rejects `alg=none` and any non-HS256 header by comparing the
header segment against the fixed expected value (no algorithm confusion).

### Sessions

| Function | Description |
|---|---|
| `session_store_new() <&SessionStore>` / `session_free(store)` | Create/destroy |
| `session_create(store, user_id, ttl_secs) <string>` | 64-hex-char token |
| `session_get(store, token) <string>` | user_id, or `""` when unknown/expired |
| `session_destroy(store, token) <bool>` | Invalidate |
| `session_sweep(store) <int>` | Drop expired; returns count removed |

### CSRF

`csrf_token() <string>` — 64 hex chars from the CSPRNG.
`csrf_check(a, b) <bool>` — constant-time comparison.

## Verification status

**VERIFIED 2026-10-20** — built and executed with finc 0.4.0 (contract 3).
`tests/test_auth.fin` passes: base64url round-trips, two PBKDF2-HMAC-SHA256
vectors from Python `hashlib.pbkdf2_hmac`, password hash/verify round-trips,
a Python-generated JWT HS256 vector plus tamper/`alg=none`/malformed
rejections, claim/`exp` handling, and the session store lifecycle.
`tests/test_auth_crypt.fin` passes with `-lcrypt` (FIN_CC wrapper): the
`crypt(3)` `$6$` vector matches Python's `crypt` module, and bad settings
are rejected via crypt's `*0`/`*1` convention. `examples/basic.fin` runs
end-to-end (register → login → JWT → session → CSRF).


## Known limitations (v0.1.0)

- JWT: HS256 only (no RS256/ECDSA — needs bignum or FFI).
- PBKDF2 at 10,000 iterations (below OWASP's 210k+ recommendation; pure-Fin
  SHA-256 keeps interactive hashing affordable — raise once finc optimizes
  or a native KDF lands).
- Session store is in-memory and single-process (no persistence, no
  distribution).
- `crypt(3)` may fail to link where `libcrypt` isn't linked by default.

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## License

MIT — see [LICENSE](LICENSE).
