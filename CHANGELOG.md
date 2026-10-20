# Changelog — fin-auth

## [0.1.0] — 2026-10-20
### Added
- Password hashing: PBKDF2-HMAC-SHA256 (10k iterations, 16-byte salt,
  `$pbkdf2-sha256$` format) with constant-time verify; `auth_pbkdf2_hex`
  interop diagnostic.
- `crypt(3)` C FFI binding with exact C ABI (EXPERIMENTAL — libcrypt link
  risk documented); buffer copied via snprintf `%s`.
- JWT HS256: encode, verify (constant-time signature, fixed-header alg
  check rejecting `none`/confusion), unverified parse, claim extraction via
  finson, `exp` handling in double space (no float->int casts).
- In-memory session store (parallel collections; create/get/destroy/sweep).
- CSRF token helpers (CSPRNG + constant-time check).
- Local `auth_hex_to_bytes` + explicit-length base64url (documented: fin-crypto
  has no raw-bytes HMAC API yet; std base64 is strlen-limited).
- Test suite: Python-generated PBKDF2/JWT/crypt vectors, tamper and
  alg=none rejections, session lifecycle.
- Examples: end-to-end register/login/JWT/session flow. Full scaffold:
  finn.toml (deps `M1778/fin-crypto@0.1.0`, `M1778/finson@0.1.0`), CI, MIT.

### Notes
- UNVERIFIED: no working finc in the build environment; tests not yet run.
- Known limits: HS256 only; 10k PBKDF2 iterations (documented, to raise);
  in-memory sessions only.
