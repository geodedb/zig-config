# FIPS-140-3 Status — config

**REQ-ID:** REQ-FIPS-EXEMPT-001 — non-security crypto/hash/RNG sites are
allow-listed (exempt) from the workspace FIPS-140-3 routing requirement per
`docs/superpowers/specs/2026-06-20-fips-pqc-design.md` §5.

**Mode:** This library performs only **non-security** hashing: a string-keyed
hashmap context. It is **exempt** from the workspace FIPS-140-3 routing
requirement (see `fips` package spec
`docs/superpowers/specs/2026-06-20-fips-pqc-design.md` §5). No site produces,
protects, or verifies a secret, key, credential, authentication tag, or
signature; therefore none is routed through the `crypto_backend` seam and none
links the OpenSSL FIPS provider. When a consumer builds with `-Dfips=true`,
this library is unaffected: it adds no `-Dfips` flag and changes no behavior.

## Exempt call sites

| File:Line | Primitive | Use | Why non-security (exempt) |
|-----------|-----------|-----|---------------------------|
| `src/config.zig:35` | `std.hash.Wyhash` | String-keyed hashmap context (config keys) | Lookup only; not a secret |

Line numbers are pre-annotation approximations.

## Secret zeroization

`src/secret.zig:313` defines `secureZero`, a defense-in-depth memory-hygiene
routine that overwrites a buffer with zeros using a `*volatile u8` write to
prevent the compiler from eliding the clear. It does **not** call
`std.crypto.secureZero` and is **not** a `std.crypto` / `std.hash` /
`std.Random` call site, so the zlint FIPS rule does not flag it and no inline
annotation is required. Its callers in `src/remote.zig` and
`src/encrypted_secrets.zig` invoke this same helper for memory hygiene only.
This zeroization is exempt from FIPS routing: zeroing freed memory is not a
cryptographic transform, produces no key/tag/ciphertext, and changes no
behavior under `-Dfips=true`.

## zlint allow-list

The Wyhash site above carries an inline
`// fips-exempt: non-security — <reason>` annotation so the `zlint` FIPS rule
treats it as allow-listed rather than a violation. Adding a new `std.crypto` /
`std.hash` / `std.Random` use to this library REQUIRES adding both the inline
annotation and a row in the table above.
