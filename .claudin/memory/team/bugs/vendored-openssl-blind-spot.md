---
name: vendored-openssl-blind-spot
description: The binary statically links a vendored OpenSSL via webauthn-rs that neither Trivy nor cargo audit can see
type: project
paths: crates/infrastructure/Cargo.toml
---

`crates/infrastructure/Cargo.toml` declares `openssl = { version = "0.10",
features = ["vendored"] }` purely so `webauthn-rs` cross-compiles to
aarch64/musl. That compiles a full OpenSSL **into** the binary — as of
2026-09-09 `openssl-src 300.6.1+3.6.3`, i.e. OpenSSL 3.6.3.

OpenSSL 3.6.3 is affected by the whole August 2026 advisory batch (the same ten
CVEs the Trivy alerts list), first fixed in **3.6.4**. Nothing in the pipeline
sees this:

- Trivy scans OS packages and finds the apk `libssl3`, not the statically linked
  copy (the binary is stripped and not built with `cargo auditable`).
- `cargo audit` is clean — RustSec has no advisory for `openssl-src`.

There is no upgrade path yet: crates.io tops out at `300.6.1+3.6.3` on the 300.x
line, and `400.0.1+4.0.2` (OpenSSL 4.0.2, fixed) is unusable because
`openssl-sys` 0.9.117 requires `^300.2.0`. `webauthn-rs` 0.5.5 is the newest
stable and depends on OpenSSL unconditionally (0.6 is `-dev` only).

Exploitability is nil today: no crate in the workspace calls `openssl::`
directly, QUIC uses `quinn` + `rustls-aws-lc-rs`, HTTP uses `reqwest`/rustls, and
the ten CVEs all need QUIC server, DTLS, CMP, `CMS_decrypt`, TLS raw public keys
or low-level `EVP_Cipher` AEAD — none of which WebAuthn attestation touches.

**Why:** the image can be certified clean while the binary still carries an
unpatched OpenSSL; anyone reading only the Security tab would miss it.

**How to apply:** watch for an `openssl-src` release vendoring 3.6.4+ (or an
`openssl-sys` that accepts the 400.x line) and bump it, then re-check with
`curl -s https://index.crates.io/op/en/openssl-src`. Related:
[[container-cve-triage]].
