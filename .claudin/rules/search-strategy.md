---
paths:
  - "**/*.rs"
  - "**/*.sql"
  - "**/*.js"
---
<!-- claudin:module-map -->
# Module Map

Generated from the tracked file list, and meant to be edited by hand. The
structure and the `(N)` counts are kept current automatically; the `←`
annotations are not — replace each `TODO` with what the directory is for,
and that text will survive every later refresh.

```
├── crates/ (721)                 ← workspace member crates
│   ├── api-pihole/ (46)          ← Pi-hole-compatible API
│   ├── api/ (102)                ← axum REST API + OpenAPI
│   ├── application/ (207)        ← use cases + port traits
│   ├── cli/ (33)                 ← the binary; wires everything
│   ├── domain/ (78)              ← pure business logic, no I/O
│   ├── infrastructure/ (234)     ← DB, DNS adapters, auth
│   └── jobs/ (21)                ← background jobs
├── fuzz/ (5)                     ← libFuzzer workspace (nightly)
│   └── fuzz_targets/ (5)         ← the 5 fuzz targets
├── migrations/ (52)              ← sqlx migrations, append-only
├── site/ (38)                    ← generated MkDocs output; bot-committed
│   └── assets/ (36)              ← generated site assets
├── tests/ (10)                   ← integration/performance harness crate
│   ├── common/ (3)               ← shared fixtures + test server
│   └── performance/ (5)          ← competitor benchmarks (#[ignore]d)
└── web/ (11)                     ← admin UI frontend
    └── static/ (11)              ← vanilla HTML/CSS/JS served by the API
```
