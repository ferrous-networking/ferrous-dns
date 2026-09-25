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
├── crates/ (721)                   ← workspace member crates
│   ├── api-pihole/ (46)            ← Pi-hole-compatible API
│   │   ├── src/ (33)               ← TODO
│   │   │   ├── dto/ (14)           ← TODO
│   │   │   └── handlers/ (13)      ← TODO
│   │   └── tests/ (13)             ← TODO
│   ├── api/ (102)                  ← axum REST API + OpenAPI
│   │   ├── src/ (79)               ← TODO
│   │   │   ├── dto/ (31)           ← TODO
│   │   │   ├── handlers/ (38)      ← TODO
│   │   │   └── middleware/ (3)     ← TODO
│   │   └── tests/ (24)             ← TODO
│   │       └── helpers/ (4)        ← TODO
│   ├── application/ (207)          ← use cases + port traits
│   │   ├── src/ (178)              ← TODO
│   │   │   ├── ports/ (42)         ← TODO
│   │   │   └── use_cases/ (133)    ← TODO
│   │   └── tests/ (31)             ← TODO
│   ├── cli/ (33)                   ← the binary; wires everything
│   │   ├── src/ (30)               ← TODO
│   │   │   ├── bootstrap/ (5)      ← TODO
│   │   │   ├── server/ (13)        ← TODO
│   │   │   └── wiring/ (9)         ← TODO
│   │   └── tests/ (5)              ← TODO
│   ├── domain/ (78)                ← pure business logic, no I/O
│   │   ├── src/ (58)               ← TODO
│   │   │   ├── config/ (22)        ← TODO
│   │   │   ├── dns_record/ (4)     ← TODO
│   │   │   ├── entities/ (22)      ← TODO
│   │   │   └── value_objects/ (7)  ← TODO
│   │   └── tests/ (22)             ← TODO
│   ├── infrastructure/ (234)       ← DB, DNS adapters, auth
│   │   ├── src/ (153)              ← TODO
│   │   │   ├── auth/ (7)           ← TODO
│   │   │   ├── dns/ (110)          ← TODO
│   │   │   ├── repositories/ (25)  ← TODO
│   │   │   ├── schedule/ (3)       ← TODO
│   │   │   └── system/ (3)         ← TODO
│   │   └── tests/ (87)             ← TODO
│   │       └── helpers/ (3)        ← TODO
│   └── jobs/ (21)                  ← background jobs
│       ├── src/ (14)               ← TODO
│       └── tests/ (7)              ← TODO
├── fuzz/ (5)                       ← libFuzzer workspace (nightly)
│   └── fuzz_targets/ (5)           ← the 5 fuzz targets
├── migrations/ (52)                ← sqlx migrations, append-only
├── site/ (38)                      ← generated MkDocs output; bot-committed
│   └── assets/ (36)                ← generated site assets
│       └── javascripts/ (36)       ← TODO
│           └── lunr/ (34)          ← TODO
├── tests/ (10)                     ← integration/performance harness crate
│   ├── common/ (3)                 ← shared fixtures + test server
│   └── performance/ (5)            ← competitor benchmarks (#[ignore]d)
└── web/ (11)                       ← admin UI frontend
    └── static/ (11)                ← vanilla HTML/CSS/JS served by the API
```
