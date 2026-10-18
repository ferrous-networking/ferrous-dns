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
├── crates/ (795)                   ← workspace member crates
│   ├── api-pihole/ (69)            ← Pi-hole-compatible API
│   │   ├── src/ (48)               ← TODO
│   │   │   ├── dto/ (19)           ← TODO
│   │   │   └── handlers/ (17)      ← TODO
│   │   └── tests/ (19)             ← TODO
│   │       └── helpers/ (3)        ← TODO
│   ├── api/ (102)                  ← axum REST API + OpenAPI
│   │   ├── src/ (79)               ← TODO
│   │   │   ├── dto/ (31)           ← TODO
│   │   │   └── handlers/ (38)      ← TODO
│   │   └── tests/ (28)             ← TODO
│   │       └── helpers/ (4)        ← TODO
│   ├── application/ (233)          ← use cases + port traits
│   │   ├── src/ (197)              ← TODO
│   │   │   ├── ports/ (52)         ← TODO
│   │   │   └── use_cases/ (133)    ← TODO
│   │   └── tests/ (36)             ← TODO
│   ├── cli/ (41)                   ← the binary; wires everything
│   │   ├── src/ (30)               ← TODO
│   │   │   ├── bootstrap/ (5)      ← TODO
│   │   │   ├── server/ (13)        ← TODO
│   │   │   └── wiring/ (9)         ← TODO
│   │   └── tests/ (9)              ← TODO
│   ├── domain/ (78)                ← pure business logic, no I/O
│   │   ├── src/ (58)               ← TODO
│   │   │   ├── config/ (22)        ← TODO
│   │   │   ├── entities/ (22)      ← TODO
│   │   │   └── value_objects/ (7)  ← TODO
│   │   └── tests/ (22)             ← TODO
│   ├── infrastructure/ (264)       ← DB, DNS adapters, auth
│   │   ├── src/ (153)              ← TODO
│   │   │   ├── auth/ (7)           ← TODO
│   │   │   ├── dns/ (110)          ← TODO
│   │   │   ├── repositories/ (25)  ← TODO
│   │   │   └── system/ (3)         ← TODO
│   │   └── tests/ (132)            ← TODO
│   │       ├── helpers/ (3)        ← TODO
│   │       └── support/ (3)        ← TODO
│   └── jobs/ (21)                  ← background jobs
│       ├── src/ (14)               ← TODO
│       └── tests/ (7)              ← TODO
├── fuzz/ (5)                       ← libFuzzer workspace (nightly)
│   └── fuzz_targets/ (5)           ← the 5 fuzz targets
├── migrations/ (65)                ← sqlx migrations, append-only
├── site/ (38)                      ← generated MkDocs output; bot-committed
│   └── assets/ (36)                ← generated site assets
│       └── javascripts/ (36)       ← TODO
│           └── lunr/ (34)          ← TODO
├── tests/ (10)                     ← integration/performance harness crate
│   ├── common/ (3)                 ← shared fixtures + test server
│   └── performance/ (5)            ← competitor benchmarks (#[ignore]d)
└── web/ (16)                       ← admin UI frontend
    └── static/ (16)                ← vanilla HTML/CSS/JS served by the API
        └── vendor/ (4)             ← TODO
```
