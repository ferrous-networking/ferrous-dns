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
├── crates/ (876)                   ← workspace member crates
│   ├── api-pihole/ (69)            ← Pi-hole-compatible API
│   │   ├── src/ (48)               ← TODO
│   │   │   ├── dto/ (19)           ← TODO
│   │   │   └── handlers/ (17)      ← TODO
│   │   └── tests/ (19)             ← TODO
│   │       └── helpers/ (3)        ← TODO
│   ├── api/ (113)                  ← axum REST API + OpenAPI
│   │   ├── src/ (79)               ← TODO
│   │   │   ├── dto/ (31)           ← TODO
│   │   │   └── handlers/ (38)      ← TODO
│   │   └── tests/ (37)             ← TODO
│   │       └── helpers/ (4)        ← TODO
│   ├── application/ (233)          ← use cases + port traits
│   │   ├── src/ (197)              ← TODO
│   │   │   ├── ports/ (52)         ← TODO
│   │   │   └── use_cases/ (147)    ← TODO
│   │   └── tests/ (45)             ← TODO
│   │       └── helpers/ (3)        ← TODO
│   ├── cli/ (59)                   ← the binary; wires everything
│   │   ├── src/ (35)               ← TODO
│   │   │   ├── bootstrap/ (5)      ← TODO
│   │   │   ├── server/ (13)        ← TODO
│   │   │   └── wiring/ (9)         ← TODO
│   │   └── tests/ (23)             ← TODO
│   ├── domain/ (78)                ← pure business logic, no I/O
│   │   ├── src/ (58)               ← TODO
│   │   │   ├── config/ (22)        ← TODO
│   │   │   ├── entities/ (22)      ← TODO
│   │   │   └── value_objects/ (7)  ← TODO
│   │   └── tests/ (26)             ← TODO
│   ├── infrastructure/ (300)       ← DB, DNS adapters, auth
│   │   ├── src/ (153)              ← TODO
│   │   │   ├── auth/ (7)           ← TODO
│   │   │   ├── database/ (3)       ← TODO
│   │   │   ├── dns/ (110)          ← TODO
│   │   │   ├── repositories/ (25)  ← TODO
│   │   │   └── system/ (3)         ← TODO
│   │   └── tests/ (163)            ← TODO
│   │       ├── helpers/ (3)        ← TODO
│   │       └── support/ (9)        ← TODO
│   └── jobs/ (21)                  ← background jobs
│       ├── src/ (14)               ← TODO
│       └── tests/ (7)              ← TODO
├── fuzz/ (5)                       ← libFuzzer workspace (nightly)
│   └── fuzz_targets/ (5)           ← the 5 fuzz targets
├── migrations/ (72)                ← sqlx migrations, append-only
├── tests/ (10)                     ← integration/performance harness crate
│   ├── common/ (3)                 ← shared fixtures + test server
│   └── performance/ (5)            ← competitor benchmarks (#[ignore]d)
└── web/ (61)                       ← admin UI frontend
    └── static/ (61)                ← vanilla HTML/CSS/JS served by the API
        └── vendor/ (20)            ← TODO
```
