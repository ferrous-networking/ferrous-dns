# Changelog

All notable changes to Ferrous DNS, newest first. Each entry links the pull request that made it and credits its author; the section of a release is also its [GitHub Release](https://github.com/ferrous-networking/ferrous-dns/releases) notes. Releases up to v0.9.3 predate this file and are listed only on GitHub Releases.

<!-- --8<-- [start:releases] -->

## [0.9.24](https://github.com/ferrous-networking/ferrous-dns/compare/v0.9.23...v0.9.24) - 2026-10-23

### ✨ Features

- **cache:** show how many times each cache entry was refreshed by @andersonviudes in [#296](https://github.com/ferrous-networking/ferrous-dns/pull/296)
- **web:** add upstream and cache refresh cards and align the ui by @andersonviudes in [#297](https://github.com/ferrous-networking/ferrous-dns/pull/297)

### 🐛 Bug Fixes

- **query-log:** log filtered queries as blocked with their own source by @andersonviudes in [#300](https://github.com/ferrous-networking/ferrous-dns/pull/300)

### ⬆️ Dependencies

- bump pymdown-extensions from 12.1 to 12.3 in the pip-minor-patch group by @dependabot[bot] in [#299](https://github.com/ferrous-networking/ferrous-dns/pull/299)
- bump the cargo-minor-patch group with 3 updates by @dependabot[bot] in [#298](https://github.com/ferrous-networking/ferrous-dns/pull/298)

## [0.9.23](https://github.com/ferrous-networking/ferrous-dns/compare/v0.9.22...v0.9.23) - 2026-10-17

### ✨ Features

- **api:** serve the remaining pi-hole v6 routes ferrous can answer by @andersonviudes in [#290](https://github.com/ferrous-networking/ferrous-dns/pull/290)
- **dns:** route chosen domains to their own pool, per client group by @andersonviudes in [#291](https://github.com/ferrous-networking/ferrous-dns/pull/291)
- **config:** configure malware detection from the settings page by @andersonviudes in [#292](https://github.com/ferrous-networking/ferrous-dns/pull/292)
- **web:** link the sidebar version to its release notes and the repo by @andersonviudes in [#294](https://github.com/ferrous-networking/ferrous-dns/pull/294)

### 🐛 Bug Fixes

- **dns:** stop caching upstream SERVFAILs and honor the negative TTL by @andersonviudes in [#282](https://github.com/ferrous-networking/ferrous-dns/pull/282)
- **cache:** renew each entry on its own timer and stop early exits by @andersonviudes in [#286](https://github.com/ferrous-networking/ferrous-dns/pull/286)
- keep the WAL from surviving shutdown and fix the docker build by @andersonviudes in [#287](https://github.com/ferrous-networking/ferrous-dns/pull/287)
- **api:** answer the pi-hole v6 api the way ftl does by @andersonviudes in [#289](https://github.com/ferrous-networking/ferrous-dns/pull/289)
- **dns:** refuse deleting a client group a pool still routes for by @andersonviudes in [#293](https://github.com/ferrous-networking/ferrous-dns/pull/293)
- **cache:** expire and evict entries on events, not periodic jobs by @andersonviudes in [#295](https://github.com/ferrous-networking/ferrous-dns/pull/295)

### ⬆️ Dependencies

- bump the cargo-minor-patch group with 6 updates by @dependabot[bot] in [#284](https://github.com/ferrous-networking/ferrous-dns/pull/284)
- bump rust from 1.98-alpine to 1.99-alpine by @dependabot[bot] in [#285](https://github.com/ferrous-networking/ferrous-dns/pull/285)

## [0.9.22](https://github.com/ferrous-networking/ferrous-dns/compare/v0.9.21...v0.9.22) - 2026-10-12

### 🐛 Bug Fixes

- **database:** keep a large query log from slowing down startup by @andersonviudes in [#278](https://github.com/ferrous-networking/ferrous-dns/pull/278)
- **dns:** echo the cookie on every reply and fix strict cookie mode by @andersonviudes in [#280](https://github.com/ferrous-networking/ferrous-dns/pull/280)

## [0.9.21](https://github.com/ferrous-networking/ferrous-dns/compare/v0.9.20...v0.9.21) - 2026-10-10

### ✨ Features

- **web:** serve dashboard assets from the binary so it works offline by @andersonviudes in [#274](https://github.com/ferrous-networking/ferrous-dns/pull/274)

### 🐛 Bug Fixes

- **database:** stop a large WAL from crash-looping startup by @andersonviudes in [#277](https://github.com/ferrous-networking/ferrous-dns/pull/277)

### 📚 Documentation

- **dns:** describe conditional forwarding as it actually works by @andersonviudes in [#273](https://github.com/ferrous-networking/ferrous-dns/pull/273)
- **dns:** add conditional forwarding to the roadmap by @andersonviudes in [#275](https://github.com/ferrous-networking/ferrous-dns/pull/275)

### ⬆️ Dependencies

- bump tokio-rustls from 0.26.5 to 0.26.6 in the cargo-minor-patch group by @dependabot[bot] in [#269](https://github.com/ferrous-networking/ferrous-dns/pull/269)
- bump codelytv/pr-size-labeler from 1.11.1 to 1.12.0 in the github-actions group by @dependabot[bot] in [#270](https://github.com/ferrous-networking/ferrous-dns/pull/270)

## [0.9.20](https://github.com/ferrous-networking/ferrous-dns/compare/v0.9.19...v0.9.20) - 2026-10-03

### ✨ Features

- **metrics:** export overload shed and drop totals on /metrics by @fbernier in [#268](https://github.com/ferrous-networking/ferrous-dns/pull/268)

### 🐛 Bug Fixes

- **dns:** keep local answers serviceable when upstreams saturate by @andersonviudes in [#264](https://github.com/ferrous-networking/ferrous-dns/pull/264)
- **dnssec:** require a signed proof before treating a name as insecure by @fbernier in [#265](https://github.com/ferrous-networking/ferrous-dns/pull/265)
- **dns:** echo the client's question spelling in relayed cached answers by @fbernier in [#267](https://github.com/ferrous-networking/ferrous-dns/pull/267)

### ⬆️ Dependencies

- bump the cargo-minor-patch group with 4 updates by @dependabot[bot] in [#257](https://github.com/ferrous-networking/ferrous-dns/pull/257)
- bump criterion from 0.7.0 to 0.8.2 by @dependabot[bot] in [#262](https://github.com/ferrous-networking/ferrous-dns/pull/262)
- bump pymdown-extensions from 12.0.1 to 12.1 in the pip-minor-patch group by @dependabot[bot] in [#263](https://github.com/ferrous-networking/ferrous-dns/pull/263)
- bump getrandom from 0.3.4 to 0.4.3 by @dependabot[bot] in [#261](https://github.com/ferrous-networking/ferrous-dns/pull/261)
- bump utoipa-axum from 0.2.0 to 0.3.0 by @dependabot[bot] in [#260](https://github.com/ferrous-networking/ferrous-dns/pull/260)
- bump utoipa to 6.0.0 and utoipa-scalar to 0.4.0 by @dependabot[bot] in [#258](https://github.com/ferrous-networking/ferrous-dns/pull/258)

### 👷 CI/CD

- label and assign fork PRs from pull_request_target by @andersonviudes in [#266](https://github.com/ferrous-networking/ferrous-dns/pull/266)

## [0.9.19](https://github.com/ferrous-networking/ferrous-dns/compare/v0.9.18...v0.9.19) - 2026-09-28

### ✨ Features

- **dns:** explain how to write upstream URLs in the settings and docs by @andersonviudes in [#255](https://github.com/ferrous-networking/ferrous-dns/pull/255)

### 🐛 Bug Fixes

- **web:** clear the restart banner once the server has restarted by @andersonviudes in [#236](https://github.com/ferrous-networking/ferrous-dns/pull/236)
- **query-log:** keep the domain column visible on laptop screens by @andersonviudes in [#237](https://github.com/ferrous-networking/ferrous-dns/pull/237)
- **dns:** validate local_dns_server answers like upstream answers by @andersonviudes in [#240](https://github.com/ferrous-networking/ferrous-dns/pull/240)
- **block-filter:** stop dropping large blocklists on slow links by @andersonviudes in [#252](https://github.com/ferrous-networking/ferrous-dns/pull/252)
- **dns:** don't cache a message whose names read TTL bytes by @fbernier in [#253](https://github.com/ferrous-networking/ferrous-dns/pull/253)

### ⚡ Performance

- **dns:** bounded tokio workloads and perf improvement by @fbernier in [#233](https://github.com/ferrous-networking/ferrous-dns/pull/233)
- **query-log:** serve dashboard aggregates from per-minute rollups and drop four query_log indexes by @fbernier in [#242](https://github.com/ferrous-networking/ferrous-dns/pull/242)
- **dns:** cut per-query cost on the resolution path and the UDP cache-hit path by @fbernier in [#241](https://github.com/ferrous-networking/ferrous-dns/pull/241)

### ♻️ Refactor

- simplify the workspace and fix the bugs the audit turned up by @fbernier in [#251](https://github.com/ferrous-networking/ferrous-dns/pull/251)

### 🔧 Miscellaneous

- share the team memory notes from the latest dns and api fixes by @andersonviudes

### 📋 Other

- Merge commit from fork by @andersonviudes

## [0.9.18](https://github.com/ferrous-networking/ferrous-dns/compare/v0.9.17...v0.9.18) - 2026-09-21

### 🐛 Bug Fixes

- **dns:** harden doh requests, response limits and h3 retries by @fbernier in [#226](https://github.com/ferrous-networking/ferrous-dns/pull/226)
- **dns:** return nodata for missing local record types by @fbernier in [#227](https://github.com/ferrous-networking/ferrous-dns/pull/227)
- **cache:** release the shard lock before fallback eviction removes by @andersonviudes in [#229](https://github.com/ferrous-networking/ferrous-dns/pull/229)

### ⬆️ Dependencies

- bump pymdown-extensions from 11.0.2 to 12.0.1 by @dependabot[bot] in [#232](https://github.com/ferrous-networking/ferrous-dns/pull/232)
- bump mkdocs-git-revision-date-localized-plugin from 1.5.4 to 1.6.0 in the pip-minor-patch group by @dependabot[bot] in [#231](https://github.com/ferrous-networking/ferrous-dns/pull/231)
- bump the cargo-minor-patch group with 4 updates by @dependabot[bot] in [#230](https://github.com/ferrous-networking/ferrous-dns/pull/230)

### 🎉 New contributors

- @fbernier made their first contribution in [#227](https://github.com/ferrous-networking/ferrous-dns/pull/227)

## [0.9.17](https://github.com/ferrous-networking/ferrous-dns/compare/v0.9.16...v0.9.17) - 2026-09-14

### ✨ Features

- **dns:** resolve wildcard local DNS records by @andersonviudes in [#224](https://github.com/ferrous-networking/ferrous-dns/pull/224)

### 🐛 Bug Fixes

- **docker:** ship patched openssl in the published images by @andersonviudes in [#222](https://github.com/ferrous-networking/ferrous-dns/pull/222)

### ⬆️ Dependencies

- bump the cargo-minor-patch group with 12 updates by @dependabot[bot] in [#221](https://github.com/ferrous-networking/ferrous-dns/pull/221)
- bump the cargo-minor-patch group with 5 updates by @dependabot[bot] in [#225](https://github.com/ferrous-networking/ferrous-dns/pull/225)

## [0.9.16](https://github.com/ferrous-networking/ferrous-dns/compare/v0.9.15...v0.9.16) - 2026-09-06

### 🐛 Bug Fixes

- **dns:** relay local_dns_server answers so LAN reverse lookups return the router's PTR by @pwnflakes in [#218](https://github.com/ferrous-networking/ferrous-dns/pull/218)
- **block-filter:** apply blocklist source changes without a restart by @andersonviudes in [#219](https://github.com/ferrous-networking/ferrous-dns/pull/219)

### 📚 Documentation

- rewrite the contributor guide and illustrate every dashboard page by @andersonviudes in [#220](https://github.com/ferrous-networking/ferrous-dns/pull/220)

### 🎉 New contributors

- @pwnflakes made their first contribution in [#218](https://github.com/ferrous-networking/ferrous-dns/pull/218)

## [0.9.15](https://github.com/ferrous-networking/ferrous-dns/compare/v0.9.14...v0.9.15) - 2026-09-04

### 🐛 Bug Fixes

- **auth:** drop the Secure cookie flag when HTTPS falls back to HTTP by @andersonviudes in [#215](https://github.com/ferrous-networking/ferrous-dns/pull/215)

### ⬆️ Dependencies

- bump pymdown-extensions from 11.0.1 to 11.0.2 in the pip-minor-patch group by @dependabot[bot] in [#213](https://github.com/ferrous-networking/ferrous-dns/pull/213)
- bump the cargo-minor-patch group with 2 updates by @dependabot[bot] in [#212](https://github.com/ferrous-networking/ferrous-dns/pull/212)

## [0.9.14](https://github.com/ferrous-networking/ferrous-dns/compare/v0.9.13...v0.9.14) - 2026-08-26

### 🐛 Bug Fixes

- **cache:** pace optimistic refresh by backlog, not a fixed rate by @andersonviudes in [#211](https://github.com/ferrous-networking/ferrous-dns/pull/211)

## [0.9.13](https://github.com/ferrous-networking/ferrous-dns/compare/v0.9.12...v0.9.13) - 2026-08-24

### ✨ Features

- **query-log:** record and display the client protocol on each query by @andersonviudes in [#205](https://github.com/ferrous-networking/ferrous-dns/pull/205)

### 🐛 Bug Fixes

- **web:** key Local DNS records by id so hosts with both A and AAAA render by @crahles in [#201](https://github.com/ferrous-networking/ferrous-dns/pull/201)
- **dns:** answer UDP queries on dual-stack and IPv6 binds by @crahles in [#202](https://github.com/ferrous-networking/ferrous-dns/pull/202)
- **dns:** key IPv4 clients on dual-stack listeners as plain IPv4 by @andersonviudes in [#204](https://github.com/ferrous-networking/ferrous-dns/pull/204)

### ⚡ Performance

- **cache:** drain optimistic refreshes through a paced queue by @andersonviudes in [#210](https://github.com/ferrous-networking/ferrous-dns/pull/210)

### ⬆️ Dependencies

- bump uuid from 1.24.0 to 1.24.1 in the cargo-minor-patch group by @dependabot[bot] in [#206](https://github.com/ferrous-networking/ferrous-dns/pull/206)
- update pygments requirement from <2.21.0 to <2.22.0 by @dependabot[bot] in [#209](https://github.com/ferrous-networking/ferrous-dns/pull/209)
- bump mkdocs-git-revision-date-localized-plugin from 1.5.3 to 1.5.4 in the pip-minor-patch group by @dependabot[bot] in [#208](https://github.com/ferrous-networking/ferrous-dns/pull/208)
- bump rust from 1.97-alpine to 1.98-alpine by @dependabot[bot] in [#207](https://github.com/ferrous-networking/ferrous-dns/pull/207)

### 🎉 New contributors

- @crahles made their first contribution in [#202](https://github.com/ferrous-networking/ferrous-dns/pull/202)

## [0.9.12](https://github.com/ferrous-networking/ferrous-dns/compare/v0.9.11...v0.9.12) - 2026-08-20

### ✨ Features

- **cache:** add a cache control page listing every cached entry by @andersonviudes in [#200](https://github.com/ferrous-networking/ferrous-dns/pull/200)

### ⬆️ Dependencies

- bump the cargo-minor-patch group with 4 updates by @dependabot[bot] in [#197](https://github.com/ferrous-networking/ferrous-dns/pull/197)
- bump h2 from 0.4.15 to 0.4.16 to fix RUSTSEC-2026-0258 by @andersonviudes in [#199](https://github.com/ferrous-networking/ferrous-dns/pull/199)

### 🔧 Miscellaneous

- add Claudin agent setup (AGENTS.md, rules, skills) by @andersonviudes in [#198](https://github.com/ferrous-networking/ferrous-dns/pull/198)

## [0.9.11](https://github.com/ferrous-networking/ferrous-dns/compare/v0.9.10...v0.9.11) - 2026-08-16

### 🐛 Bug Fixes

- **docker:** stop the restart loop when the config bind mount is a directory by @andersonviudes in [#196](https://github.com/ferrous-networking/ferrous-dns/pull/196)

### ⬆️ Dependencies

- bump fancy-regex from 0.18.0 to 0.19.0 by @dependabot[bot] in [#193](https://github.com/ferrous-networking/ferrous-dns/pull/193)
- bump the cargo-minor-patch group with 2 updates by @dependabot[bot] in [#192](https://github.com/ferrous-networking/ferrous-dns/pull/192)
- bump the cargo-minor-patch group with 5 updates by @dependabot[bot] in [#194](https://github.com/ferrous-networking/ferrous-dns/pull/194)

## [0.9.10](https://github.com/ferrous-networking/ferrous-dns/compare/v0.9.9...v0.9.10) - 2026-08-02

### ✨ Features

- **query-log:** record the resolved IPs and show them in an ANSWER column by @andersonviudes in [#191](https://github.com/ferrous-networking/ferrous-dns/pull/191)

### 📦 Build

- stop the dev profile from filling the disk with debug info by @andersonviudes

## [0.9.9](https://github.com/ferrous-networking/ferrous-dns/compare/v0.9.8...v0.9.9) - 2026-08-01

### ✨ Features

- **block-filter:** give manual allow/deny rules top priority by @andersonviudes in [#190](https://github.com/ferrous-networking/ferrous-dns/pull/190)

### 🐛 Bug Fixes

- **release:** commit the docs version banners with the version bump by @andersonviudes

### 📚 Documentation

- Update FUNDING.yml to include custom funding link by @andersonviudes in [#189](https://github.com/ferrous-networking/ferrous-dns/pull/189)
- update funding.yml by @andersonviudes
- Simplify FUNDING.yml format by @andersonviudes
- Update funding source in FUNDING.yml by @andersonviudes
- add a support page and point FUNDING.yml at it by @andersonviudes

### 👷 CI/CD

- **docs:** sync the version banners on every push to main, not at release by @andersonviudes
- skip the workflow on the bot's release commits by @andersonviudes

## [0.9.8](https://github.com/ferrous-networking/ferrous-dns/compare/v0.9.7...v0.9.8) - 2026-07-31

### 🐛 Bug Fixes

- **dnssec:** trust both root KSKs so the 2026-10-11 rollover is a no-op by @andersonviudes in [#186](https://github.com/ferrous-networking/ferrous-dns/pull/186)
- **dns:** advertise 1232-byte EDNS payload per DNS Flag Day 2020 by @andersonviudes
- **dns:** upstream anti-spoofing hardening and DNSSEC downgrade detection by @andersonviudes in [#187](https://github.com/ferrous-networking/ferrous-dns/pull/187)
- **cache:** stop corrupting non-ASCII bytes in oversized cache keys by @andersonviudes in [#188](https://github.com/ferrous-networking/ferrous-dns/pull/188)
- **block-filter:** match wildcard, adblock and substring rules at runtime by @andersonviudes
- **dns:** keep IDN and escapable labels off the UDP fast path by @andersonviudes
- **config:** nest the DNS cookie table under [dns] in the shipped config by @andersonviudes
- **fuzz:** write the PROXY v2 signature with hex escapes in the dictionary by @andersonviudes
- **dns:** gate the fast path on hickory's escaping rule, not "is printable" by @andersonviudes
- **fuzz:** decode only the question in the fast-path oracle by @andersonviudes

### ⚡ Performance

- **block-filter:** evict the decision cache in constant time by @andersonviudes

### 📚 Documentation

- reframe benchmark headline as same-tier, not a ranking by @andersonviudes
- **dns:** clarify why recv_matching drains non-matching datagrams by @andersonviudes
- correct the claims that no longer match the code, and gate the drift by @andersonviudes
- rebuild the generated site output by @andersonviudes

### 🧪 Testing

- **fuzz:** add a cargo-fuzz suite for the wire-format parsers by @andersonviudes

### 📋 Other

- rebuild the harness and publish all three scenarios by @andersonviudes

## [0.9.7](https://github.com/ferrous-networking/ferrous-dns/compare/v0.9.6...v0.9.7) - 2026-07-30

### 🐛 Bug Fixes

- **cache:** re-seed bloom on rotation so live entries stay cacheable by @andersonviudes in [#185](https://github.com/ferrous-networking/ferrous-dns/pull/185)

### 📚 Documentation

- **roadmap:** mark TOTP/2FA as shipped by @andersonviudes
- **installation:** document running on Windows via WSL2 by @andersonviudes

### ⬆️ Dependencies

- bump the cargo-minor-patch group with 4 updates by @dependabot[bot] in [#183](https://github.com/ferrous-networking/ferrous-dns/pull/183)
- bump base64 from 0.22.1 to 0.23.0 by @dependabot[bot] in [#184](https://github.com/ferrous-networking/ferrous-dns/pull/184)

## [0.9.6](https://github.com/ferrous-networking/ferrous-dns/compare/v0.9.5...v0.9.6) - 2026-07-22

### ✨ Features

- **auth:** TOTP 2FA and passkey/WebAuthn login by @andersonviudes in [#178](https://github.com/ferrous-networking/ferrous-dns/pull/178)

### 🐛 Bug Fixes

- **docker:** setcap for non-root port 53 bind, fix broken compose healthcheck and phantom ghcr.io image by @andersonviudes

### ⬆️ Dependencies

- bump mkdocs-material from 9.7.6 to 9.7.7 in the pip-minor-patch group by @dependabot[bot] in [#182](https://github.com/ferrous-networking/ferrous-dns/pull/182)
- bump compact_str from 0.9.1 to 0.10.0 by @dependabot[bot] in [#181](https://github.com/ferrous-networking/ferrous-dns/pull/181)
- bump the cargo-minor-patch group with 12 updates by @dependabot[bot] in [#180](https://github.com/ferrous-networking/ferrous-dns/pull/180)
- bump actions/setup-python from 6 to 7 in the github-actions group by @dependabot[bot] in [#179](https://github.com/ferrous-networking/ferrous-dns/pull/179)

## [0.9.5](https://github.com/ferrous-networking/ferrous-dns/compare/v0.9.4...v0.9.5) - 2026-07-16

### 🐛 Bug Fixes

- remove baked-in Docker credentials + close config-doc gaps by @andersonviudes in [#176](https://github.com/ferrous-networking/ferrous-dns/pull/176)
- **cache:** prevent startup hang when cache is disabled by @andersonviudes

## [0.9.4](https://github.com/ferrous-networking/ferrous-dns/compare/v0.9.3...v0.9.4) - 2026-07-13

### ✨ Features

- **dns:** DNS-over-QUIC (DoQ) server listener (RFC 9250) by @andersonviudes in [#174](https://github.com/ferrous-networking/ferrous-dns/pull/174)

### 🐛 Bug Fixes

- honor log_queries on hot path and republish fair benchmark by @andersonviudes in [#173](https://github.com/ferrous-networking/ferrous-dns/pull/173)

### ⬆️ Dependencies

- bump toml_edit from 0.24.1+spec-1.1.0 to 0.25.4+spec-1.1.0 by @dependabot[bot] in [#172](https://github.com/ferrous-networking/ferrous-dns/pull/172)
- bump toml from 0.9.11+spec-1.1.0 to 1.0.6+spec-1.1.0 by @dependabot[bot] in [#171](https://github.com/ferrous-networking/ferrous-dns/pull/171)
- bump the github-actions group with 2 updates by @dependabot[bot] in [#170](https://github.com/ferrous-networking/ferrous-dns/pull/170)
