---
name: dependabot-round-checks
description: What CI does not cover when merging a batch of Dependabot PRs — the source Dockerfile is never built, docs bumps pass Build MkDocs regardless, adjacent requirements.txt bumps conflict, and a release that misses the docs/changelog.md row turns every PR red
type: project
---

Learned while merging #396–#400 on 2026-11-22.

- **Every PR red on "Docs Consistency" only, right after a release:** the release PR shipped without the new series row in `docs/changelog.md`. v1.0.0 (#395, `810728c0`, 2026-11-16) did; its checklist item asks for it. `main` itself is red too. The row went in as a separate `docs(changelog)` commit on #398 (`86a17c19`).
- **The source `Dockerfile` is never built in CI.** `docker.yml` builds only `Dockerfile.release`, and the CI Build job compiles the gnu target on stable. So a `rust:X-alpine` bump needs a local `docker build`. To stay at half the cores, build a scratch copy with `ENV CARGO_BUILD_JOBS=<half>` inserted after `FROM`. Then start a prefixed container ([[live-test-container-names]] style) and wait for `healthy`. #400 (rust 1.100) built in ~5 min at 8 jobs.
- **Docs bumps:** Build MkDocs passing says little. Build the site twice in Python 3.12 venvs (CI's version), once per requirements set, and diff the HTML after normalizing the material `bundle.<hash>.min.js` name. That also proves `pymdownx.snippets` still pulls `CHANGELOG.md` into the changelog page.
- **Two pip PRs touching adjacent lines of `requirements.txt` conflict** once the first merges. Merging `origin/main` into the bot branch and pushing (no force push) resolved it.
- **Two Cargo.lock PRs:** before merging the second, a no-commit merge plus `cargo metadata --locked` confirms the combined lock resolves.
- **PR checks are frozen at their run date.** RUSTSEC-2026-0592 (`url` 2.5.8, published 2026-11-20) turned `main`'s Security Audit red right after five PRs that were green on 11-16. Watch `main`'s audit job after a round. The fix was PR #405 (`url` 2.5.9).

**How to apply:** before merging a Dependabot batch, compare each PR's failures with `main`'s own CI run, then run the checks above for whatever CI does not build.
