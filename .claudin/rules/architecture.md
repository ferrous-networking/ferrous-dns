---
paths: crates/**/*.rs
---

# Architecture — Clean Architecture

Dependency direction (enforced by each crate's Cargo.toml — check it before adding a dep):

```
cli → api / api-pihole / jobs → infrastructure → application → domain
```

- `domain` — zero workspace deps and **zero `async fn`**; no tokio/sqlx. Entities, DNS record types, `DomainError`.
- `application` — depends on `domain` only. Owns **all port traits** (`src/ports/`, one file per port) and use cases (`src/use_cases/<context>/`, one file per use case). No sqlx/axum/reqwest.
- `infrastructure` — implements the ports: `Sqlite*Repository` in `src/repositories/`, DNS internals (resolver, block_filter, cache) in `src/dns/`.
- `api` / `api-pihole` — consume concrete use cases via `AppState`; `infrastructure` appears only in their dev-dependencies (tests). Handlers stay thin.
- `jobs` — receives ports as `Arc<dyn Port>` (e.g. `BlocklistSyncJob` gets `Arc<dyn BlockFilterEnginePort>`).
- `cli` — the only crate that may depend on all others; manual DI in `src/wiring/` (`Repositories` → `UseCases` → `build_app_state`). No DI container.

Patterns to follow:

- **New capability** = port trait in `application/src/ports/` + use case struct `XxxUseCase` with `new(Arc<dyn Port>)` and `async fn execute(...)` + adapter in `infrastructure`. Reference: `BlocklistRepository` → `SqliteBlocklistRepository`.
- **Errors**: everything returns `Result<_, DomainError>` (single thiserror enum in `domain/src/errors/domain_error.rs`); the API maps variants to status codes via `ApiError(pub DomainError)`. `anyhow` is allowed in `cli` only.
- Domain decisions (record semantics, entities) belong in `domain`; orchestration (query handling, guards, cache policy) belongs in `application`; wire/format/IO details belong in `infrastructure`.
