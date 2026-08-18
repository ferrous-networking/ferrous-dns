---
paths: crates/**/*.rs
---

# Code standards — SOLID & Clean Code (Rust)

## SOLID em Rust

- **SRP** — um use case por arquivo, uma struct, um `execute`. Referência: `application/src/use_cases/blocklist_sources/create_blocklist_source.rs`. Se um arquivo ganhou uma segunda responsabilidade, extraia um novo use case em vez de crescer o existente.
- **OCP** — comportamento novo = nova impl de port trait, sem tocar código existente. Ex.: `SqliteBlocklistSourceRepository` (produção) e `MockBlocklistSourceRepository` (`application/tests/helpers/mock_repositories.rs`) implementam a mesma trait; adicionar um backend novo não muda os use cases.
- **DIP** — use cases recebem `Arc<dyn Port>` no construtor e nunca conhecem a implementação concreta (`create_blocklist_source.rs:14`). Concreto só aparece no wiring (`cli/src/wiring/use_cases.rs`) e em dev-dependencies de testes.
- **ISP** — ports pequenas e focadas: bom exemplo é `whitelist_repository.rs` (4 métodos) e `upstream_reload_port.rs` (1 método). Não engorde traits existentes com métodos de outro contexto — `mfa_repository.rs` (17 métodos) é o anti-padrão a não repetir; prefira uma trait nova.
- **Composição** — sem hierarquias: structs com campos + traits. Injeção manual em camadas (`Repositories` → `UseCases` com `with_*` opcionais em `cli/src/wiring/use_cases.rs:159`).

## Clean Code

- **Nomes**: verbos em funções (`create_*`, `validate_*`, `resolve_*`); `is_*`/`has_*`/`can_*` para booleanos; tipos com vocabulário do domínio (`WhitelistedDomain`, `Nat64Prefix`). Sem abreviações inventadas.
- **Guard clauses**: valide cedo e saia com `?` — sequência plana de validações no topo do `execute` (ver `create_blocklist_source.rs:30`). Evite `if` aninhado; em erro, retorne na hora.
- **Erros**: sempre `Result<_, DomainError>` com `map_err` explícito + `?` (o projeto não usa `#[from]` — siga o padrão existente). Sem `unwrap`/`expect`/`panic!` fora de testes.
- **Imutabilidade**: entidades com construtor validado (`BlocklistSource::new` valida e retorna `Result`) e campos `Arc<str>` para strings compartilhadas. Newtype NÃO é o padrão do projeto — não introduza.
- **Testes**: integração em `crates/<crate>/tests/*.rs` com helpers compartilhados; nomes descritivos `test_<o_que>_<condição>` (ex.: `test_validate_name_empty`). Builders de teste ficam em `domain/tests/helpers/builders.rs` — reaproveite.
- **Duplicação**: antes de escrever helper novo, procure em `application/tests/helpers/` e `domain/tests/helpers/` — mocks e builders já existem para a maioria das ports.

## Enforcement mecânico (não burlar)

O projeto não tem `clippy.toml` nem `#![deny]` nos lib.rs — o gate é CI: `cargo fmt --check` + `clippy --all-targets --all-features -- -D warnings`. Rode `make ci` antes de finalizar; não adicione `#[allow(...)]` para silenciar lint sem discutir.
