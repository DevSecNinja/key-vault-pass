# Task breakdown — key-vault-pass

> Traceable work items derived from [`spec.md`](./spec.md) and
> [`plan.md`](./plan.md). All items are complete; each maps to functional
> requirements (FR) / NFRs.

## Phase 0 — Project setup

- [x] **T0.1** Pin the Rust toolchain + lint tools in `.mise.toml`; Cargo
      workspace with the approved crate set. (NFR-2, NFR-3)
- [x] **T0.2** `.gitignore`, `.gitattributes` (LF), `.env.example`, `README.md`,
      `Dockerfile`. Org lint configs (`dprint.json`, `.yamllint.yaml`, ...).

## Phase 1 — Core library (`kvp-core`)

- [x] **T1.1** `config.rs` — `Settings` from `KVP_*` env vars. (§7)
- [x] **T1.2** `error.rs` — `thiserror` domain error enum. (FR-2)
- [x] **T1.3** `model.rs` — `PasswordEntry` (`SecretString`), `EntrySummary`,
      `GeneratePasswordOptions`, name validation + JSON mapping. (§4)
- [x] **T1.4** `password.rs` — CSPRNG password generator. (FR-8)
- [x] **T1.5** `secret_store.rs` — `SecretStore` trait boundary. (NFR-4)
- [x] **T1.6** `vault.rs` — `VaultRepository` CRUD + tag filtering/search. (FR-3..7)
- [x] **T1.7** `keyvault.rs` — `KeyVaultStore` (Azure Key Vault data plane).
- [x] **T1.8** `auth.rs` — CLI credential chain; web `StaticTokenCredential`.
      (FR-1, FR-2)

## Phase 2 — CLI (`kvp`)

- [x] **T2.1** `clap` app with `set`, `get`, `list`, `search`, `delete`,
      `generate`. (FR-3..8)
- [x] **T2.2** Password input via secure prompt (`rpassword`), never argv. (NFR-1)

## Phase 3 — Web app (`kvp-web`)

- [x] **T3.1** `oauth2` auth-code + PKCE helpers; manual token exchange. (FR-1)
- [x] **T3.2** `axum` app: session middleware, auth routes, auth guard,
      `/healthz`. (NFR-1)
- [x] **T3.3** CRUD routes + Tera templates with masked/reveal passwords.
      (FR-3..7, FR-9)

## Phase 4 — Quality & delivery

- [x] **T4.1** `kvp-core` tests via in-memory `FakeSecretStore`. (NFR-4)
- [x] **T4.2** Web auth-helper + auth-guard redirect tests. (FR-1)
- [x] **T4.3** Single consolidated `ci-cd.yml` (lint reuse + fmt/clippy/test/build
      + release-please + az-based tag deploy). Release-please config for the Rust
      workspace (`release-please-config.json`, `.release-please-manifest.json`).

## Traceability matrix

| Requirement | Implemented by                                       |
| ----------- | ---------------------------------------------------- |
| FR-1        | `kvp-core::auth`, `kvp-web::auth`, `kvp-web::routes` |
| FR-2        | `kvp-core::vault`, `kvp-core::keyvault`, `error`     |
| FR-3        | `VaultRepository::set_entry`, CLI `set`, web POST    |
| FR-4        | `VaultRepository::get_entry`, CLI `get`, web GET     |
| FR-5        | `VaultRepository::list_entries`, CLI/web list        |
| FR-6        | `VaultRepository::list_entries(query)`, CLI `search` |
| FR-7        | `VaultRepository::delete_entry`, CLI/web delete      |
| FR-8        | `password::generate_password`                        |
| FR-9        | `kvp-web/templates/detail.html` (mask/reveal)        |
