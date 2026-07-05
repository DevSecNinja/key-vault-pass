# Implementation plan — key-vault-pass

> The **how** for [`spec.md`](./spec.md). Technology choices, architecture, and
> the storage/auth contracts the implementation must honour.

## 1. Technology choices

**Rust** is used because the product handles highly sensitive secret material:
memory safety without a garbage collector, plus mature in-memory zeroization
(`zeroize`/`secrecy`), reduce the risk of secrets lingering in process memory.
The **Azure SDK for Rust reached 1.0 (GA)**, so Key Vault and Entra access rest
on Microsoft-authored, stable crates. All other crates are widely adopted and
actively maintained.

| Concern           | Crate                                 | Why                                           |
| ----------------- | ------------------------------------- | --------------------------------------------- |
| Entra auth (CLI)  | `azure_identity` 1.0                  | Credential chain (az CLI, MI, env SP).        |
| Key Vault secrets | `azure_security_keyvault_secrets` 1.0 | Official secrets data-plane client.           |
| Core primitives   | `azure_core` 1.0                      | Credentials, pageables, error types.          |
| Entra auth (web)  | `oauth2` 5.0                          | RFC-compliant auth-code + PKCE against Entra. |
| CLI framework     | `clap` 4 (derive)                     | De-facto standard, typed, ergonomic.          |
| Web framework     | `axum` 0.8 + `tokio` 1                | Mature, Tower-based async HTTP stack.         |
| Sessions          | `tower-sessions` 0.15                 | Signed, cookie-backed sessions for axum.      |
| Templating        | `tera` 2                              | Jinja-like server-side HTML rendering.        |
| Serialization     | `serde` + `serde_json` 1              | Entry <-> JSON secret payload.                |
| Secret hygiene    | `zeroize` 1, `secrecy` 0.10           | Scrub passwords/tokens from memory on drop.   |
| HTTP (web auth)   | `reqwest` 0.12                        | Token exchange transport for `oauth2`.        |
| Errors            | `thiserror` 2, `anyhow` 1             | Typed library errors; ergonomic app errors.   |
| Password RNG      | `rand` 0.9                            | CSPRNG (`OsRng`) for generation.              |

Tooling: **mise** pins the Rust toolchain; `cargo test`/`cargo clippy`/`cargo
fmt` for quality; the repo's existing lint stack (`dprint`, `yamlfmt`,
`actionlint`, `gitleaks`, …) is reused for non-Rust files.

## 2. Architecture — Cargo workspace

A workspace with one shared library and two binaries so the CLI and web app
share all domain logic:

```
Cargo.toml                 # [workspace] members
crates/
  kvp-core/                # shared library (no front-end concerns)
    src/
      lib.rs
      config.rs            # KVP_* settings
      error.rs             # thiserror domain error enum
      model.rs             # PasswordEntry, EntrySummary, name validation
      password.rs          # CSPRNG password generator
      secret_store.rs      # SecretStore trait (test boundary)
      vault.rs             # KeyVaultStore + VaultRepository CRUD mapping
      auth.rs              # credential + token-credential adapter
  kvp-cli/                 # binary `kvp`
    src/main.rs            # clap commands -> VaultRepository
  kvp-web/                 # binary `kvp-web`
    src/
      main.rs              # axum server bootstrap
      state.rs             # AppState (settings, tera, oauth client)
      auth.rs              # oauth2 auth-code + PKCE handlers
      routes.rs            # entry CRUD handlers
    templates/*.html       # tera UI
    static/app.css
```

The front ends depend only on `kvp-core`'s `VaultRepository` + models; neither
touches the Azure SDK directly beyond obtaining a credential/token.

## 3. Storage contract (entry <-> Key Vault secret)

- **Secret name** = entry `name`; validated against `^[0-9A-Za-z-]{1,127}$`.
- **Secret value** = compact JSON: `{"password","username","url","notes"}`
  (omitting empty fields). `content_type =
  application/json;profile=key-vault-pass`.
- **Tags** = `{"app": "key-vault-pass"}` marker only (never secret data). Listing
  filters on this tag so unrelated secrets in a shared vault are ignored.
- `created_at`/`updated_at` read from the secret attributes.
- Malformed/legacy values are treated as a password-only entry (best effort) so
  the tool degrades gracefully on secrets created elsewhere.
- The in-memory `PasswordEntry.password` is a `SecretString` (`secrecy`) so it is
  never accidentally logged and is zeroized on drop.

## 4. Auth contract

### CLI

`azure_identity`'s credential chain (developer tools + managed identity +
environment service principal) is passed to the Key Vault `SecretClient`. This
supports `az login`, managed identity, workload identity and SP env vars without
code changes.

### Web

1. Unauthenticated request -> redirect to `/auth/login`.
2. `oauth2` builds the Entra authorize URL with a random CSRF `state` and a PKCE
   verifier stored server-side in the session. Scope:
   `https://vault.azure.net/user_impersonation` + `openid profile offline_access`.
3. Entra redirects to `/auth/callback`; `state` is verified and the code is
   exchanged (with the PKCE verifier) for a Key Vault–scoped access token and
   claims.
4. Token + expiry are stored in the signed session. A `StaticTokenCredential`
   adapter feeds the token to the Key Vault client, so the vault sees the user's
   own delegated identity (their RBAC applies).
5. `/auth/logout` clears the session.

Sessions use `tower-sessions` with a signed cookie (`KVP_SESSION_SECRET`),
`HttpOnly`, `SameSite=Lax`, and `Secure` when not running locally.

## 5. Testing strategy

- `SecretStore` is a trait exposing only the operations `VaultRepository` needs
  (set/get/delete/list). A `FakeSecretStore` in tests implements it in-memory,
  enabling full CRUD tests with no network.
- A `FileSecretStore` (mock.rs) implements the same trait against a local JSON
  file for offline development; a `BackingStore` enum lets the CLI/web select
  the real Key Vault or the mock at runtime (`KVP_MOCK` / `--mock`). In mock
  mode the web app simulates Entra sign-in.
- Unit tests cover: entry<->secret JSON mapping, list/tag filtering + search,
  not-found and exists errors, name validation, and password-generation
  guarantees (length + required character classes).
- Web auth helpers (authorize-URL construction, state/PKCE handling) are unit
  tested; a route test asserts unauthenticated requests redirect to login.

## 6. Deployment (out-of-band, documented)

Per the operator persona and the "prefer az CLI over azure/* actions"
convention, deployment builds a release binary / container and uses `az`
commands (App Service or Container Apps) driven from the single `ci-cd.yml`. CI
runs `cargo fmt --check`, `cargo clippy -D warnings`, and `cargo test` on every
push; deploy is tag-gated and uses OIDC federated credentials (no stored cloud
secrets).
