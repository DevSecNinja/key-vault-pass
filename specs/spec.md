# Specification — key-vault-pass

> Spec-driven development: this document defines **what** we build and **why**.
> The **how** lives in [`plan.md`](./plan.md); the work items live in
> [`tasks.md`](./tasks.md).

## 1. Summary

`key-vault-pass` is an enterprise-grade password manager that stores secrets in
**Azure Key Vault** and authenticates users through **Microsoft Entra ID**. It
ships two front ends that share a single core library:

- a **CLI** for engineers and automation, and
- a **web app** for interactive, browser-based use.

Azure Key Vault is the single source of truth: the product never stores secret
material at rest anywhere else. Access is always governed by Entra identity and
Key Vault RBAC.

## 2. Goals & non-goals

### Goals

- Store, retrieve, list, search and delete password entries backed by Key Vault
  secrets.
- Authenticate exclusively via Microsoft Entra ID (no local password database).
- Authorize using the _caller's own_ Entra identity and Key Vault RBAC — the app
  adds no parallel permission system.
- Provide a consistent experience across CLI and web via a shared core library.
- Generate strong random passwords.
- Be deployable to Azure using enterprise-standard, well-known dependencies only.

### Non-goals

- Managing certificates or keys (only Key Vault **secrets**).
- Client-side/end-to-end encryption beyond what Key Vault provides.
- Multi-tenant SaaS hosting, billing, or team-sharing workflows.
- Mobile or desktop native apps.
- Browser auto-fill / extension integration.

## 3. Personas

- **Engineer (CLI):** authenticates with `az login`, managed identity, or a
  service principal; scripts secret access into pipelines.
- **Business user (web):** signs in through the browser with their Entra account
  and manages personal/team passwords via a UI.
- **Operator:** provisions the Key Vault, assigns RBAC roles, and deploys the web
  app.

## 4. Domain model

A **password entry** maps 1:1 to a Key Vault **secret**:

| Field                     | Storage                            | Notes                                    |
| ------------------------- | ---------------------------------- | ---------------------------------------- |
| `name`                    | Key Vault secret name              | `^[0-9A-Za-z-]{1,127}$` (Key Vault rule) |
| `password`                | JSON field inside the secret value | Required.                                |
| `username`                | JSON field inside the secret value | Optional.                                |
| `url`                     | JSON field inside the secret value | Optional.                                |
| `notes`                   | JSON field inside the secret value | Optional, free text.                     |
| `created_at`/`updated_at` | Key Vault secret properties        | Managed by Key Vault.                    |

The secret **value** is a JSON document
(`content_type = application/json;profile=key-vault-pass`) so _all_ fields —
including metadata — inherit Key Vault encryption at rest. Tags carry only a
non-secret `app=key-vault-pass` marker used to distinguish managed entries.

## 5. Functional requirements

- **FR-1 Authentication.** All access requires a valid Entra identity. The CLI
  uses `DefaultAzureCredential`; the web app uses the Entra OAuth 2.0
  authorization-code flow with PKCE.
- **FR-2 Authorization.** Operations use the caller's delegated token against the
  Key Vault data plane; failures surface Key Vault's own 403 semantics.
- **FR-3 Create/Update entry.** Set an entry by name with password + optional
  metadata. Re-setting an existing name creates a new Key Vault version.
- **FR-4 Get entry.** Retrieve a single entry (all fields) by name.
- **FR-5 List entries.** List names of managed entries with timestamps, without
  exposing secret values.
- **FR-6 Search entries.** Filter the list by a case-insensitive substring of the
  name.
- **FR-7 Delete entry.** Delete an entry by name.
- **FR-8 Generate password.** Produce a cryptographically strong password with
  configurable length and character classes.
- **FR-9 Reveal control (web).** Passwords are masked by default in the UI and
  revealed only on explicit user action; the web app never logs secret values.

## 6. Non-functional requirements

- **NFR-1 Security.** No secret material in logs, error messages, or the CLI
  process table. Secret-bearing values are held in memory-zeroizing wrappers
  (`zeroize`/`secrecy`) and scrubbed on drop. Web sessions are signed,
  `HttpOnly`, `SameSite=Lax`, and `Secure` in production. State/PKCE verifier
  protect the auth flow.
- **NFR-2 Dependencies.** Only well-known, maintained crates (Microsoft Azure
  SDK for Rust, `clap`, `axum`, `tokio`, `oauth2`, `serde`). Pinned and
  Renovate-managed.
- **NFR-3 Portability.** Builds a self-contained binary for Linux, macOS and
  Windows with the pinned Rust toolchain (1.96+).
- **NFR-4 Testability.** Core logic is unit-testable without a live Key Vault via
  an injectable secret-client boundary.
- **NFR-5 Observability.** Structured, secret-free logging at configurable level.

## 7. Configuration (environment variables)

| Variable                  | Used by   | Purpose                                               |
| ------------------------- | --------- | ----------------------------------------------------- |
| `KVP_VAULT_URL`           | CLI + web | Key Vault URL, e.g. `https://myvault.vault.azure.net` |
| `KVP_ENTRA_TENANT_ID`     | web       | Entra tenant (directory) ID.                          |
| `KVP_ENTRA_CLIENT_ID`     | web       | App registration (client) ID.                         |
| `KVP_ENTRA_CLIENT_SECRET` | web       | App registration client secret.                       |
| `KVP_ENTRA_REDIRECT_URI`  | web       | OAuth redirect URI.                                   |
| `KVP_SESSION_SECRET`      | web       | Key used to sign session cookies.                     |
| `KVP_LOG_LEVEL`           | CLI + web | Logging verbosity (default `INFO`).                   |

## 8. Acceptance criteria

- CLI can `set`, `get`, `list`, `search`, `delete`, and `generate` against a Key
  Vault when the caller has the `Key Vault Secrets Officer` role.
- Web app enforces Entra sign-in before any secret operation and performs CRUD
  using the signed-in user's delegated permissions.
- Core library has unit tests that pass without network access using a fake
  secret client.
- No dependency outside the approved, pinned set; all lint and tests pass in CI.
