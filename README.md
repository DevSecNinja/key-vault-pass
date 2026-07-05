# key-vault-pass

An enterprise-grade password manager backed by **Azure Key Vault** with
**Microsoft Entra ID** authentication. It ships two front ends that share one
core library written in Rust:

- **`kvp`** — a command-line interface for engineers and automation.
- **`kvp-web`** — a browser-based web application.

Azure Key Vault is the single source of truth: no secret material is stored at
rest anywhere else, and every operation is authorized by the caller's own Entra
identity and Key Vault RBAC.

> Built with spec-driven development. See [`specs/`](./specs) for the
> requirements ([`spec.md`](./specs/spec.md)), the technical plan
> ([`plan.md`](./specs/plan.md)), and the task breakdown
> ([`tasks.md`](./specs/tasks.md)).

## Why Rust?

Passwords are highly sensitive. Rust gives us memory safety without a garbage
collector and mature in-memory zeroization (`secrecy`/`zeroize`), so secret
values are redacted in logs and scrubbed from memory on drop. The **Azure SDK
for Rust (1.0, GA)** provides first-class, Microsoft-authored clients for Key
Vault and Entra.

## Architecture

A Cargo workspace with a shared core and two thin front ends:

| Crate      | Purpose                                                                                   |
| ---------- | ----------------------------------------------------------------------------------------- |
| `kvp-core` | Domain model, password generation, `VaultRepository`, Key Vault store, Entra credentials. |
| `kvp-cli`  | `clap`-based CLI (`kvp`).                                                                 |
| `kvp-web`  | `axum` web app: Entra OAuth2 auth-code + PKCE, session, CRUD UI.                          |

Each **password entry** maps 1:1 to a Key Vault **secret**. The secret value is
a compact JSON document (`{"password","username","url","notes"}`) so all fields
inherit Key Vault encryption at rest; a `app=key-vault-pass` tag distinguishes
managed entries from other secrets in a shared vault.

## Prerequisites

1. **Tooling** — [mise](https://mise.jdx.dev/) manages the toolchain:

   ```bash
   mise install   # installs the pinned Rust toolchain + lint tools
   ```

2. **An Azure Key Vault** using **Azure RBAC** for its data plane. Grant callers
   the `Key Vault Secrets Officer` role (read/write) or `Key Vault Secrets User`
   (read-only) on the vault:

   ```bash
   az role assignment create \
     --role "Key Vault Secrets Officer" \
     --assignee <user-or-sp-object-id> \
     --scope "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.KeyVault/vaults/<vault>"
   ```

3. **For the web app**, a Microsoft Entra **app registration**:
   - Redirect URI (Web): `https://<your-host>/auth/callback`
     (or `http://localhost:8000/auth/callback` for local dev).
   - A client secret.
   - Delegated permission to Azure Key Vault (`user_impersonation`).

## Configuration

All configuration is via `KVP_*` environment variables (see
[`.env.example`](./.env.example)):

| Variable                  | Used by   | Purpose                                                           |
| ------------------------- | --------- | ----------------------------------------------------------------- |
| `KVP_VAULT_URL`           | CLI + web | Key Vault URL (`https://<vault>.vault.azure.net`).                |
| `KVP_ENTRA_TENANT_ID`     | web       | Entra tenant (directory) ID.                                      |
| `KVP_ENTRA_CLIENT_ID`     | web       | App registration (client) ID.                                     |
| `KVP_ENTRA_CLIENT_SECRET` | web       | App registration client secret.                                   |
| `KVP_ENTRA_REDIRECT_URI`  | web       | OAuth redirect URI.                                               |
| `KVP_SESSION_SECRET`      | web       | Secret used for the session subsystem.                            |
| `KVP_BIND_ADDR`           | web       | Bind address (default `0.0.0.0`; use `127.0.0.1` for local-only). |
| `KVP_LOG_LEVEL`           | CLI + web | Log verbosity (`info`, `debug`, ...).                             |

## Local testing without Azure (mock vault)

You can exercise the full CLI and web UX **without an Azure subscription or an
Entra tenant** using the built-in file-backed mock vault. Secrets are stored in
a plain JSON file (unencrypted — local testing only).

**CLI** — pass `--mock` (flag), `--mock-file <path>`, or set `KVP_MOCK`:

```bash
kvp --mock set github --username alice --generate
kvp --mock list
kvp --mock get github --show
# persist to a specific file (across a shell session):
export KVP_MOCK="$PWD/kvp-mock-vault.json"
kvp set email --username bob@example.com --password s3cret
```

`--mock` on its own uses `./kvp-mock-vault.json`.

**Web** — set `KVP_MOCK` (no Entra/Key Vault config needed):

```bash
KVP_MOCK=1 KVP_BIND_ADDR=127.0.0.1 mise exec -- cargo run --bin kvp-web
# open http://127.0.0.1:8000 — "Sign in (dev mock)" logs in as a local dev user
```

In mock mode the web app simulates sign-in (no Microsoft Entra round trip) and
reads/writes the same JSON file.

## CLI usage

The CLI authenticates with `azure_identity`'s credential chain: environment
service principal → managed identity → developer tools (`az login` / `azd`).

```bash
export KVP_VAULT_URL="https://my-vault.vault.azure.net"

# Create/update an entry (prompts securely for the password):
kvp set github --username alice --url https://github.com

# Or generate a strong password on the fly:
kvp set github --username alice --generate --length 24

# Retrieve (password hidden unless --show):
kvp get github
kvp get github --show

# List / search:
kvp list
kvp search git

# Delete:
kvp delete github

# Just generate a password:
kvp generate --length 32 --no-symbols
```

## Web app

```bash
cp .env.example .env   # fill in your values
mise exec -- cargo run --release --bin kvp-web
# open http://localhost:8000
```

Sign-in flow: the app redirects to Microsoft Entra (auth-code + PKCE), then uses
the signed-in user's **delegated** token against Key Vault — so the user's own
RBAC governs what they can see and change. Passwords are masked in the UI and
revealed only on explicit action.

## Development

```bash
mise exec -- cargo fmt --all             # format
mise exec -- cargo clippy --workspace --all-targets -- -D warnings
mise exec -- cargo test --workspace      # tests (no Azure needed; uses a fake store)
mise exec -- lefthook run pre-commit     # run all pre-commit checks
```

The core is unit-tested without network access via an in-memory `SecretStore`
implementation.

## Deployment

`Dockerfile` builds a minimal container running `kvp-web`.
[`.github/workflows/ci-cd.yml`](./.github/workflows/ci-cd.yml) is a single
pipeline with four jobs:

- **lint** — reuses the centralized DevSecNinja lint workflow.
- **build-test** — format check, clippy (`-D warnings`), tests, release build.
- **release-please** — on pushes to `main`, opens/updates a release PR that
  bumps the version (`[workspace.package]` in `Cargo.toml`, inherited by all
  crates) and the `CHANGELOG.md`. Merging it creates the `vX.Y.Z` tag.
- **deploy** — triggered by the `v*` tag; logs in to Azure via the Azure CLI
  with **OIDC federated credentials** (no stored cloud secrets) and rolls out to
  Azure Container Apps.

Configure before releasing/deploying:

- Release PRs (so CI fires on them): `RELEASE_PLEASE_APP_ID` (variable) +
  `RELEASE_PLEASE_APP_PRIVATE_KEY` (secret). Without a GitHub App, release-please
  falls back to `GITHUB_TOKEN` and PRs won't trigger CI.
- Deploy: `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`,
  `ACR_NAME`, `CONTAINERAPP_NAME`, `CONTAINERAPP_RG` (repository/environment
  variables).

The web app uses an in-memory session store; for multi-instance deployments,
front it with sticky sessions or swap in a shared `tower-sessions` backend.

## License

[MIT](./LICENSE)
