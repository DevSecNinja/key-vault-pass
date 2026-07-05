//! Application configuration loaded from `KVP_*` environment variables.

use crate::error::{Error, Result};

/// Runtime settings for both the CLI and the web app.
///
/// Only `vault_url` is required for the CLI. The Entra/web fields are required
/// only when serving the web app and are validated by [`Settings::require_web`].
#[derive(Clone, Debug)]
pub struct Settings {
    pub vault_url: String,
    pub log_level: String,
    pub entra_tenant_id: String,
    pub entra_client_id: String,
    pub entra_client_secret: String,
    pub entra_redirect_uri: String,
    pub session_secret: String,
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

impl Settings {
    /// Load settings from the process environment (`KVP_*`).
    pub fn from_env() -> Self {
        Self {
            vault_url: env_or("KVP_VAULT_URL", ""),
            log_level: env_or("KVP_LOG_LEVEL", "info"),
            entra_tenant_id: env_or("KVP_ENTRA_TENANT_ID", ""),
            entra_client_id: env_or("KVP_ENTRA_CLIENT_ID", ""),
            entra_client_secret: env_or("KVP_ENTRA_CLIENT_SECRET", ""),
            entra_redirect_uri: env_or(
                "KVP_ENTRA_REDIRECT_URI",
                "http://localhost:8000/auth/callback",
            ),
            session_secret: env_or("KVP_SESSION_SECRET", ""),
        }
    }

    /// Return the vault URL or fail if it is not configured.
    pub fn require_vault_url(&self) -> Result<&str> {
        if self.vault_url.is_empty() {
            return Err(Error::Configuration(
                "KVP_VAULT_URL is not set; point it at your Key Vault, e.g. \
                 https://my-vault.vault.azure.net"
                    .into(),
            ));
        }
        Ok(&self.vault_url)
    }

    /// Entra authority URL derived from the tenant id.
    pub fn authority(&self) -> String {
        format!("https://login.microsoftonline.com/{}", self.entra_tenant_id)
    }

    /// Validate that all settings needed to serve the web app are present.
    pub fn require_web(&self) -> Result<()> {
        let mut missing = Vec::new();
        for (name, value) in [
            ("KVP_VAULT_URL", &self.vault_url),
            ("KVP_ENTRA_TENANT_ID", &self.entra_tenant_id),
            ("KVP_ENTRA_CLIENT_ID", &self.entra_client_id),
            ("KVP_ENTRA_CLIENT_SECRET", &self.entra_client_secret),
            ("KVP_SESSION_SECRET", &self.session_secret),
        ] {
            if value.is_empty() {
                missing.push(name);
            }
        }
        if missing.is_empty() {
            Ok(())
        } else {
            Err(Error::Configuration(format!(
                "missing required web configuration: {}",
                missing.join(", ")
            )))
        }
    }
}
