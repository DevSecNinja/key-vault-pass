//! Microsoft Entra credential helpers.
//!
//! - [`build_cli_credential`] assembles a credential chain suitable for the CLI
//!   and automation: environment service principal, then managed identity, then
//!   local developer tools (`az login` / `azd`). The Azure SDK for Rust 1.0
//!   removed `DefaultAzureCredential`, so we compose the chain explicitly.
//! - [`StaticTokenCredential`] adapts a token already acquired by the web app
//!   (on the user's behalf) to the `TokenCredential` API so the Key Vault client
//!   can act as the signed-in user.

use std::sync::Arc;

use async_trait::async_trait;
use azure_core::credentials::{AccessToken, Secret, TokenCredential, TokenRequestOptions};
use azure_core::time::OffsetDateTime;
use azure_identity::{ClientSecretCredential, DeveloperToolsCredential, ManagedIdentityCredential};
use secrecy::{ExposeSecret, SecretString};

use crate::error::{Error, Result};

/// Data-plane scope for the Azure Key Vault resource (client-credentials style).
pub const KEY_VAULT_SCOPE: &str = "https://vault.azure.net/.default";
/// Delegated scope requested during the web sign-in flow.
pub const KEY_VAULT_DELEGATED_SCOPE: &str = "https://vault.azure.net/user_impersonation";

/// Build the credential chain used by the CLI / automation.
pub fn build_cli_credential() -> Result<Arc<dyn TokenCredential>> {
    let map = |e: azure_core::Error| Error::Vault(format!("failed to build credential: {e}"));

    // 1. Environment service principal (CI / non-MI production).
    if let (Ok(tenant), Ok(client_id), Ok(secret)) = (
        std::env::var("AZURE_TENANT_ID"),
        std::env::var("AZURE_CLIENT_ID"),
        std::env::var("AZURE_CLIENT_SECRET"),
    ) {
        let cred = ClientSecretCredential::new(&tenant, client_id, Secret::new(secret), None)
            .map_err(map)?;
        return Ok(cred as Arc<dyn TokenCredential>);
    }

    // 2. Managed identity (App Service, AKS, VM, ...).
    if std::env::var("IDENTITY_ENDPOINT").is_ok() || std::env::var("MSI_ENDPOINT").is_ok() {
        let cred = ManagedIdentityCredential::new(None).map_err(map)?;
        return Ok(cred as Arc<dyn TokenCredential>);
    }

    // 3. Local developer tools: `az login` / `azd auth login`.
    let cred = DeveloperToolsCredential::new(None).map_err(map)?;
    Ok(cred as Arc<dyn TokenCredential>)
}

/// A credential that returns a pre-acquired bearer token (used by the web app).
///
/// The token is held in a [`SecretString`] so it is redacted in logs and
/// zeroized from memory on drop.
#[derive(Debug)]
pub struct StaticTokenCredential {
    token: SecretString,
    expires_on: OffsetDateTime,
}

impl StaticTokenCredential {
    /// Wrap an existing access token and its expiry.
    pub fn new(token: impl Into<String>, expires_on: OffsetDateTime) -> Arc<Self> {
        Arc::new(Self {
            token: SecretString::from(token.into()),
            expires_on,
        })
    }
}

#[async_trait]
impl TokenCredential for StaticTokenCredential {
    async fn get_token(
        &self,
        _scopes: &[&str],
        _options: Option<TokenRequestOptions<'_>>,
    ) -> azure_core::Result<AccessToken> {
        Ok(AccessToken::new(
            self.token.expose_secret().to_string(),
            self.expires_on,
        ))
    }
}
