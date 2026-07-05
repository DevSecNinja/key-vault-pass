//! Azure Key Vault–backed implementation of [`SecretStore`].

use std::collections::HashMap;
use std::sync::Arc;

use azure_core::credentials::TokenCredential;
use azure_core::error::ErrorKind;
use azure_core::http::StatusCode;
use azure_security_keyvault_secrets::models::SetSecretParameters;
use azure_security_keyvault_secrets::{ResourceExt, SecretClient};
use futures::TryStreamExt as _;

use crate::error::{Error, Result};
use crate::secret_store::{RawSecret, RawSecretProperties, SecretStore};

/// Translate an Azure SDK error into a domain [`Error`].
fn map_azure_err(err: azure_core::Error, name: Option<&str>) -> Error {
    if let ErrorKind::HttpResponse { status, .. } = err.kind() {
        match *status {
            StatusCode::NotFound => {
                if let Some(name) = name {
                    return Error::EntryNotFound(name.to_string());
                }
            }
            StatusCode::Unauthorized | StatusCode::Forbidden => return Error::Authorization,
            _ => {}
        }
    }
    Error::Vault(err.to_string())
}

/// A [`SecretStore`] backed by the Azure Key Vault secrets data plane.
pub struct KeyVaultStore {
    client: SecretClient,
}

impl KeyVaultStore {
    /// Build a store for `vault_url` using the given Entra credential.
    pub fn new(vault_url: &str, credential: Arc<dyn TokenCredential>) -> Result<Self> {
        let client = SecretClient::new(vault_url, credential, None)
            .map_err(|e| Error::Vault(format!("failed to create Key Vault client: {e}")))?;
        Ok(Self { client })
    }
}

impl SecretStore for KeyVaultStore {
    async fn set_secret(
        &self,
        name: &str,
        value: &str,
        content_type: &str,
        tags: &HashMap<String, String>,
    ) -> Result<()> {
        let params = SetSecretParameters {
            value: Some(value.to_string()),
            content_type: Some(content_type.to_string()),
            tags: Some(tags.clone()),
            secret_attributes: None,
        };
        let body = params
            .try_into()
            .map_err(|e: azure_core::Error| Error::Vault(e.to_string()))?;
        self.client
            .set_secret(name, body, None)
            .await
            .map_err(|e| map_azure_err(e, Some(name)))?;
        Ok(())
    }

    async fn get_secret(&self, name: &str) -> Result<RawSecret> {
        let secret = self
            .client
            .get_secret(name, None)
            .await
            .map_err(|e| map_azure_err(e, Some(name)))?
            .into_model()
            .map_err(|e| Error::Vault(e.to_string()))?;

        let (created_at, updated_at) = secret
            .attributes
            .map(|a| (a.created, a.updated))
            .unwrap_or((None, None));

        Ok(RawSecret {
            value: secret.value.unwrap_or_default(),
            created_at,
            updated_at,
        })
    }

    async fn delete_secret(&self, name: &str) -> Result<()> {
        self.client
            .delete_secret(name, None)
            .await
            .map_err(|e| map_azure_err(e, Some(name)))?;
        Ok(())
    }

    async fn list_secret_properties(&self) -> Result<Vec<RawSecretProperties>> {
        let mut pager = self
            .client
            .list_secret_properties(None)
            .map_err(|e| map_azure_err(e, None))?;

        let mut out = Vec::new();
        while let Some(item) = pager.try_next().await.map_err(|e| map_azure_err(e, None))? {
            let name = item
                .resource_id()
                .map_err(|e| Error::Vault(e.to_string()))?
                .name;
            let (created_at, updated_at) = item
                .attributes
                .map(|a| (a.created, a.updated))
                .unwrap_or((None, None));
            out.push(RawSecretProperties {
                name,
                tags: item.tags.unwrap_or_default(),
                created_at,
                updated_at,
            });
        }
        Ok(out)
    }
}
