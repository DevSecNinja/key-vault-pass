//! The narrow secret-store boundary used by [`crate::vault::VaultRepository`].
//!
//! Defining a trait with only the operations we depend on keeps the repository
//! decoupled from the concrete Azure Key Vault client and makes it trivially
//! unit-testable with an in-memory fake (see the crate's tests).

use std::collections::HashMap;

use time::OffsetDateTime;

use crate::error::Result;

/// A secret value plus the metadata we surface, as returned by the store.
#[derive(Clone, Debug)]
pub struct RawSecret {
    pub value: String,
    pub created_at: Option<OffsetDateTime>,
    pub updated_at: Option<OffsetDateTime>,
}

/// Lightweight secret metadata returned when listing (no value).
#[derive(Clone, Debug)]
pub struct RawSecretProperties {
    pub name: String,
    pub tags: HashMap<String, String>,
    pub created_at: Option<OffsetDateTime>,
    pub updated_at: Option<OffsetDateTime>,
}

/// Subset of the Key Vault secrets data plane the repository relies on.
///
/// Implemented for real by [`crate::keyvault::KeyVaultStore`] and by an
/// in-memory fake in tests. `VaultRepository` is generic over this trait, so
/// both use static dispatch with no runtime cost.
#[allow(async_fn_in_trait)]
pub trait SecretStore {
    /// Create or update a secret with the given value, content type and tags.
    async fn set_secret(
        &self,
        name: &str,
        value: &str,
        content_type: &str,
        tags: &HashMap<String, String>,
    ) -> Result<()>;

    /// Fetch the latest version of a secret by name.
    async fn get_secret(&self, name: &str) -> Result<RawSecret>;

    /// Delete a secret by name.
    async fn delete_secret(&self, name: &str) -> Result<()>;

    /// Enumerate all secret properties (names, tags, timestamps).
    async fn list_secret_properties(&self) -> Result<Vec<RawSecretProperties>>;
}
