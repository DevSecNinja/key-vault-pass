//! Domain error types for key-vault-pass.
//!
//! Lower-level Azure SDK errors are translated into these stable, front-end
//! agnostic variants so the CLI and web app render consistent, secret-free
//! messages.

use thiserror::Error;

/// Result alias used throughout the core crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur while managing password entries.
#[derive(Debug, Error)]
pub enum Error {
    /// Required configuration was missing or invalid.
    #[error("configuration error: {0}")]
    Configuration(String),

    /// An entry name violated Key Vault naming rules.
    #[error("invalid entry name: {0}")]
    InvalidEntryName(String),

    /// The requested entry does not exist.
    #[error("no password entry named {0:?} was found")]
    EntryNotFound(String),

    /// An entry with the given name already exists.
    #[error("a password entry named {0:?} already exists")]
    EntryAlreadyExists(String),

    /// The caller is not authorized to perform the operation.
    #[error(
        "access denied by Key Vault; ensure your Entra identity has an \
         appropriate Key Vault Secrets role"
    )]
    Authorization,

    /// An unexpected Key Vault / transport failure.
    #[error("Key Vault operation failed: {0}")]
    Vault(String),
}
