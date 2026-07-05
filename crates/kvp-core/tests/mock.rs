//! Tests for the file-backed mock store used for local development.

use std::collections::HashMap;

use kvp_core::error::Error;
use kvp_core::model::{APP_TAG_KEY, APP_TAG_VALUE};
use kvp_core::secret_store::SecretStore;
use kvp_core::{FileSecretStore, PasswordEntry, VaultRepository};
use secrecy::ExposeSecret;

fn temp_path(name: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "kvp-mock-test-{}-{}.json",
        name,
        std::process::id()
    ));
    let _ = std::fs::remove_file(&p);
    p
}

#[tokio::test]
async fn file_store_persists_across_instances() {
    let path = temp_path("persist");

    // First "process": write an entry.
    {
        let repo = VaultRepository::new(FileSecretStore::new(&path));
        let entry = PasswordEntry::new(
            "github",
            "hunter2",
            Some("alice".into()),
            None,
            Some("note".into()),
        )
        .unwrap();
        repo.set_entry(&entry, false).await.unwrap();
    }

    // Second "process": a fresh store reading the same file sees the entry.
    {
        let repo = VaultRepository::new(FileSecretStore::new(&path));
        let got = repo.get_entry("github").await.unwrap();
        assert_eq!(got.password.expose_secret(), "hunter2");
        assert_eq!(got.username.as_deref(), Some("alice"));

        let names: Vec<String> = repo
            .list_entries(None)
            .await
            .unwrap()
            .into_iter()
            .map(|s| s.name)
            .collect();
        assert_eq!(names, vec!["github"]);

        repo.delete_entry("github").await.unwrap();
        assert!(matches!(
            repo.get_entry("github").await,
            Err(Error::EntryNotFound(_))
        ));
    }

    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn file_store_list_filters_foreign_secrets() {
    let path = temp_path("tags");
    let store = FileSecretStore::new(&path);

    // A foreign secret written without the app tag must be ignored by listing.
    store
        .set_secret("foreign", "x", "text/plain", &HashMap::new())
        .await
        .unwrap();

    let repo = VaultRepository::new(FileSecretStore::new(&path));
    repo.set_entry(
        &PasswordEntry::new("svc", "pw", None, None, None).unwrap(),
        false,
    )
    .await
    .unwrap();

    let names: Vec<String> = repo
        .list_entries(None)
        .await
        .unwrap()
        .into_iter()
        .map(|s| s.name)
        .collect();
    assert_eq!(names, vec!["svc"]);
    assert_eq!((APP_TAG_KEY, APP_TAG_VALUE), ("app", "key-vault-pass"));

    let _ = std::fs::remove_file(&path);
}
