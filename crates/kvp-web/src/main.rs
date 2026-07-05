//! `kvp-web` — the key-vault-pass web application.
//!
//! Microsoft Entra sign-in (OAuth 2.0 auth-code + PKCE) followed by Key Vault
//! CRUD performed with the signed-in user's delegated token.

mod auth;
mod routes;
mod state;

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use axum::routing::{get, post};
use axum::Router;
use kvp_core::config::Settings;
use tera::Tera;
use time::Duration;
use tower_sessions::{Expiry, MemoryStore, SessionManagerLayer};

use crate::state::AppState;

/// Templates embedded into the binary for a self-contained deployment.
const TEMPLATES: &[(&str, &str)] = &[
    ("base.html", include_str!("../templates/base.html")),
    ("login.html", include_str!("../templates/login.html")),
    ("entries.html", include_str!("../templates/entries.html")),
    ("detail.html", include_str!("../templates/detail.html")),
    ("edit.html", include_str!("../templates/edit.html")),
];

fn build_tera() -> anyhow::Result<Tera> {
    let mut tera = Tera::default();
    tera.add_raw_templates(TEMPLATES.iter().copied())
        .context("failed to load templates")?;
    tera.autoescape_on(vec![".html"]);
    Ok(tera)
}

fn router(state: AppState, secure_cookies: bool) -> Router {
    let session_layer = SessionManagerLayer::new(MemoryStore::default())
        .with_secure(secure_cookies)
        .with_http_only(true)
        .with_same_site(tower_sessions::cookie::SameSite::Lax)
        .with_name("kvp_session")
        .with_expiry(Expiry::OnInactivity(Duration::hours(8)));

    Router::new()
        .route("/", get(routes::index))
        .route("/healthz", get(routes::healthz))
        .route("/auth/login", get(routes::login))
        .route("/auth/callback", get(routes::callback))
        .route("/auth/logout", get(routes::logout))
        .route(
            "/entries",
            get(routes::list_entries).post(routes::create_entry),
        )
        .route("/entries/new", get(routes::new_entry))
        .route("/entries/{name}", get(routes::entry_detail))
        .route("/entries/{name}/delete", post(routes::delete_entry))
        .with_state(state)
        .layer(session_layer)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("KVP_LOG_LEVEL")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let settings = Settings::from_env();

    // Local mock mode: file-backed vault + dev sign-in, no Azure/Entra required.
    let mock = std::env::var("KVP_MOCK").ok().map(|value| {
        if value.is_empty() || value == "1" || value.eq_ignore_ascii_case("true") {
            std::path::PathBuf::from(kvp_core::mock::DEFAULT_MOCK_FILE)
        } else {
            std::path::PathBuf::from(value)
        }
    });

    if mock.is_some() {
        tracing::warn!("running in LOCAL MOCK mode: Entra sign-in is simulated and secrets are stored in a local file");
    } else {
        settings.require_web()?;
    }

    // Secure cookies everywhere except plain-HTTP localhost development.
    let secure_cookies = !settings.entra_redirect_uri.starts_with("http://localhost");

    // reqwest client for the token exchange; never follow redirects.
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("failed to build HTTP client")?;

    let state = AppState {
        settings: Arc::new(settings),
        tera: Arc::new(build_tera()?),
        http,
        mock,
    };

    let app = router(state, secure_cookies);

    let bind_host = std::env::var("KVP_BIND_ADDR").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8000);
    let ip: std::net::IpAddr = bind_host
        .parse()
        .with_context(|| format!("invalid KVP_BIND_ADDR: {bind_host}"))?;
    let addr = SocketAddr::new(ip, port);
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind {addr}"))?;
    tracing::info!(%addr, "key-vault-pass web listening");

    axum::serve(listener, app.into_make_service())
        .await
        .context("server error")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    fn test_state() -> AppState {
        let settings = Settings {
            vault_url: "https://v.vault.azure.net".into(),
            log_level: "info".into(),
            entra_tenant_id: "t".into(),
            entra_client_id: "c".into(),
            entra_client_secret: "s".into(),
            entra_redirect_uri: "http://localhost:8000/auth/callback".into(),
            session_secret: "sekret".into(),
        };
        AppState {
            settings: Arc::new(settings),
            tera: Arc::new(build_tera().unwrap()),
            http: reqwest::Client::new(),
            mock: None,
        }
    }

    #[tokio::test]
    async fn entries_requires_authentication() {
        let app = router(test_state(), false);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/entries")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(response.status().is_redirection());
        assert_eq!(response.headers()["location"], "/auth/login");
    }

    #[tokio::test]
    async fn index_renders_login_page() {
        let app = router(test_state(), false);
        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn healthz_is_ok_without_auth() {
        let app = router(test_state(), false);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn mock_login_signs_in_without_entra() {
        let mut state = test_state();
        state.mock = Some(std::path::PathBuf::from("kvp-mock-test-unused.json"));
        let app = router(state, false);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/auth/login")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        // Dev sign-in redirects straight to the entries page (no Entra round trip).
        assert!(response.status().is_redirection());
        assert_eq!(response.headers()["location"], "/entries");
    }
}
