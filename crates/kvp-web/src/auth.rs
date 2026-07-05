//! Microsoft Entra OAuth 2.0 authorization-code (PKCE) helpers.
//!
//! `oauth2` builds the authorize URL and generates the CSRF `state` and PKCE
//! verifier/challenge. The token exchange is performed directly with our
//! native-tls `reqwest` client so we fully control the TLS backend and can
//! capture the OIDC `id_token` alongside the Key Vault access token.

use anyhow::{anyhow, Context, Result};
use base64::Engine as _;
use kvp_core::config::Settings;
use oauth2::basic::BasicClient;
use oauth2::{
    AuthUrl, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, RedirectUrl, Scope, TokenUrl,
};
use serde::Deserialize;

/// Delegated Key Vault scope plus OIDC scopes requested at sign-in.
const SCOPES: &[&str] = &[
    "https://vault.azure.net/user_impersonation",
    "openid",
    "profile",
    "offline_access",
];

/// Values produced when starting the auth-code flow; the CSRF state and PKCE
/// verifier must be persisted server-side (session) until the callback.
pub struct AuthStart {
    pub redirect_url: String,
    pub csrf_state: String,
    pub pkce_verifier: String,
}

fn authorize_endpoint(settings: &Settings) -> String {
    format!("{}/oauth2/v2.0/authorize", settings.authority())
}

fn token_endpoint(settings: &Settings) -> String {
    format!("{}/oauth2/v2.0/token", settings.authority())
}

/// Begin the authorization-code flow: build the Entra authorize URL with a
/// random CSRF state and an S256 PKCE challenge.
pub fn start_auth(settings: &Settings) -> Result<AuthStart> {
    let client = BasicClient::new(ClientId::new(settings.entra_client_id.clone()))
        .set_client_secret(ClientSecret::new(settings.entra_client_secret.clone()))
        .set_auth_uri(AuthUrl::new(authorize_endpoint(settings)).context("invalid auth URL")?)
        .set_token_uri(TokenUrl::new(token_endpoint(settings)).context("invalid token URL")?)
        .set_redirect_uri(
            RedirectUrl::new(settings.entra_redirect_uri.clone())
                .context("invalid redirect URI")?,
        );

    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let mut builder = client.authorize_url(CsrfToken::new_random);
    for scope in SCOPES {
        builder = builder.add_scope(Scope::new((*scope).to_string()));
    }
    let (url, csrf) = builder.set_pkce_challenge(challenge).url();

    Ok(AuthStart {
        redirect_url: url.to_string(),
        csrf_state: csrf.secret().clone(),
        pkce_verifier: verifier.secret().clone(),
    })
}

/// A successful token response.
pub struct TokenResult {
    pub access_token: String,
    pub expires_in: i64,
    pub id_token: Option<String>,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    expires_in: i64,
    #[serde(default)]
    id_token: Option<String>,
}

/// Exchange an authorization code (with the PKCE verifier) for tokens.
pub async fn exchange_code(
    settings: &Settings,
    http: &reqwest::Client,
    code: &str,
    pkce_verifier: &str,
) -> Result<TokenResult> {
    let scope = SCOPES.join(" ");
    let body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("client_id", &settings.entra_client_id)
        .append_pair("client_secret", &settings.entra_client_secret)
        .append_pair("grant_type", "authorization_code")
        .append_pair("code", code)
        .append_pair("redirect_uri", &settings.entra_redirect_uri)
        .append_pair("code_verifier", pkce_verifier)
        .append_pair("scope", &scope)
        .finish();

    let response = http
        .post(token_endpoint(settings))
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(body)
        .send()
        .await
        .context("token request failed")?;

    if !response.status().is_success() {
        // Avoid echoing secrets; surface only the status.
        return Err(anyhow!(
            "token endpoint returned HTTP {}",
            response.status()
        ));
    }

    let body: TokenResponse = response.json().await.context("invalid token response")?;
    Ok(TokenResult {
        access_token: body.access_token,
        expires_in: body.expires_in,
        id_token: body.id_token,
    })
}

/// Best-effort display name/email extracted from an OIDC `id_token`.
///
/// This decodes (does not verify) the JWT payload purely to greet the user.
/// It is never used for authorization — Key Vault validates the access token
/// and enforces the user's RBAC.
pub fn claims_from_id_token(id_token: &str) -> (String, String) {
    let fallback = ("user".to_string(), String::new());
    let Some(payload) = id_token.split('.').nth(1) else {
        return fallback;
    };
    let Ok(bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload) else {
        return fallback;
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return fallback;
    };
    let email = value
        .get("preferred_username")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let name = value
        .get("name")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| {
            if email.is_empty() {
                "user".into()
            } else {
                email.clone()
            }
        });
    (name, email)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kvp_core::config::Settings;

    fn test_settings() -> Settings {
        Settings {
            vault_url: "https://v.vault.azure.net".into(),
            log_level: "info".into(),
            entra_tenant_id: "my-tenant".into(),
            entra_client_id: "my-client".into(),
            entra_client_secret: "my-secret".into(),
            entra_redirect_uri: "http://localhost:8000/auth/callback".into(),
            session_secret: "x".into(),
        }
    }

    #[test]
    fn start_auth_builds_pkce_authorize_url() {
        let start = start_auth(&test_settings()).unwrap();
        assert!(start
            .redirect_url
            .contains("login.microsoftonline.com/my-tenant"));
        assert!(start.redirect_url.contains("client_id=my-client"));
        assert!(start.redirect_url.contains("code_challenge="));
        assert!(start.redirect_url.contains("code_challenge_method=S256"));
        assert!(start.redirect_url.contains("state="));
        assert!(!start.csrf_state.is_empty());
        assert!(start.pkce_verifier.len() >= 43);
    }

    #[test]
    fn claims_from_id_token_reads_name_and_email() {
        let payload = serde_json::json!({
            "name": "Jane Doe",
            "preferred_username": "jane@example.com",
        });
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&payload).unwrap());
        let jwt = format!("header.{encoded}.signature");
        let (name, email) = claims_from_id_token(&jwt);
        assert_eq!(name, "Jane Doe");
        assert_eq!(email, "jane@example.com");
    }

    #[test]
    fn claims_from_malformed_token_falls_back() {
        let (name, email) = claims_from_id_token("not-a-jwt");
        assert_eq!(name, "user");
        assert_eq!(email, "");
    }
}
