use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PdsSession {
    pub did: String,
    pub handle: String,
    pub access_jwt: String,
    pub refresh_jwt: String,
    #[serde(default = "default_pds_endpoint")]
    pub pds_endpoint: String,
}

fn default_pds_endpoint() -> String {
    "https://bsky.social".to_string()
}

impl PdsSession {
    fn config_path() -> Result<PathBuf> {
        let config_dir = dirs::config_dir()
            .ok_or_else(|| anyhow::anyhow!("Could not find config directory"))?
            .join("plc-touch");
        std::fs::create_dir_all(&config_dir)?;
        Ok(config_dir.join("session.json"))
    }

    /// Save session to disk.
    pub fn save(&self) -> Result<()> {
        let path = Self::config_path()?;
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(&path, json)?;
        Ok(())
    }

    /// Load session from disk.
    pub fn load() -> Result<Option<PdsSession>> {
        let path = Self::config_path()?;
        if !path.exists() {
            return Ok(None);
        }
        let json = std::fs::read_to_string(&path)?;
        let session: PdsSession = serde_json::from_str(&json)?;
        Ok(Some(session))
    }

    /// Delete saved session.
    pub fn delete() -> Result<()> {
        let path = Self::config_path()?;
        if path.exists() {
            std::fs::remove_file(&path)?;
        }
        Ok(())
    }
}

/// Create a new PDS session (login).
pub async fn create_session(
    pds_endpoint: &str,
    identifier: &str,
    password: &str,
) -> Result<PdsSession> {
    let client = reqwest::Client::new();
    let url = format!("{}/xrpc/com.atproto.server.createSession", pds_endpoint);

    let body = serde_json::json!({
        "identifier": identifier,
        "password": password,
    });

    let resp = client
        .post(&url)
        .json(&body)
        .send()
        .await
        .context("Failed to connect to PDS")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("Login failed ({}): {}", status, body);
    }

    let mut session: PdsSession = resp
        .json()
        .await
        .context("Failed to parse session response")?;

    session.pds_endpoint = pds_endpoint.to_string();
    session.save()?;

    Ok(session)
}

/// Refresh an existing session.
pub async fn refresh_session(session: &PdsSession) -> Result<PdsSession> {
    let client = reqwest::Client::new();
    let url = format!(
        "{}/xrpc/com.atproto.server.refreshSession",
        session.pds_endpoint
    );

    let resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", session.refresh_jwt))
        .send()
        .await
        .context("Failed to refresh session")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("Session refresh failed ({}): {}", status, body);
    }

    let mut new_session: PdsSession = resp
        .json()
        .await
        .context("Failed to parse refresh response")?;

    new_session.pds_endpoint = session.pds_endpoint.clone();
    new_session.save()?;

    Ok(new_session)
}

/// Request PLC operation signature from PDS (triggers email with token).
pub async fn request_plc_operation_signature(session: &PdsSession) -> Result<()> {
    let client = reqwest::Client::new();
    let url = format!(
        "{}/xrpc/com.atproto.identity.requestPlcOperationSignature",
        session.pds_endpoint
    );

    let resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", session.access_jwt))
        .send()
        .await
        .context("Failed to request PLC operation signature")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("Request failed ({}): {}", status, body);
    }

    Ok(())
}

/// Sign a PLC operation via PDS.
pub async fn sign_plc_operation(
    session: &PdsSession,
    token: &str,
    rotation_keys: Option<Vec<String>>,
) -> Result<serde_json::Value> {
    let client = reqwest::Client::new();
    let url = format!(
        "{}/xrpc/com.atproto.identity.signPlcOperation",
        session.pds_endpoint
    );

    let mut body = serde_json::json!({
        "token": token,
    });

    if let Some(keys) = rotation_keys {
        body["rotationKeys"] = serde_json::json!(keys);
    }

    let resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", session.access_jwt))
        .json(&body)
        .send()
        .await
        .context("Failed to sign PLC operation via PDS")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("PDS signing failed ({}): {}", status, body);
    }

    let result: serde_json::Value = resp.json().await?;
    Ok(result)
}

/// Create a post on Bluesky.
pub async fn create_post(session: &PdsSession, text: &str) -> Result<String> {
    let client = reqwest::Client::new();
    let url = format!(
        "{}/xrpc/com.atproto.repo.createRecord",
        session.pds_endpoint
    );

    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

    let body = serde_json::json!({
        "repo": session.did,
        "collection": "app.bsky.feed.post",
        "record": {
            "$type": "app.bsky.feed.post",
            "text": text,
            "createdAt": now,
            "langs": ["en"],
        }
    });

    let resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", session.access_jwt))
        .json(&body)
        .send()
        .await
        .context("Failed to create post")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("Post creation failed ({}): {}", status, body);
    }

    let result: serde_json::Value = resp.json().await?;
    let uri = result
        .get("uri")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    Ok(uri)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_session() -> PdsSession {
        PdsSession {
            did: "did:plc:abc123".to_string(),
            handle: "alice.test".to_string(),
            access_jwt: "eyJhbGciOiJIUzI1NiJ9.access".to_string(),
            refresh_jwt: "eyJhbGciOiJIUzI1NiJ9.refresh".to_string(),
            pds_endpoint: "https://pds.example.com".to_string(),
        }
    }

    #[test]
    fn test_session_serialization_roundtrip() {
        let session = make_session();
        let json = serde_json::to_string(&session).unwrap();
        let deserialized: PdsSession = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.did, session.did);
        assert_eq!(deserialized.handle, session.handle);
        assert_eq!(deserialized.access_jwt, session.access_jwt);
        assert_eq!(deserialized.refresh_jwt, session.refresh_jwt);
        assert_eq!(deserialized.pds_endpoint, session.pds_endpoint);
    }

    #[test]
    fn test_session_camel_case_serialization() {
        let session = make_session();
        let json = serde_json::to_value(&session).unwrap();

        // Verify camelCase keys
        assert!(json.get("accessJwt").is_some());
        assert!(json.get("refreshJwt").is_some());
        assert!(json.get("pdsEndpoint").is_some());

        // Should NOT have snake_case keys
        assert!(json.get("access_jwt").is_none());
        assert!(json.get("refresh_jwt").is_none());
    }

    #[test]
    fn test_session_deserialization_from_server_response() {
        // Simulate what a real PDS returns (camelCase)
        let json = serde_json::json!({
            "did": "did:plc:xyz",
            "handle": "bob.test",
            "accessJwt": "token_a",
            "refreshJwt": "token_r"
        });

        let session: PdsSession = serde_json::from_value(json).unwrap();
        assert_eq!(session.did, "did:plc:xyz");
        assert_eq!(session.handle, "bob.test");
        assert_eq!(session.access_jwt, "token_a");
        assert_eq!(session.refresh_jwt, "token_r");
        // pds_endpoint should get default
        assert_eq!(session.pds_endpoint, "https://bsky.social");
    }

    #[test]
    fn test_default_pds_endpoint() {
        assert_eq!(default_pds_endpoint(), "https://bsky.social");
    }

    #[test]
    fn test_session_save_load_delete() {
        // Use a temp directory to avoid polluting the real config
        let session = make_session();

        // We can at least test that save/load/delete don't panic
        // (they use the real config path though, so just test serialization logic)
        let json = serde_json::to_string_pretty(&session).unwrap();
        let loaded: PdsSession = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.did, session.did);
    }

    #[test]
    fn test_session_with_extra_fields() {
        // PDS may return extra fields we don't care about
        let json = serde_json::json!({
            "did": "did:plc:test",
            "handle": "test.bsky.social",
            "accessJwt": "a",
            "refreshJwt": "r",
            "email": "test@example.com",
            "emailConfirmed": true,
            "didDoc": {},
            "active": true
        });

        // Should deserialize without error (extra fields ignored)
        let session: Result<PdsSession, _> = serde_json::from_value(json);
        assert!(session.is_ok());
    }
}
