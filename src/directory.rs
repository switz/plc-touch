use anyhow::{Context, Result};
use crate::plc::PlcState;

const DEFAULT_PLC_DIRECTORY: &str = "https://plc.directory";

pub struct PlcDirectoryClient {
    client: reqwest::Client,
    base_url: String,
}

impl PlcDirectoryClient {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: DEFAULT_PLC_DIRECTORY.to_string(),
        }
    }

    /// Fetch the current PLC state for a DID.
    pub async fn get_state(&self, did: &str) -> Result<PlcState> {
        let url = format!("{}/{}/data", self.base_url, did);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .context("Failed to fetch PLC state")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("PLC directory returned {}: {}", status, body);
        }

        let mut state: PlcState = resp
            .json()
            .await
            .context("Failed to parse PLC state")?;

        // The /data endpoint doesn't include the DID in the response body,
        // so set it from the request
        if state.did.is_empty() {
            state.did = did.to_string();
        }

        Ok(state)
    }

    /// Fetch the audit log for a DID.
    pub async fn get_audit_log(&self, did: &str) -> Result<Vec<serde_json::Value>> {
        let url = format!("{}/{}/log/audit", self.base_url, did);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .context("Failed to fetch audit log")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("PLC directory returned {}: {}", status, body);
        }

        let log: Vec<serde_json::Value> = resp
            .json()
            .await
            .context("Failed to parse audit log")?;

        Ok(log)
    }

    /// Submit a signed PLC operation.
    pub async fn submit_operation(
        &self,
        did: &str,
        operation: &serde_json::Value,
    ) -> Result<String> {
        let url = format!("{}/{}", self.base_url, did);
        let resp = self
            .client
            .post(&url)
            .json(operation)
            .send()
            .await
            .context("Failed to submit PLC operation")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("PLC directory returned {}: {}", status, body);
        }

        Ok("Operation submitted successfully".to_string())
    }
}
