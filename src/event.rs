use crate::enclave::EnclaveKey;
use crate::plc::{PlcOperation, PlcState};
use ratatui::crossterm::event::KeyEvent;

/// Messages sent from async tasks back to the main event loop.
#[derive(Debug)]
pub enum AppMessage {
    // Terminal input
    KeyEvent(KeyEvent),

    // Key management
    KeysLoaded(Result<Vec<EnclaveKey>, String>),
    KeyGenerated(Result<EnclaveKey, String>),
    KeyDeleted(Result<String, String>), // label

    // PLC directory
    PlcStateLoaded(Result<PlcState, String>),
    AuditLogLoaded(Result<Vec<serde_json::Value>, String>),
    OperationSubmitted(Result<String, String>), // CID

    // Signing
    OperationSigned(Result<PlcOperation, String>),

    // PDS / atproto
    LoginResult(Result<crate::atproto::PdsSession, String>),
    SessionRefreshed(Result<crate::atproto::PdsSession, String>),
    PostCreated(Result<String, String>), // URI
    PlcTokenRequested(Result<(), String>),
    PdsPlcOperationSigned(Result<serde_json::Value, String>),
}
