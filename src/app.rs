use anyhow::Result;
use ratatui::crossterm::event::{self, KeyCode, KeyEvent, KeyModifiers};
use ratatui::widgets::ListState;
use std::collections::HashSet;
use tokio::sync::mpsc;

use crate::atproto::PdsSession;
use crate::directory::PlcDirectoryClient;
use crate::enclave::EnclaveKey;
use crate::event::AppMessage;
use crate::plc::{self, OperationDiff, PlcOperation, PlcState};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ActiveTab {
    Keys,
    Identity,
    Sign,
    Audit,
    Post,
    Login,
}

impl ActiveTab {
    pub fn index(&self) -> usize {
        match self {
            ActiveTab::Keys => 0,
            ActiveTab::Identity => 1,
            ActiveTab::Sign => 2,
            ActiveTab::Audit => 3,
            ActiveTab::Post => 4,
            ActiveTab::Login => 5,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Modal {
    None,
    Help,
    TouchId { message: String },
    Confirm {
        title: String,
        message: String,
        options: Vec<(String, String)>,
    },
    Error { message: String },
    Success { message: String },
    KeyGenForm { label: String, syncable: bool },
    TextInput {
        title: String,
        value: String,
        target: TextInputTarget,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum TextInputTarget {
    EditDid,
    PlcToken,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InputMode {
    Normal,
    Editing,
}

pub struct App {
    pub active_tab: ActiveTab,
    pub modal: Modal,
    pub input_mode: InputMode,
    pub should_quit: bool,

    // State
    pub keys: Vec<EnclaveKey>,
    pub active_key_index: Option<usize>,
    pub current_did: Option<String>,
    pub plc_state: Option<PlcState>,
    pub audit_log: Option<Vec<serde_json::Value>>,
    pub session: Option<PdsSession>,
    pub last_prev_cid: Option<String>,
    pub pending_rotation_keys: Option<Vec<String>>,

    // UI state
    pub key_list_state: ListState,
    pub rotation_key_list_state: ListState,
    pub audit_list_state: ListState,
    pub expanded_audit_entries: HashSet<usize>,
    pub post_textarea: tui_textarea::TextArea<'static>,
    pub show_operation_json: bool,
    pub sign_scroll: u16,

    // Login form
    pub login_handle: String,
    pub login_password: String,
    pub login_field: usize, // 0=handle, 1=password

    // Pending operation
    pub pending_operation: Option<PlcOperation>,
    pub operation_diff: Option<OperationDiff>,

    // Confirm action state
    pub confirm_action: Option<ConfirmAction>,

    // Async
    pub loading: Option<String>,
    msg_tx: mpsc::UnboundedSender<AppMessage>,
    msg_rx: mpsc::UnboundedReceiver<AppMessage>,
}

#[derive(Debug, Clone)]
pub enum ConfirmAction {
    SubmitOperation,
    DeleteKey(String),
    Disconnect,
}

impl App {
    pub fn new() -> Self {
        let (msg_tx, msg_rx) = mpsc::unbounded_channel();
        let mut textarea = tui_textarea::TextArea::default();
        textarea.set_cursor_line_style(ratatui::style::Style::default());

        Self {
            active_tab: ActiveTab::Keys,
            modal: Modal::None,
            input_mode: InputMode::Normal,
            should_quit: false,
            keys: Vec::new(),
            active_key_index: None,
            current_did: None,
            plc_state: None,
            audit_log: None,
            session: None,
            last_prev_cid: None,
            pending_rotation_keys: None,
            key_list_state: ListState::default(),
            rotation_key_list_state: ListState::default(),
            audit_list_state: ListState::default(),
            expanded_audit_entries: HashSet::new(),
            post_textarea: textarea,
            show_operation_json: false,
            sign_scroll: 0,
            login_handle: String::new(),
            login_password: String::new(),
            login_field: 0,
            pending_operation: None,
            operation_diff: None,
            confirm_action: None,
            loading: None,
            msg_tx,
            msg_rx,
        }
    }

    pub async fn run(
        &mut self,
        terminal: &mut ratatui::Terminal<ratatui::backend::CrosstermBackend<std::io::Stdout>>,
    ) -> Result<()> {
        // Load saved session
        if let Ok(Some(session)) = PdsSession::load() {
            self.current_did = Some(session.did.clone());
            self.session = Some(session);
        }

        // Load keys on startup
        self.spawn_load_keys();

        // If we have a DID, load PLC state
        if let Some(did) = &self.current_did {
            let did = did.clone();
            self.spawn_load_plc_state(&did);
        }

        // Dedicated thread for crossterm event polling
        let event_tx = self.msg_tx.clone();
        std::thread::spawn(move || {
            loop {
                if event::poll(std::time::Duration::from_millis(50)).unwrap_or(false) {
                    if let Ok(evt) = event::read() {
                        if let event::Event::Key(key) = evt {
                            if event_tx.send(AppMessage::KeyEvent(key)).is_err() {
                                break;
                            }
                        }
                    }
                }
            }
        });

        loop {
            terminal.draw(|frame| self.render(frame))?;

            if let Some(msg) = self.msg_rx.recv().await {
                match msg {
                    AppMessage::KeyEvent(key) => self.handle_key_event(key),
                    other => self.handle_message(other),
                }
            }

            if self.should_quit {
                return Ok(());
            }
        }
    }

    fn handle_key_event(&mut self, key: KeyEvent) {
        // Modal takes priority
        if self.modal != Modal::None {
            self.handle_modal_key(key);
            return;
        }

        // Editing mode for login form and post textarea
        if self.input_mode == InputMode::Editing {
            self.handle_editing_key(key);
            return;
        }

        // Global bindings
        match key.code {
            KeyCode::Char('q') => self.should_quit = true,
            KeyCode::Char('?') => self.modal = Modal::Help,
            KeyCode::Char('1') => self.active_tab = ActiveTab::Keys,
            KeyCode::Char('2') => self.active_tab = ActiveTab::Identity,
            KeyCode::Char('3') => self.active_tab = ActiveTab::Sign,
            KeyCode::Char('4') => self.active_tab = ActiveTab::Audit,
            KeyCode::Char('5') => {
                self.active_tab = ActiveTab::Post;
                self.input_mode = InputMode::Editing;
            }
            KeyCode::Char('6') => {
                self.active_tab = ActiveTab::Login;
                if self.session.is_none() {
                    self.input_mode = InputMode::Editing;
                }
            }
            _ => self.handle_tab_key(key),
        }
    }

    fn handle_modal_key(&mut self, key: KeyEvent) {
        match &self.modal {
            Modal::Help => {
                if key.code == KeyCode::Esc || key.code == KeyCode::Char('?') {
                    self.modal = Modal::None;
                }
            }
            Modal::Error { .. } => {
                if key.code == KeyCode::Esc || key.code == KeyCode::Enter {
                    self.modal = Modal::None;
                }
            }
            Modal::Success { .. } => {
                // Any key closes
                self.modal = Modal::None;
            }
            Modal::TouchId { .. } => {
                // Can't dismiss, waiting for Touch ID
            }
            Modal::Confirm { .. } => {
                self.handle_confirm_key(key);
            }
            Modal::KeyGenForm { .. } => {
                self.handle_keygen_key(key);
            }
            Modal::TextInput { .. } => {
                self.handle_text_input_key(key);
            }
            Modal::None => {}
        }
    }

    fn handle_confirm_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                self.modal = Modal::None;
                self.confirm_action = None;
            }
            KeyCode::Char('y') => {
                let action = self.confirm_action.take();
                self.modal = Modal::None;
                if let Some(action) = action {
                    self.execute_confirm_action(action);
                }
            }
            KeyCode::Char('n') | KeyCode::Char('f') => {
                // For submit confirmation: 'f' saves to file (not yet implemented)
                self.modal = Modal::None;
                self.confirm_action = None;
            }
            _ => {}
        }
    }

    fn execute_confirm_action(&mut self, action: ConfirmAction) {
        match action {
            ConfirmAction::SubmitOperation => {
                self.submit_pending_operation();
            }
            ConfirmAction::DeleteKey(label) => {
                self.spawn_delete_key(&label);
            }
            ConfirmAction::Disconnect => {
                let _ = PdsSession::delete();
                self.session = None;
            }
        }
    }

    fn handle_keygen_key(&mut self, key: KeyEvent) {
        let (mut label, mut syncable) = match &self.modal {
            Modal::KeyGenForm { label, syncable } => (label.clone(), *syncable),
            _ => return,
        };

        match key.code {
            KeyCode::Esc => {
                self.modal = Modal::None;
            }
            KeyCode::Enter => {
                if !label.is_empty() {
                    self.modal = Modal::None;
                    self.spawn_generate_key(&label, syncable);
                }
            }
            KeyCode::Backspace => {
                label.pop();
                self.modal = Modal::KeyGenForm { label, syncable };
            }
            KeyCode::Tab => {
                syncable = !syncable;
                self.modal = Modal::KeyGenForm { label, syncable };
            }
            KeyCode::Char(c) => {
                if c.is_alphanumeric() || c == '-' || c == '_' {
                    label.push(c);
                    self.modal = Modal::KeyGenForm { label, syncable };
                }
            }
            _ => {}
        }
    }

    fn handle_text_input_key(&mut self, key: KeyEvent) {
        let (title, mut value, target) = match &self.modal {
            Modal::TextInput { title, value, target } => {
                (title.clone(), value.clone(), target.clone())
            }
            _ => return,
        };

        match key.code {
            KeyCode::Esc => {
                self.modal = Modal::None;
            }
            KeyCode::Enter => {
                self.modal = Modal::None;
                self.handle_text_input_submit(&value, &target);
            }
            KeyCode::Backspace => {
                value.pop();
                self.modal = Modal::TextInput { title, value, target };
            }
            KeyCode::Char(c) => {
                value.push(c);
                self.modal = Modal::TextInput { title, value, target };
            }
            _ => {}
        }
    }

    fn handle_text_input_submit(&mut self, value: &str, target: &TextInputTarget) {
        match target {
            TextInputTarget::EditDid => {
                let did = value.trim().to_string();
                if did.starts_with("did:plc:") {
                    self.current_did = Some(did.clone());
                    self.spawn_load_plc_state(&did);
                    self.spawn_load_audit_log(&did);
                } else {
                    self.modal = Modal::Error {
                        message: "Invalid DID: must start with 'did:plc:'".to_string(),
                    };
                }
            }
            TextInputTarget::PlcToken => {
                let token = value.trim().to_string();
                if !token.is_empty() {
                    self.spawn_pds_sign_operation(&token);
                }
            }
        }
    }

    fn handle_editing_key(&mut self, key: KeyEvent) {
        match self.active_tab {
            ActiveTab::Login => self.handle_login_editing(key),
            ActiveTab::Post => self.handle_post_editing(key),
            _ => {
                if key.code == KeyCode::Esc {
                    self.input_mode = InputMode::Normal;
                }
            }
        }
    }

    fn handle_login_editing(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                self.input_mode = InputMode::Normal;
            }
            KeyCode::Tab => {
                self.login_field = (self.login_field + 1) % 2;
            }
            KeyCode::Enter => {
                if !self.login_handle.is_empty() && !self.login_password.is_empty() {
                    self.input_mode = InputMode::Normal;
                    self.spawn_login();
                }
            }
            KeyCode::Backspace => {
                if self.login_field == 0 {
                    self.login_handle.pop();
                } else {
                    self.login_password.pop();
                }
            }
            KeyCode::Char(c) => {
                if self.login_field == 0 {
                    self.login_handle.push(c);
                } else {
                    self.login_password.push(c);
                }
            }
            _ => {}
        }
    }

    fn handle_post_editing(&mut self, key: KeyEvent) {
        if key.code == KeyCode::Esc {
            self.input_mode = InputMode::Normal;
            return;
        }

        // Ctrl+D to send (Ctrl+Enter is unreliable on macOS)
        if key.code == KeyCode::Char('d') && key.modifiers.contains(KeyModifiers::CONTROL) {
            let text = self.post_textarea.lines().join("\n");
            if !text.is_empty() && text.len() <= 300 {
                self.input_mode = InputMode::Normal;
                self.spawn_create_post(&text);
            }
            return;
        }

        // Forward to textarea
        self.post_textarea.input(key);
    }

    fn handle_tab_key(&mut self, key: KeyEvent) {
        match self.active_tab {
            ActiveTab::Keys => self.handle_keys_key(key),
            ActiveTab::Identity => self.handle_identity_key(key),
            ActiveTab::Sign => self.handle_sign_key(key),
            ActiveTab::Audit => self.handle_audit_key(key),
            ActiveTab::Post => {
                if key.code == KeyCode::Enter || key.code == KeyCode::Char('i') {
                    self.input_mode = InputMode::Editing;
                }
            }
            ActiveTab::Login => self.handle_login_key(key),
        }
    }

    fn handle_keys_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up => {
                let len = self.keys.len();
                if len > 0 {
                    let i = self.key_list_state.selected().unwrap_or(0);
                    self.key_list_state.select(Some(if i == 0 { len - 1 } else { i - 1 }));
                }
            }
            KeyCode::Down => {
                let len = self.keys.len();
                if len > 0 {
                    let i = self.key_list_state.selected().unwrap_or(0);
                    self.key_list_state.select(Some((i + 1) % len));
                }
            }
            KeyCode::Char('n') => {
                self.modal = Modal::KeyGenForm {
                    label: String::new(),
                    syncable: true,
                };
            }
            KeyCode::Char('d') => {
                if let Some(i) = self.key_list_state.selected() {
                    if let Some(key) = self.keys.get(i) {
                        let label = key.label.clone();
                        self.confirm_action = Some(ConfirmAction::DeleteKey(label.clone()));
                        self.modal = Modal::Confirm {
                            title: "Delete Key".to_string(),
                            message: format!("Delete key '{}'? This cannot be undone.", label),
                            options: vec![
                                ("y".to_string(), "Delete".to_string()),
                                ("n".to_string(), "Cancel".to_string()),
                            ],
                        };
                    }
                }
            }
            KeyCode::Char('s') => {
                if let Some(i) = self.key_list_state.selected() {
                    self.active_key_index = Some(i);
                }
            }
            KeyCode::Enter => {
                if let Some(i) = self.key_list_state.selected() {
                    if let Some(key) = self.keys.get(i) {
                        match arboard::Clipboard::new() {
                            Ok(mut clipboard) => {
                                let _ = clipboard.set_text(&key.did_key);
                                self.modal = Modal::Success {
                                    message: format!("Copied did:key to clipboard"),
                                };
                            }
                            Err(_) => {
                                self.modal = Modal::Error {
                                    message: "Failed to access clipboard".to_string(),
                                };
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn handle_identity_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up => {
                if let Some(state) = &self.plc_state {
                    let len = state.rotation_keys.len();
                    if len > 0 {
                        let i = self.rotation_key_list_state.selected().unwrap_or(0);
                        self.rotation_key_list_state.select(Some(if i == 0 { len - 1 } else { i - 1 }));
                    }
                }
            }
            KeyCode::Down => {
                if let Some(state) = &self.plc_state {
                    let len = state.rotation_keys.len();
                    if len > 0 {
                        let i = self.rotation_key_list_state.selected().unwrap_or(0);
                        self.rotation_key_list_state.select(Some((i + 1) % len));
                    }
                }
            }
            KeyCode::Char('e') => {
                self.modal = Modal::TextInput {
                    title: "Enter DID".to_string(),
                    value: self.current_did.clone().unwrap_or_default(),
                    target: TextInputTarget::EditDid,
                };
            }
            KeyCode::Char('r') => {
                if let Some(did) = &self.current_did {
                    let did = did.clone();
                    self.spawn_load_plc_state(&did);
                    self.spawn_load_audit_log(&did);
                }
            }
            KeyCode::Char('a') => {
                self.stage_add_key_operation();
            }
            KeyCode::Char('m') => {
                self.stage_move_key_operation();
            }
            KeyCode::Char('x') => {
                self.stage_remove_key_operation();
            }
            _ => {}
        }
    }

    fn handle_sign_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('j') => {
                self.show_operation_json = !self.show_operation_json;
            }
            KeyCode::Char('s') => {
                if self.pending_operation.is_some() {
                    self.spawn_sign_operation();
                }
            }
            KeyCode::Up => {
                self.sign_scroll = self.sign_scroll.saturating_sub(1);
            }
            KeyCode::Down => {
                self.sign_scroll = self.sign_scroll.saturating_add(1);
            }
            KeyCode::Esc => {
                self.pending_operation = None;
                self.operation_diff = None;
            }
            _ => {}
        }
    }

    fn handle_audit_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up => {
                if let Some(log) = &self.audit_log {
                    let len = log.len();
                    if len > 0 {
                        let i = self.audit_list_state.selected().unwrap_or(0);
                        self.audit_list_state.select(Some(if i == 0 { len - 1 } else { i - 1 }));
                    }
                }
            }
            KeyCode::Down => {
                if let Some(log) = &self.audit_log {
                    let len = log.len();
                    if len > 0 {
                        let i = self.audit_list_state.selected().unwrap_or(0);
                        self.audit_list_state.select(Some((i + 1) % len));
                    }
                }
            }
            KeyCode::Enter | KeyCode::Char('j') => {
                if let Some(i) = self.audit_list_state.selected() {
                    if self.expanded_audit_entries.contains(&i) {
                        self.expanded_audit_entries.remove(&i);
                    } else {
                        self.expanded_audit_entries.insert(i);
                    }
                }
            }
            KeyCode::Char('r') => {
                if let Some(did) = &self.current_did {
                    let did = did.clone();
                    self.spawn_load_audit_log(&did);
                }
            }
            _ => {}
        }
    }

    fn handle_login_key(&mut self, key: KeyEvent) {
        if self.session.is_some() {
            match key.code {
                KeyCode::Char('d') => {
                    self.confirm_action = Some(ConfirmAction::Disconnect);
                    self.modal = Modal::Confirm {
                        title: "Disconnect".to_string(),
                        message: "Disconnect from PDS?".to_string(),
                        options: vec![
                            ("y".to_string(), "Disconnect".to_string()),
                            ("n".to_string(), "Cancel".to_string()),
                        ],
                    };
                }
                KeyCode::Char('r') => {
                    self.spawn_refresh_session();
                }
                _ => {}
            }
        } else {
            // Enter editing mode
            if key.code == KeyCode::Enter || key.code == KeyCode::Char('i') {
                self.input_mode = InputMode::Editing;
            }
        }
    }

    // --- Operation staging ---

    fn stage_add_key_operation(&mut self) {
        let Some(state) = &self.plc_state else {
            self.modal = Modal::Error {
                message: "Load a DID first".to_string(),
            };
            return;
        };
        let Some(idx) = self.active_key_index else {
            self.modal = Modal::Error {
                message: "Select an active Secure Enclave key first (Tab 1, 's')".to_string(),
            };
            return;
        };
        let Some(key) = self.keys.get(idx) else {
            return;
        };

        // Check if SE key is already in rotation keys (can self-sign)
        let se_key_in_rotation = state.rotation_keys.contains(&key.did_key);

        // Add key at position 0 (highest priority)
        let mut new_rotation_keys = vec![key.did_key.clone()];
        for existing in &state.rotation_keys {
            if existing != &key.did_key {
                new_rotation_keys.push(existing.clone());
            }
        }

        if se_key_in_rotation {
            // Can self-sign with our SE key
            let prev = self.last_prev_cid.clone().unwrap_or_default();
            let op = plc::build_update_operation(state, &prev, Some(new_rotation_keys), None, None, None);
            let diff = plc::compute_diff(state, &op);
            self.pending_operation = Some(op);
            self.operation_diff = Some(diff);
            self.active_tab = ActiveTab::Sign;
        } else {
            // Need PDS to sign — request token via email
            let Some(session) = &self.session else {
                self.modal = Modal::Error {
                    message: "Log in to your PDS first (Tab 6). Your SE key is not yet in rotation keys, so the PDS must sign.".to_string(),
                };
                return;
            };
            self.pending_rotation_keys = Some(new_rotation_keys);
            self.spawn_request_plc_token();
        }
    }

    fn stage_move_key_operation(&mut self) {
        let Some(state) = &self.plc_state else {
            self.modal = Modal::Error {
                message: "Load a DID first".to_string(),
            };
            return;
        };
        let Some(selected) = self.rotation_key_list_state.selected() else {
            return;
        };

        if selected == 0 || state.rotation_keys.len() < 2 {
            return;
        }

        // Move selected key up by one position
        let mut new_keys = state.rotation_keys.clone();
        new_keys.swap(selected, selected - 1);

        let prev = self.last_prev_cid.clone().unwrap_or_default();
        let op = plc::build_update_operation(state, &prev, Some(new_keys), None, None, None);
        let diff = plc::compute_diff(state, &op);

        self.pending_operation = Some(op);
        self.operation_diff = Some(diff);
        self.active_tab = ActiveTab::Sign;
    }

    fn stage_remove_key_operation(&mut self) {
        let Some(state) = &self.plc_state else {
            self.modal = Modal::Error {
                message: "Load a DID first".to_string(),
            };
            return;
        };
        let Some(selected) = self.rotation_key_list_state.selected() else {
            return;
        };

        if state.rotation_keys.len() <= 1 {
            self.modal = Modal::Error {
                message: "Cannot remove the last rotation key".to_string(),
            };
            return;
        }

        let removed_key = &state.rotation_keys[selected];
        let new_keys: Vec<String> = state
            .rotation_keys
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != selected)
            .map(|(_, k)| k.clone())
            .collect();

        // Check if we have authority to self-sign
        let can_self_sign = self.active_key_index.and_then(|idx| self.keys.get(idx))
            .map(|k| state.rotation_keys.contains(&k.did_key))
            .unwrap_or(false);

        if can_self_sign {
            let prev = self.last_prev_cid.clone().unwrap_or_default();
            let op = plc::build_update_operation(state, &prev, Some(new_keys), None, None, None);
            let diff = plc::compute_diff(state, &op);
            self.pending_operation = Some(op);
            self.operation_diff = Some(diff);
            self.active_tab = ActiveTab::Sign;
        } else if self.session.is_some() {
            self.pending_rotation_keys = Some(new_keys);
            self.spawn_request_plc_token();
        } else {
            self.modal = Modal::Error {
                message: format!(
                    "Cannot remove key. Log in to PDS (Tab 6) or set an active SE key that's already in rotation (Tab 1, 's')."
                ),
            };
        }
    }

    // --- Async spawns ---

    fn spawn_load_keys(&mut self) {
        self.loading = Some("Loading keys".to_string());
        let tx = self.msg_tx.clone();
        tokio::task::spawn_blocking(move || {
            let result = crate::enclave::list_keys()
                .map_err(|e| e.to_string());
            let _ = tx.send(AppMessage::KeysLoaded(result));
        });
    }

    fn spawn_generate_key(&mut self, label: &str, syncable: bool) {
        self.loading = Some("Generating key".to_string());
        let tx = self.msg_tx.clone();
        let label = label.to_string();
        tokio::task::spawn_blocking(move || {
            let result = crate::enclave::generate_key(&label, syncable)
                .map_err(|e| e.to_string());
            let _ = tx.send(AppMessage::KeyGenerated(result));
        });
    }

    fn spawn_delete_key(&mut self, label: &str) {
        self.loading = Some("Deleting key".to_string());
        let tx = self.msg_tx.clone();
        let label = label.to_string();
        tokio::task::spawn_blocking(move || {
            let result = crate::enclave::delete_key(&label)
                .map(|_| label.clone())
                .map_err(|e| e.to_string());
            let _ = tx.send(AppMessage::KeyDeleted(result));
        });
    }

    fn spawn_load_plc_state(&mut self, did: &str) {
        self.loading = Some("Fetching PLC state".to_string());
        let tx = self.msg_tx.clone();
        let did = did.to_string();
        tokio::spawn(async move {
            let client = PlcDirectoryClient::new();
            let result = client.get_state(&did).await.map_err(|e| e.to_string());
            let _ = tx.send(AppMessage::PlcStateLoaded(result));
        });
    }

    fn spawn_load_audit_log(&mut self, did: &str) {
        let tx = self.msg_tx.clone();
        let did = did.to_string();
        tokio::spawn(async move {
            let client = PlcDirectoryClient::new();
            let result = client.get_audit_log(&did).await.map_err(|e| e.to_string());
            let _ = tx.send(AppMessage::AuditLogLoaded(result));
        });
    }

    fn spawn_sign_operation(&mut self) {
        let Some(op) = &self.pending_operation else {
            return;
        };
        let Some(idx) = self.active_key_index else {
            self.modal = Modal::Error {
                message: "No active key selected".to_string(),
            };
            return;
        };
        let Some(key) = self.keys.get(idx) else {
            return;
        };

        self.modal = Modal::TouchId {
            message: "Place your finger on the sensor to sign this operation".to_string(),
        };

        let tx = self.msg_tx.clone();
        let mut op = op.clone();
        let label = key.label.clone();
        let is_syncable = key.syncable;

        tokio::task::spawn_blocking(move || {
            let result = (|| -> Result<PlcOperation, String> {
                let dag_cbor = plc::serialize_for_signing(&op).map_err(|e| e.to_string())?;

                let sig = crate::sign::sign_operation(&dag_cbor, |data| {
                    crate::enclave::sign_with_key(&label, data, is_syncable)
                })
                .map_err(|e| e.to_string())?;

                op.sig = Some(sig);
                Ok(op)
            })();

            let _ = tx.send(AppMessage::OperationSigned(result));
        });
    }

    fn spawn_request_plc_token(&mut self) {
        let Some(session) = &self.session else {
            return;
        };
        self.loading = Some("Requesting PLC token (check email)".to_string());
        let tx = self.msg_tx.clone();
        let session = session.clone();

        tokio::spawn(async move {
            let result = crate::atproto::request_plc_operation_signature(&session)
                .await
                .map_err(|e| e.to_string());
            let _ = tx.send(AppMessage::PlcTokenRequested(result));
        });
    }

    fn spawn_pds_sign_operation(&mut self, token: &str) {
        let Some(session) = &self.session else {
            return;
        };
        let Some(keys) = &self.pending_rotation_keys else {
            return;
        };
        self.loading = Some("PDS signing operation".to_string());
        let tx = self.msg_tx.clone();
        let session = session.clone();
        let token = token.to_string();
        let keys = keys.clone();

        tokio::spawn(async move {
            let result = crate::atproto::sign_plc_operation(&session, &token, Some(keys))
                .await
                .map_err(|e| e.to_string());
            let _ = tx.send(AppMessage::PdsPlcOperationSigned(result));
        });
    }

    fn submit_pending_operation(&mut self) {
        let Some(op) = &self.pending_operation else {
            return;
        };
        let Some(did) = &self.current_did else {
            return;
        };

        self.loading = Some("Submitting operation".to_string());
        let tx = self.msg_tx.clone();
        let op_json = serde_json::to_value(op).unwrap_or_default();
        let did = did.clone();

        tokio::spawn(async move {
            let client = PlcDirectoryClient::new();
            let result = client
                .submit_operation(&did, &op_json)
                .await
                .map_err(|e| e.to_string());
            let _ = tx.send(AppMessage::OperationSubmitted(result));
        });
    }

    fn spawn_login(&mut self) {
        self.loading = Some("Logging in".to_string());
        let tx = self.msg_tx.clone();
        let handle = self.login_handle.clone();
        let password = self.login_password.clone();

        tokio::spawn(async move {
            let pds_endpoint = "https://bsky.social".to_string();
            let result = crate::atproto::create_session(&pds_endpoint, &handle, &password)
                .await
                .map_err(|e| e.to_string());
            let _ = tx.send(AppMessage::LoginResult(result));
        });
    }

    fn spawn_refresh_session(&mut self) {
        let Some(session) = &self.session else {
            return;
        };

        self.loading = Some("Refreshing session".to_string());
        let tx = self.msg_tx.clone();
        let session = session.clone();

        tokio::spawn(async move {
            let result = crate::atproto::refresh_session(&session)
                .await
                .map_err(|e| e.to_string());
            let _ = tx.send(AppMessage::SessionRefreshed(result));
        });
    }

    fn spawn_create_post(&mut self, text: &str) {
        let Some(session) = &self.session else {
            self.modal = Modal::Error {
                message: "Not logged in".to_string(),
            };
            return;
        };

        self.loading = Some("Creating post".to_string());
        let tx = self.msg_tx.clone();
        let session = session.clone();
        let text = text.to_string();

        tokio::spawn(async move {
            let result = crate::atproto::create_post(&session, &text)
                .await
                .map_err(|e| e.to_string());
            let _ = tx.send(AppMessage::PostCreated(result));
        });
    }

    // --- Public test helpers ---

    #[cfg(test)]
    pub fn send_key(&mut self, code: KeyCode) {
        self.handle_key_event(KeyEvent::new(code, KeyModifiers::empty()));
    }

    #[cfg(test)]
    pub fn send_key_with_modifiers(&mut self, code: KeyCode, modifiers: KeyModifiers) {
        self.handle_key_event(KeyEvent::new(code, modifiers));
    }

    #[cfg(test)]
    pub fn inject_message(&mut self, msg: AppMessage) {
        self.handle_message(msg);
    }

    // --- Message handling ---

    fn handle_message(&mut self, msg: AppMessage) {
        self.loading = None;

        match msg {
            AppMessage::KeyEvent(_) => {} // handled in run loop
            AppMessage::KeysLoaded(Ok(keys)) => {
                self.keys = keys;
                if !self.keys.is_empty() && self.key_list_state.selected().is_none() {
                    self.key_list_state.select(Some(0));
                }
            }
            AppMessage::KeysLoaded(Err(e)) => {
                self.modal = Modal::Error {
                    message: format!("Failed to load keys: {}", e),
                };
            }
            AppMessage::KeyGenerated(Ok(key)) => {
                self.keys.push(key);
                let idx = self.keys.len() - 1;
                self.key_list_state.select(Some(idx));
                if self.active_key_index.is_none() {
                    self.active_key_index = Some(idx);
                }
                self.modal = Modal::Success {
                    message: "Key generated successfully".to_string(),
                };
            }
            AppMessage::KeyGenerated(Err(e)) => {
                self.modal = Modal::Error {
                    message: format!("Key generation failed: {}", e),
                };
            }
            AppMessage::KeyDeleted(Ok(label)) => {
                self.keys.retain(|k| k.label != label);
                if self.keys.is_empty() {
                    self.key_list_state.select(None);
                    self.active_key_index = None;
                } else {
                    let max = self.keys.len().saturating_sub(1);
                    if let Some(sel) = self.key_list_state.selected() {
                        if sel > max {
                            self.key_list_state.select(Some(max));
                        }
                    }
                    if let Some(idx) = self.active_key_index {
                        if idx >= self.keys.len() {
                            self.active_key_index = Some(self.keys.len().saturating_sub(1));
                        }
                    }
                }
                self.modal = Modal::Success {
                    message: format!("Key '{}' deleted", label),
                };
            }
            AppMessage::KeyDeleted(Err(e)) => {
                self.modal = Modal::Error {
                    message: format!("Failed to delete key: {}", e),
                };
            }
            AppMessage::PlcStateLoaded(Ok(state)) => {
                // Compute the CID of the latest operation for `prev`
                if let Some(log) = &self.audit_log {
                    if let Some(last) = log.last() {
                        if let Some(cid) = last.get("cid").and_then(|c| c.as_str()) {
                            self.last_prev_cid = Some(cid.to_string());
                        }
                    }
                }
                self.current_did = Some(state.did.clone());
                self.plc_state = Some(state);
            }
            AppMessage::PlcStateLoaded(Err(e)) => {
                self.modal = Modal::Error {
                    message: format!("Failed to load PLC state: {}", e),
                };
            }
            AppMessage::AuditLogLoaded(Ok(log)) => {
                // Extract prev CID from last entry
                if let Some(last) = log.last() {
                    if let Some(cid) = last.get("cid").and_then(|c| c.as_str()) {
                        self.last_prev_cid = Some(cid.to_string());
                    }
                }
                self.audit_log = Some(log);
                self.expanded_audit_entries.clear();
                if self.audit_list_state.selected().is_none() {
                    self.audit_list_state.select(Some(0));
                }
            }
            AppMessage::AuditLogLoaded(Err(e)) => {
                self.modal = Modal::Error {
                    message: format!("Failed to load audit log: {}", e),
                };
            }
            AppMessage::OperationSigned(Ok(signed_op)) => {
                self.pending_operation = Some(signed_op);
                self.confirm_action = Some(ConfirmAction::SubmitOperation);
                self.modal = Modal::Confirm {
                    title: "Operation Signed".to_string(),
                    message: "Submit to plc.directory?".to_string(),
                    options: vec![
                        ("y".to_string(), "Submit now".to_string()),
                        ("f".to_string(), "Save to file".to_string()),
                        ("n".to_string(), "Cancel".to_string()),
                    ],
                };
            }
            AppMessage::OperationSigned(Err(e)) => {
                self.modal = Modal::Error {
                    message: format!("Signing failed: {}", e),
                };
            }
            AppMessage::OperationSubmitted(Ok(_)) => {
                self.pending_operation = None;
                self.operation_diff = None;
                self.modal = Modal::Success {
                    message: "PLC operation submitted to plc.directory".to_string(),
                };
                // Refresh state
                if let Some(did) = &self.current_did {
                    let did = did.clone();
                    self.spawn_load_plc_state(&did);
                    self.spawn_load_audit_log(&did);
                }
            }
            AppMessage::OperationSubmitted(Err(e)) => {
                self.modal = Modal::Error {
                    message: format!("Submission failed: {}", e),
                };
            }
            AppMessage::LoginResult(Ok(session)) => {
                self.current_did = Some(session.did.clone());
                self.login_password.clear();
                let did = session.did.clone();
                self.session = Some(session);
                self.spawn_load_plc_state(&did);
                self.spawn_load_audit_log(&did);
                self.modal = Modal::Success {
                    message: "Logged in successfully".to_string(),
                };
            }
            AppMessage::LoginResult(Err(e)) => {
                self.login_password.clear();
                self.modal = Modal::Error {
                    message: format!("Login failed: {}", e),
                };
            }
            AppMessage::SessionRefreshed(Ok(session)) => {
                self.session = Some(session);
                self.modal = Modal::Success {
                    message: "Session refreshed".to_string(),
                };
            }
            AppMessage::SessionRefreshed(Err(e)) => {
                self.modal = Modal::Error {
                    message: format!("Session refresh failed: {}", e),
                };
            }
            AppMessage::PostCreated(Ok(uri)) => {
                self.post_textarea = tui_textarea::TextArea::default();
                self.modal = Modal::Success {
                    message: format!("Post created: {}", uri),
                };
            }
            AppMessage::PostCreated(Err(e)) => {
                self.modal = Modal::Error {
                    message: format!("Post failed: {}", e),
                };
            }
            AppMessage::PlcTokenRequested(Ok(())) => {
                self.modal = Modal::TextInput {
                    title: "Enter PLC token from email".to_string(),
                    value: String::new(),
                    target: TextInputTarget::PlcToken,
                };
            }
            AppMessage::PlcTokenRequested(Err(e)) => {
                self.pending_rotation_keys = None;
                self.modal = Modal::Error {
                    message: format!("Failed to request token: {}", e),
                };
            }
            AppMessage::PdsPlcOperationSigned(Ok(signed_resp)) => {
                // PDS returns {"operation": {the actual op}} — extract the inner operation
                let op = signed_resp.get("operation").cloned().unwrap_or(signed_resp);
                if let Some(did) = &self.current_did {
                    self.loading = Some("Submitting PDS-signed operation".to_string());
                    let tx = self.msg_tx.clone();
                    let did = did.clone();
                    tokio::spawn(async move {
                        let client = PlcDirectoryClient::new();
                        let result = client
                            .submit_operation(&did, &op)
                            .await
                            .map_err(|e| e.to_string());
                        let _ = tx.send(AppMessage::OperationSubmitted(result));
                    });
                }
                self.pending_rotation_keys = None;
            }
            AppMessage::PdsPlcOperationSigned(Err(e)) => {
                self.pending_rotation_keys = None;
                self.modal = Modal::Error {
                    message: format!("PDS signing failed: {}", e),
                };
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enclave::EnclaveKey;
    use crate::plc::{PlcOperation, PlcService, PlcState};
    use std::collections::BTreeMap;

    fn make_app() -> App {
        App::new()
    }

    fn make_test_key(label: &str) -> EnclaveKey {
        EnclaveKey {
            label: label.to_string(),
            did_key: format!("did:key:zTest{}", label),
            syncable: true,
            public_key_bytes: vec![0x04; 65],
        }
    }

    fn make_test_state() -> PlcState {
        let mut services = BTreeMap::new();
        services.insert(
            "atproto_pds".to_string(),
            PlcService {
                service_type: "AtprotoPersonalDataServer".to_string(),
                endpoint: "https://pds.example.com".to_string(),
            },
        );

        PlcState {
            did: "did:plc:testdid123".to_string(),
            rotation_keys: vec![
                "did:key:zRot1".to_string(),
                "did:key:zRot2".to_string(),
                "did:key:zRot3".to_string(),
            ],
            verification_methods: BTreeMap::new(),
            also_known_as: vec!["at://test.handle".to_string()],
            services,
        }
    }

    fn make_test_session() -> PdsSession {
        PdsSession {
            did: "did:plc:testsession".to_string(),
            handle: "test.handle".to_string(),
            access_jwt: "access_token".to_string(),
            refresh_jwt: "refresh_token".to_string(),
            pds_endpoint: "https://bsky.social".to_string(),
        }
    }

    // === ActiveTab tests ===

    #[test]
    fn test_active_tab_index() {
        assert_eq!(ActiveTab::Keys.index(), 0);
        assert_eq!(ActiveTab::Identity.index(), 1);
        assert_eq!(ActiveTab::Sign.index(), 2);
        assert_eq!(ActiveTab::Audit.index(), 3);
        assert_eq!(ActiveTab::Post.index(), 4);
        assert_eq!(ActiveTab::Login.index(), 5);
    }

    // === App initialization tests ===

    #[test]
    fn test_app_new_defaults() {
        let app = make_app();
        assert_eq!(app.active_tab, ActiveTab::Keys);
        assert_eq!(app.modal, Modal::None);
        assert_eq!(app.input_mode, InputMode::Normal);
        assert!(!app.should_quit);
        assert!(app.keys.is_empty());
        assert!(app.active_key_index.is_none());
        assert!(app.current_did.is_none());
        assert!(app.plc_state.is_none());
        assert!(app.audit_log.is_none());
        assert!(app.session.is_none());
        assert!(app.pending_operation.is_none());
        assert!(app.loading.is_none());
        assert!(!app.show_operation_json);
        assert_eq!(app.sign_scroll, 0);
        assert_eq!(app.login_field, 0);
        assert!(app.login_handle.is_empty());
        assert!(app.login_password.is_empty());
    }

    // === Global keybinding tests ===

    #[test]
    fn test_quit() {
        let mut app = make_app();
        app.send_key(KeyCode::Char('q'));
        assert!(app.should_quit);
    }

    #[test]
    fn test_help_modal() {
        let mut app = make_app();
        app.send_key(KeyCode::Char('?'));
        assert_eq!(app.modal, Modal::Help);
    }

    #[test]
    fn test_tab_switching() {
        let mut app = make_app();

        app.send_key(KeyCode::Char('2'));
        assert_eq!(app.active_tab, ActiveTab::Identity);

        app.send_key(KeyCode::Char('3'));
        assert_eq!(app.active_tab, ActiveTab::Sign);

        app.send_key(KeyCode::Char('4'));
        assert_eq!(app.active_tab, ActiveTab::Audit);

        app.send_key(KeyCode::Char('1'));
        assert_eq!(app.active_tab, ActiveTab::Keys);
    }

    #[test]
    fn test_tab_5_enters_editing() {
        let mut app = make_app();
        app.send_key(KeyCode::Char('5'));
        assert_eq!(app.active_tab, ActiveTab::Post);
        assert_eq!(app.input_mode, InputMode::Editing);
    }

    #[test]
    fn test_tab_6_enters_editing_when_no_session() {
        let mut app = make_app();
        app.send_key(KeyCode::Char('6'));
        assert_eq!(app.active_tab, ActiveTab::Login);
        assert_eq!(app.input_mode, InputMode::Editing);
    }

    #[test]
    fn test_tab_6_stays_normal_when_logged_in() {
        let mut app = make_app();
        app.session = Some(make_test_session());
        app.send_key(KeyCode::Char('6'));
        assert_eq!(app.active_tab, ActiveTab::Login);
        assert_eq!(app.input_mode, InputMode::Normal);
    }

    // === Modal tests ===

    #[test]
    fn test_help_modal_close_esc() {
        let mut app = make_app();
        app.modal = Modal::Help;
        app.send_key(KeyCode::Esc);
        assert_eq!(app.modal, Modal::None);
    }

    #[test]
    fn test_help_modal_close_question() {
        let mut app = make_app();
        app.modal = Modal::Help;
        app.send_key(KeyCode::Char('?'));
        assert_eq!(app.modal, Modal::None);
    }

    #[test]
    fn test_error_modal_close_esc() {
        let mut app = make_app();
        app.modal = Modal::Error {
            message: "test error".to_string(),
        };
        app.send_key(KeyCode::Esc);
        assert_eq!(app.modal, Modal::None);
    }

    #[test]
    fn test_error_modal_close_enter() {
        let mut app = make_app();
        app.modal = Modal::Error {
            message: "test error".to_string(),
        };
        app.send_key(KeyCode::Enter);
        assert_eq!(app.modal, Modal::None);
    }

    #[test]
    fn test_success_modal_close_any_key() {
        let mut app = make_app();
        app.modal = Modal::Success {
            message: "done".to_string(),
        };
        app.send_key(KeyCode::Char('x'));
        assert_eq!(app.modal, Modal::None);
    }

    #[test]
    fn test_touchid_modal_not_dismissible() {
        let mut app = make_app();
        app.modal = Modal::TouchId {
            message: "signing".to_string(),
        };
        app.send_key(KeyCode::Esc);
        // Still showing TouchId modal
        assert!(matches!(app.modal, Modal::TouchId { .. }));
    }

    #[test]
    fn test_modal_blocks_global_keys() {
        let mut app = make_app();
        app.modal = Modal::Help;
        app.send_key(KeyCode::Char('q'));
        assert!(!app.should_quit, "q should not quit while modal is open");
        assert_eq!(app.active_tab, ActiveTab::Keys, "tab should not change while modal is open");
    }

    // === KeyGen form tests ===

    #[test]
    fn test_keygen_form_typing() {
        let mut app = make_app();
        app.modal = Modal::KeyGenForm {
            label: String::new(),
            syncable: true,
        };

        app.send_key(KeyCode::Char('m'));
        app.send_key(KeyCode::Char('y'));
        app.send_key(KeyCode::Char('-'));
        app.send_key(KeyCode::Char('k'));

        match &app.modal {
            Modal::KeyGenForm { label, .. } => {
                assert_eq!(label, "my-k");
            }
            _ => panic!("Expected KeyGenForm modal"),
        }
    }

    #[test]
    fn test_keygen_form_backspace() {
        let mut app = make_app();
        app.modal = Modal::KeyGenForm {
            label: "test".to_string(),
            syncable: true,
        };

        app.send_key(KeyCode::Backspace);

        match &app.modal {
            Modal::KeyGenForm { label, .. } => assert_eq!(label, "tes"),
            _ => panic!("Expected KeyGenForm modal"),
        }
    }

    #[test]
    fn test_keygen_form_rejects_special_chars() {
        let mut app = make_app();
        app.modal = Modal::KeyGenForm {
            label: String::new(),
            syncable: true,
        };

        app.send_key(KeyCode::Char(' '));
        app.send_key(KeyCode::Char('!'));
        app.send_key(KeyCode::Char('@'));

        match &app.modal {
            Modal::KeyGenForm { label, .. } => assert!(label.is_empty()),
            _ => panic!("Expected KeyGenForm modal"),
        }
    }

    #[test]
    fn test_keygen_form_esc_cancels() {
        let mut app = make_app();
        app.modal = Modal::KeyGenForm {
            label: "test".to_string(),
            syncable: true,
        };

        app.send_key(KeyCode::Esc);
        assert_eq!(app.modal, Modal::None);
    }

    #[test]
    fn test_keygen_form_enter_empty_does_nothing() {
        let mut app = make_app();
        app.modal = Modal::KeyGenForm {
            label: String::new(),
            syncable: true,
        };

        app.send_key(KeyCode::Enter);
        // Modal should still be open (empty label)
        assert!(matches!(app.modal, Modal::KeyGenForm { .. }));
    }

    // === Text input modal tests ===

    #[test]
    fn test_text_input_typing() {
        let mut app = make_app();
        app.modal = Modal::TextInput {
            title: "Enter DID".to_string(),
            value: String::new(),
            target: TextInputTarget::EditDid,
        };

        app.send_key(KeyCode::Char('d'));
        app.send_key(KeyCode::Char('i'));
        app.send_key(KeyCode::Char('d'));

        match &app.modal {
            Modal::TextInput { value, .. } => assert_eq!(value, "did"),
            _ => panic!("Expected TextInput modal"),
        }
    }

    #[tokio::test]
    async fn test_text_input_submit_valid_did() {
        let mut app = make_app();
        app.modal = Modal::TextInput {
            title: "Enter DID".to_string(),
            value: "did:plc:test123".to_string(),
            target: TextInputTarget::EditDid,
        };

        app.send_key(KeyCode::Enter);
        assert_eq!(app.modal, Modal::None);
        assert_eq!(app.current_did, Some("did:plc:test123".to_string()));
    }

    #[test]
    fn test_text_input_submit_invalid_did() {
        let mut app = make_app();
        app.modal = Modal::TextInput {
            title: "Enter DID".to_string(),
            value: "not-a-did".to_string(),
            target: TextInputTarget::EditDid,
        };

        app.send_key(KeyCode::Enter);
        assert!(matches!(app.modal, Modal::Error { .. }));
    }

    // === Confirm modal tests ===

    #[test]
    fn test_confirm_esc_cancels() {
        let mut app = make_app();
        app.confirm_action = Some(ConfirmAction::Disconnect);
        app.modal = Modal::Confirm {
            title: "Test".to_string(),
            message: "Confirm?".to_string(),
            options: vec![("y".to_string(), "Yes".to_string())],
        };

        app.send_key(KeyCode::Esc);
        assert_eq!(app.modal, Modal::None);
        assert!(app.confirm_action.is_none());
    }

    #[test]
    fn test_confirm_n_cancels() {
        let mut app = make_app();
        app.confirm_action = Some(ConfirmAction::Disconnect);
        app.modal = Modal::Confirm {
            title: "Test".to_string(),
            message: "Confirm?".to_string(),
            options: vec![],
        };

        app.send_key(KeyCode::Char('n'));
        assert_eq!(app.modal, Modal::None);
        assert!(app.confirm_action.is_none());
    }

    // === Keys tab tests ===

    #[test]
    fn test_keys_navigation() {
        let mut app = make_app();
        app.keys = vec![
            make_test_key("key1"),
            make_test_key("key2"),
            make_test_key("key3"),
        ];
        app.key_list_state.select(Some(0));

        app.send_key(KeyCode::Down);
        assert_eq!(app.key_list_state.selected(), Some(1));

        app.send_key(KeyCode::Down);
        assert_eq!(app.key_list_state.selected(), Some(2));

        app.send_key(KeyCode::Down);
        assert_eq!(app.key_list_state.selected(), Some(0)); // wraps

        app.send_key(KeyCode::Up);
        assert_eq!(app.key_list_state.selected(), Some(2)); // wraps back
    }

    #[test]
    fn test_keys_navigation_empty() {
        let mut app = make_app();
        app.send_key(KeyCode::Down); // no crash
        app.send_key(KeyCode::Up);   // no crash
    }

    #[test]
    fn test_keys_new_opens_form() {
        let mut app = make_app();
        app.send_key(KeyCode::Char('n'));
        assert!(matches!(app.modal, Modal::KeyGenForm { .. }));
    }

    #[test]
    fn test_keys_set_active() {
        let mut app = make_app();
        app.keys = vec![make_test_key("key1"), make_test_key("key2")];
        app.key_list_state.select(Some(1));

        app.send_key(KeyCode::Char('s'));
        assert_eq!(app.active_key_index, Some(1));
    }

    #[test]
    fn test_keys_delete_opens_confirm() {
        let mut app = make_app();
        app.keys = vec![make_test_key("mykey")];
        app.key_list_state.select(Some(0));

        app.send_key(KeyCode::Char('d'));
        assert!(matches!(app.modal, Modal::Confirm { .. }));
        assert!(matches!(app.confirm_action, Some(ConfirmAction::DeleteKey(_))));
    }

    #[test]
    fn test_keys_delete_no_selection_does_nothing() {
        let mut app = make_app();
        app.keys = vec![make_test_key("mykey")];
        // No selection

        app.send_key(KeyCode::Char('d'));
        assert_eq!(app.modal, Modal::None);
    }

    // === Identity tab tests ===

    #[test]
    fn test_identity_edit_opens_text_input() {
        let mut app = make_app();
        app.active_tab = ActiveTab::Identity;
        app.send_key(KeyCode::Char('e'));
        assert!(matches!(app.modal, Modal::TextInput { .. }));
    }

    #[test]
    fn test_identity_rotation_key_navigation() {
        let mut app = make_app();
        app.active_tab = ActiveTab::Identity;
        app.plc_state = Some(make_test_state());

        app.send_key(KeyCode::Down);
        assert_eq!(app.rotation_key_list_state.selected(), Some(1));

        app.send_key(KeyCode::Down);
        assert_eq!(app.rotation_key_list_state.selected(), Some(2));

        app.send_key(KeyCode::Up);
        assert_eq!(app.rotation_key_list_state.selected(), Some(1));
    }

    #[test]
    fn test_identity_add_key_no_state() {
        let mut app = make_app();
        app.active_tab = ActiveTab::Identity;
        app.send_key(KeyCode::Char('a'));
        assert!(matches!(app.modal, Modal::Error { .. }));
    }

    #[test]
    fn test_identity_add_key_no_active_key() {
        let mut app = make_app();
        app.active_tab = ActiveTab::Identity;
        app.plc_state = Some(make_test_state());
        app.send_key(KeyCode::Char('a'));
        assert!(matches!(app.modal, Modal::Error { .. }));
    }

    #[test]
    fn test_identity_add_key_stages_operation() {
        let mut app = make_app();
        app.active_tab = ActiveTab::Identity;
        // Put the SE key in rotation keys so self-sign path is taken
        let mut state = make_test_state();
        state.rotation_keys.push("did:key:zTestmykey".to_string());
        app.plc_state = Some(state);
        app.keys = vec![make_test_key("mykey")];
        app.active_key_index = Some(0);
        app.last_prev_cid = Some("bafyprev".to_string());

        app.send_key(KeyCode::Char('a'));

        assert_eq!(app.active_tab, ActiveTab::Sign);
        assert!(app.pending_operation.is_some());
        assert!(app.operation_diff.is_some());

        let op = app.pending_operation.as_ref().unwrap();
        assert_eq!(op.rotation_keys[0], "did:key:zTestmykey");
        assert_eq!(op.prev, Some("bafyprev".to_string()));
    }

    #[tokio::test]
    async fn test_identity_add_key_pds_flow_when_not_in_rotation() {
        let mut app = make_app();
        app.active_tab = ActiveTab::Identity;
        app.plc_state = Some(make_test_state()); // SE key NOT in rotation
        app.keys = vec![make_test_key("mykey")];
        app.active_key_index = Some(0);
        app.session = Some(make_test_session());

        app.send_key(KeyCode::Char('a'));

        // Should NOT switch to Sign tab — goes to PDS token flow instead
        assert_eq!(app.active_tab, ActiveTab::Identity);
        assert!(app.pending_rotation_keys.is_some());
        assert!(app.pending_operation.is_none());
    }

    #[test]
    fn test_identity_add_key_no_session_no_rotation() {
        let mut app = make_app();
        app.active_tab = ActiveTab::Identity;
        app.plc_state = Some(make_test_state()); // SE key NOT in rotation
        app.keys = vec![make_test_key("mykey")];
        app.active_key_index = Some(0);
        // No session

        app.send_key(KeyCode::Char('a'));

        // Should show error about needing to login
        assert!(matches!(app.modal, Modal::Error { .. }));
    }

    #[test]
    fn test_identity_add_key_deduplicates() {
        let mut app = make_app();
        app.active_tab = ActiveTab::Identity;

        let mut state = make_test_state();
        state.rotation_keys = vec!["did:key:zTestmykey".to_string(), "did:key:zOther".to_string()];
        app.plc_state = Some(state);
        app.keys = vec![make_test_key("mykey")]; // did_key = "did:key:zTestmykey"
        app.active_key_index = Some(0);

        app.send_key(KeyCode::Char('a'));

        let op = app.pending_operation.as_ref().unwrap();
        // Should not have duplicate
        let count = op.rotation_keys.iter().filter(|k| *k == "did:key:zTestmykey").count();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_identity_move_key() {
        let mut app = make_app();
        app.active_tab = ActiveTab::Identity;
        app.plc_state = Some(make_test_state());
        app.rotation_key_list_state.select(Some(1)); // select key at index 1

        app.send_key(KeyCode::Char('m'));

        assert_eq!(app.active_tab, ActiveTab::Sign);
        let op = app.pending_operation.as_ref().unwrap();
        // Key at index 1 should now be at index 0
        assert_eq!(op.rotation_keys[0], "did:key:zRot2");
        assert_eq!(op.rotation_keys[1], "did:key:zRot1");
    }

    #[test]
    fn test_identity_move_key_at_top_does_nothing() {
        let mut app = make_app();
        app.active_tab = ActiveTab::Identity;
        app.plc_state = Some(make_test_state());
        app.rotation_key_list_state.select(Some(0)); // already at top

        app.send_key(KeyCode::Char('m'));
        assert_eq!(app.active_tab, ActiveTab::Identity); // no change
        assert!(app.pending_operation.is_none());
    }

    // === Sign tab tests ===

    #[test]
    fn test_sign_toggle_json() {
        let mut app = make_app();
        app.active_tab = ActiveTab::Sign;
        assert!(!app.show_operation_json);

        app.send_key(KeyCode::Char('j'));
        assert!(app.show_operation_json);

        app.send_key(KeyCode::Char('j'));
        assert!(!app.show_operation_json);
    }

    #[test]
    fn test_sign_scroll() {
        let mut app = make_app();
        app.active_tab = ActiveTab::Sign;

        app.send_key(KeyCode::Down);
        assert_eq!(app.sign_scroll, 1);

        app.send_key(KeyCode::Down);
        assert_eq!(app.sign_scroll, 2);

        app.send_key(KeyCode::Up);
        assert_eq!(app.sign_scroll, 1);

        app.send_key(KeyCode::Up);
        app.send_key(KeyCode::Up); // saturating
        assert_eq!(app.sign_scroll, 0);
    }

    #[test]
    fn test_sign_esc_clears_operation() {
        let mut app = make_app();
        app.active_tab = ActiveTab::Sign;
        app.pending_operation = Some(PlcOperation {
            op_type: "plc_operation".to_string(),
            rotation_keys: vec![],
            verification_methods: BTreeMap::new(),
            also_known_as: vec![],
            services: BTreeMap::new(),
            prev: None,
            sig: None,
        });
        app.operation_diff = Some(crate::plc::OperationDiff {
            changes: vec![],
        });

        app.send_key(KeyCode::Esc);
        assert!(app.pending_operation.is_none());
        assert!(app.operation_diff.is_none());
    }

    // === Audit tab tests ===

    #[test]
    fn test_audit_navigation() {
        let mut app = make_app();
        app.active_tab = ActiveTab::Audit;
        app.audit_log = Some(vec![
            serde_json::json!({"cid": "cid1"}),
            serde_json::json!({"cid": "cid2"}),
            serde_json::json!({"cid": "cid3"}),
        ]);
        app.audit_list_state.select(Some(0));

        app.send_key(KeyCode::Down);
        assert_eq!(app.audit_list_state.selected(), Some(1));
    }

    #[test]
    fn test_audit_expand_collapse() {
        let mut app = make_app();
        app.active_tab = ActiveTab::Audit;
        app.audit_log = Some(vec![serde_json::json!({"cid": "cid1"})]);
        app.audit_list_state.select(Some(0));

        assert!(!app.expanded_audit_entries.contains(&0));

        app.send_key(KeyCode::Enter);
        assert!(app.expanded_audit_entries.contains(&0));

        app.send_key(KeyCode::Enter);
        assert!(!app.expanded_audit_entries.contains(&0));
    }

    // === Login editing tests ===

    #[test]
    fn test_login_editing_handle() {
        let mut app = make_app();
        app.active_tab = ActiveTab::Login;
        app.input_mode = InputMode::Editing;
        app.login_field = 0;

        app.send_key(KeyCode::Char('t'));
        app.send_key(KeyCode::Char('e'));
        app.send_key(KeyCode::Char('s'));
        app.send_key(KeyCode::Char('t'));

        assert_eq!(app.login_handle, "test");
    }

    #[test]
    fn test_login_editing_password() {
        let mut app = make_app();
        app.active_tab = ActiveTab::Login;
        app.input_mode = InputMode::Editing;
        app.login_field = 1;

        app.send_key(KeyCode::Char('p'));
        app.send_key(KeyCode::Char('a'));
        app.send_key(KeyCode::Char('s'));
        app.send_key(KeyCode::Char('s'));

        assert_eq!(app.login_password, "pass");
    }

    #[test]
    fn test_login_editing_tab_switches_field() {
        let mut app = make_app();
        app.active_tab = ActiveTab::Login;
        app.input_mode = InputMode::Editing;
        assert_eq!(app.login_field, 0);

        app.send_key(KeyCode::Tab);
        assert_eq!(app.login_field, 1);

        app.send_key(KeyCode::Tab);
        assert_eq!(app.login_field, 0);
    }

    #[test]
    fn test_login_editing_backspace() {
        let mut app = make_app();
        app.active_tab = ActiveTab::Login;
        app.input_mode = InputMode::Editing;
        app.login_handle = "test".to_string();

        app.send_key(KeyCode::Backspace);
        assert_eq!(app.login_handle, "tes");
    }

    #[test]
    fn test_login_editing_esc() {
        let mut app = make_app();
        app.active_tab = ActiveTab::Login;
        app.input_mode = InputMode::Editing;

        app.send_key(KeyCode::Esc);
        assert_eq!(app.input_mode, InputMode::Normal);
    }

    #[test]
    fn test_login_enter_empty_does_nothing() {
        let mut app = make_app();
        app.active_tab = ActiveTab::Login;
        app.input_mode = InputMode::Editing;
        // Both fields empty

        app.send_key(KeyCode::Enter);
        assert_eq!(app.input_mode, InputMode::Editing); // unchanged
    }

    // === Login tab (normal mode) tests ===

    #[test]
    fn test_login_disconnect_opens_confirm() {
        let mut app = make_app();
        app.active_tab = ActiveTab::Login;
        app.session = Some(make_test_session());

        app.send_key(KeyCode::Char('d'));
        assert!(matches!(app.modal, Modal::Confirm { .. }));
    }

    #[test]
    fn test_login_enter_editing_when_no_session() {
        let mut app = make_app();
        app.active_tab = ActiveTab::Login;

        app.send_key(KeyCode::Enter);
        assert_eq!(app.input_mode, InputMode::Editing);
    }

    // === Message handling tests ===

    #[test]
    fn test_handle_keys_loaded_ok() {
        let mut app = make_app();
        app.loading = Some("Loading".to_string());

        app.inject_message(AppMessage::KeysLoaded(Ok(vec![
            make_test_key("key1"),
            make_test_key("key2"),
        ])));

        assert!(app.loading.is_none());
        assert_eq!(app.keys.len(), 2);
        assert_eq!(app.key_list_state.selected(), Some(0));
    }

    #[test]
    fn test_handle_keys_loaded_empty() {
        let mut app = make_app();
        app.inject_message(AppMessage::KeysLoaded(Ok(vec![])));

        assert!(app.keys.is_empty());
        assert!(app.key_list_state.selected().is_none());
    }

    #[test]
    fn test_handle_keys_loaded_err() {
        let mut app = make_app();
        app.inject_message(AppMessage::KeysLoaded(Err("SE not available".to_string())));

        assert!(matches!(app.modal, Modal::Error { .. }));
    }

    #[test]
    fn test_handle_key_generated() {
        let mut app = make_app();
        app.inject_message(AppMessage::KeyGenerated(Ok(make_test_key("new"))));

        assert_eq!(app.keys.len(), 1);
        assert_eq!(app.key_list_state.selected(), Some(0));
        assert_eq!(app.active_key_index, Some(0));
        assert!(matches!(app.modal, Modal::Success { .. }));
    }

    #[test]
    fn test_handle_key_generated_preserves_active() {
        let mut app = make_app();
        app.keys = vec![make_test_key("existing")];
        app.active_key_index = Some(0);

        app.inject_message(AppMessage::KeyGenerated(Ok(make_test_key("new"))));

        assert_eq!(app.keys.len(), 2);
        assert_eq!(app.active_key_index, Some(0)); // not changed
    }

    #[test]
    fn test_handle_key_deleted() {
        let mut app = make_app();
        app.keys = vec![make_test_key("a"), make_test_key("b")];
        app.key_list_state.select(Some(0));
        app.active_key_index = Some(0);

        app.inject_message(AppMessage::KeyDeleted(Ok("a".to_string())));

        assert_eq!(app.keys.len(), 1);
        assert_eq!(app.keys[0].label, "b");
        assert!(matches!(app.modal, Modal::Success { .. }));
    }

    #[test]
    fn test_handle_key_deleted_all() {
        let mut app = make_app();
        app.keys = vec![make_test_key("only")];
        app.key_list_state.select(Some(0));
        app.active_key_index = Some(0);

        app.inject_message(AppMessage::KeyDeleted(Ok("only".to_string())));

        assert!(app.keys.is_empty());
        assert!(app.key_list_state.selected().is_none());
        assert!(app.active_key_index.is_none());
    }

    #[test]
    fn test_handle_plc_state_loaded() {
        let mut app = make_app();
        let state = make_test_state();

        app.inject_message(AppMessage::PlcStateLoaded(Ok(state)));

        assert!(app.plc_state.is_some());
        assert_eq!(app.current_did, Some("did:plc:testdid123".to_string()));
    }

    #[test]
    fn test_handle_audit_log_loaded() {
        let mut app = make_app();
        let log = vec![
            serde_json::json!({"cid": "cid1"}),
            serde_json::json!({"cid": "cid2"}),
        ];

        app.inject_message(AppMessage::AuditLogLoaded(Ok(log)));

        assert!(app.audit_log.is_some());
        assert_eq!(app.audit_log.as_ref().unwrap().len(), 2);
        assert_eq!(app.last_prev_cid, Some("cid2".to_string()));
        assert_eq!(app.audit_list_state.selected(), Some(0));
        assert!(app.expanded_audit_entries.is_empty());
    }

    #[test]
    fn test_handle_operation_signed() {
        let mut app = make_app();
        let op = PlcOperation {
            op_type: "plc_operation".to_string(),
            rotation_keys: vec![],
            verification_methods: BTreeMap::new(),
            also_known_as: vec![],
            services: BTreeMap::new(),
            prev: None,
            sig: Some("signed!".to_string()),
        };

        app.inject_message(AppMessage::OperationSigned(Ok(op)));

        assert!(app.pending_operation.is_some());
        assert!(matches!(app.confirm_action, Some(ConfirmAction::SubmitOperation)));
        assert!(matches!(app.modal, Modal::Confirm { .. }));
    }

    #[test]
    fn test_handle_operation_signed_err() {
        let mut app = make_app();
        app.inject_message(AppMessage::OperationSigned(Err("cancelled".to_string())));

        assert!(matches!(app.modal, Modal::Error { .. }));
    }

    #[test]
    fn test_handle_operation_submitted() {
        let mut app = make_app();
        app.pending_operation = Some(PlcOperation {
            op_type: "plc_operation".to_string(),
            rotation_keys: vec![],
            verification_methods: BTreeMap::new(),
            also_known_as: vec![],
            services: BTreeMap::new(),
            prev: None,
            sig: Some("sig".to_string()),
        });
        app.operation_diff = Some(crate::plc::OperationDiff { changes: vec![] });

        app.inject_message(AppMessage::OperationSubmitted(Ok("ok".to_string())));

        assert!(app.pending_operation.is_none());
        assert!(app.operation_diff.is_none());
        assert!(matches!(app.modal, Modal::Success { .. }));
    }

    #[tokio::test]
    async fn test_handle_login_result_ok() {
        let mut app = make_app();
        app.login_password = "secret".to_string();

        app.inject_message(AppMessage::LoginResult(Ok(make_test_session())));

        assert!(app.session.is_some());
        assert_eq!(app.current_did, Some("did:plc:testsession".to_string()));
        assert!(app.login_password.is_empty(), "password should be cleared");
        assert!(matches!(app.modal, Modal::Success { .. }));
    }

    #[test]
    fn test_handle_login_result_err() {
        let mut app = make_app();
        app.login_password = "wrong".to_string();

        app.inject_message(AppMessage::LoginResult(Err("bad creds".to_string())));

        assert!(app.session.is_none());
        assert!(app.login_password.is_empty(), "password should be cleared on error too");
        assert!(matches!(app.modal, Modal::Error { .. }));
    }

    #[test]
    fn test_handle_session_refreshed() {
        let mut app = make_app();
        let new_session = make_test_session();
        app.inject_message(AppMessage::SessionRefreshed(Ok(new_session)));

        assert!(app.session.is_some());
        assert!(matches!(app.modal, Modal::Success { .. }));
    }

    #[test]
    fn test_handle_post_created() {
        let mut app = make_app();
        app.inject_message(AppMessage::PostCreated(Ok("at://did:plc:test/app.bsky.feed.post/abc".to_string())));

        assert!(matches!(app.modal, Modal::Success { .. }));
    }

    #[test]
    fn test_handle_post_created_err() {
        let mut app = make_app();
        app.inject_message(AppMessage::PostCreated(Err("unauthorized".to_string())));

        assert!(matches!(app.modal, Modal::Error { .. }));
    }

    #[test]
    fn test_loading_cleared_on_message() {
        let mut app = make_app();
        app.loading = Some("Doing stuff".to_string());

        app.inject_message(AppMessage::KeysLoaded(Ok(vec![])));
        assert!(app.loading.is_none());
    }

    // === Post editing tests ===

    #[test]
    fn test_post_editing_esc() {
        let mut app = make_app();
        app.active_tab = ActiveTab::Post;
        app.input_mode = InputMode::Editing;

        app.send_key(KeyCode::Esc);
        assert_eq!(app.input_mode, InputMode::Normal);
    }
}
