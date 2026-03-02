pub mod audit;
pub mod components;
pub mod identity;
pub mod keys;
pub mod login;
pub mod operations;
pub mod post;

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Tabs},
    Frame,
};

use crate::app::{ActiveTab, App, Modal};
use components::{centered_rect, centered_rect_fixed, render_keybind_bar};

impl App {
    pub fn render(&self, frame: &mut Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1), // Status bar
                Constraint::Length(3), // Tab bar
                Constraint::Min(0),   // Content
                Constraint::Length(1), // Keybind bar
            ])
            .split(frame.area());

        self.render_status_bar(frame, chunks[0]);
        self.render_tab_bar(frame, chunks[1]);

        match self.active_tab {
            ActiveTab::Keys => self.render_keys(frame, chunks[2]),
            ActiveTab::Identity => self.render_identity(frame, chunks[2]),
            ActiveTab::Sign => self.render_sign(frame, chunks[2]),
            ActiveTab::Audit => self.render_audit(frame, chunks[2]),
            ActiveTab::Post => self.render_post(frame, chunks[2]),
            ActiveTab::Login => self.render_login(frame, chunks[2]),
        }

        self.render_keybind_bar_section(frame, chunks[3]);

        // Modal overlay (rendered last, on top)
        match &self.modal {
            Modal::None => {}
            _ => self.render_modal(frame),
        }
    }

    fn render_status_bar(&self, frame: &mut Frame, area: Rect) {
        let did_display = self
            .current_did
            .as_ref()
            .map(|d| {
                if d.len() > 24 {
                    format!("{}...{}", &d[..12], &d[d.len() - 8..])
                } else {
                    d.clone()
                }
            })
            .unwrap_or_else(|| "no DID".to_string());

        let key_display = self
            .active_key_index
            .and_then(|i| self.keys.get(i))
            .map(|k| format!("  \u{1f511} {}", k.label))
            .unwrap_or_default();

        let pds_status = if self.session.is_some() {
            Span::styled(" \u{25cf} PDS", Style::default().fg(Color::Green))
        } else {
            Span::styled(" \u{25cb} PDS", Style::default().fg(Color::DarkGray))
        };

        let loading = self
            .loading
            .as_ref()
            .map(|msg| Span::styled(format!("  {} ...", msg), Style::default().fg(Color::Yellow)))
            .unwrap_or_else(|| Span::raw(""));

        let line = Line::from(vec![
            Span::styled(
                " plc-touch ",
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            Span::styled(did_display, Style::default().fg(Color::Cyan)),
            Span::styled(key_display, Style::default().fg(Color::Yellow)),
            pds_status,
            loading,
        ]);

        frame.render_widget(Paragraph::new(line), area);
    }

    fn render_tab_bar(&self, frame: &mut Frame, area: Rect) {
        let titles = vec!["1 Keys", "2 Identity", "3 Sign", "4 Audit", "5 Post", "6 Login"];
        let tabs = Tabs::new(titles)
            .block(Block::default().borders(Borders::BOTTOM))
            .select(self.active_tab.index())
            .style(Style::default().fg(Color::DarkGray))
            .highlight_style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
            .divider(Span::raw(" | "));

        frame.render_widget(tabs, area);
    }

    fn render_keybind_bar_section(&self, frame: &mut Frame, area: Rect) {
        let mut bindings: Vec<(&str, &str)> = vec![
            ("q", "quit"),
            ("?", "help"),
            ("1-6", "tabs"),
        ];

        let tab_bindings = match self.active_tab {
            ActiveTab::Keys => self.keys_keybindings(),
            ActiveTab::Identity => self.identity_keybindings(),
            ActiveTab::Sign => self.sign_keybindings(),
            ActiveTab::Audit => self.audit_keybindings(),
            ActiveTab::Post => self.post_keybindings(),
            ActiveTab::Login => self.login_keybindings(),
        };

        bindings.extend(tab_bindings);
        render_keybind_bar(frame, area, &bindings);
    }

    fn render_modal(&self, frame: &mut Frame) {
        let area = frame.area();

        match &self.modal {
            Modal::None => {}
            Modal::Help => self.render_help_modal(frame, area),
            Modal::TouchId { message } => {
                let msg = message.clone();
                components::render_dim_overlay(frame, area);
                let modal_area = centered_rect_fixed(50, 7, area);
                frame.render_widget(Clear, modal_area);

                let lines = vec![
                    Line::from(""),
                    Line::from(Span::styled(
                        "  \u{1f510} Waiting for Touch ID...",
                        Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                    )),
                    Line::from(""),
                    Line::from(Span::styled(
                        format!("  {}", msg),
                        Style::default().fg(Color::DarkGray),
                    )),
                    Line::from(""),
                ];

                let block = Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Yellow));
                let paragraph = Paragraph::new(lines).block(block);
                frame.render_widget(paragraph, modal_area);
            }
            Modal::Confirm {
                title,
                message,
                options,
            } => {
                let opts: Vec<(&str, &str)> =
                    options.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
                components::render_confirm_modal(frame, area, title, message, &opts);
            }
            Modal::Error { message } => {
                components::render_error_modal(frame, area, message);
            }
            Modal::Success { message } => {
                components::render_success_modal(frame, area, message);
            }
            Modal::KeyGenForm { .. } => self.render_keygen_modal(frame, area),
            Modal::TextInput { title, value, .. } => {
                let t = title.clone();
                let v = value.clone();
                let modal_area = centered_rect_fixed(50, 7, area);
                frame.render_widget(Clear, modal_area);

                let lines = vec![
                    Line::from(""),
                    Line::from(vec![
                        Span::raw("  "),
                        Span::styled(format!("{}\u{2588}", v), Style::default().fg(Color::Cyan)),
                    ]),
                    Line::from(""),
                    Line::from(Span::styled(
                        "  [enter] confirm  [esc] cancel",
                        Style::default().fg(Color::DarkGray),
                    )),
                ];

                let block = Block::default()
                    .title(format!(" {} ", t))
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Cyan));
                frame.render_widget(Paragraph::new(lines).block(block), modal_area);
            }
        }
    }

    fn render_help_modal(&self, frame: &mut Frame, area: Rect) {
        let modal_area = centered_rect(60, 80, area);
        frame.render_widget(Clear, modal_area);

        let lines = vec![
            Line::from(""),
            Line::from(Span::styled("  Global", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))),
            Line::from("  1-6       Switch tabs"),
            Line::from("  q         Quit"),
            Line::from("  ?         This help"),
            Line::from("  esc       Close modal / cancel"),
            Line::from(""),
            Line::from(Span::styled("  Keys tab", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))),
            Line::from("  n         Generate new key"),
            Line::from("  d         Delete selected key"),
            Line::from("  s         Set as active key"),
            Line::from("  enter     Copy did:key to clipboard"),
            Line::from(""),
            Line::from(Span::styled("  Identity tab", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))),
            Line::from("  e         Edit DID"),
            Line::from("  m         Move selected key (then \u{2191}\u{2193} + enter)"),
            Line::from("  a         Add active key to rotation keys"),
            Line::from("  r         Refresh from plc.directory"),
            Line::from(""),
            Line::from(Span::styled("  Sign tab", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))),
            Line::from("  s         Sign operation (Touch ID)"),
            Line::from("  j         View full operation JSON"),
            Line::from(""),
            Line::from(Span::styled("  Audit tab", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))),
            Line::from("  r         Refresh"),
            Line::from("  enter     Expand/collapse operation"),
            Line::from("  j         View JSON"),
            Line::from(""),
            Line::from(Span::styled(
                "  [esc] close",
                Style::default().fg(Color::DarkGray),
            )),
        ];

        let block = Block::default()
            .title(" Key Bindings ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Yellow));

        let paragraph = Paragraph::new(lines).block(block);
        frame.render_widget(paragraph, modal_area);
    }

    fn render_keygen_modal(&self, frame: &mut Frame, area: Rect) {
        let modal_area = centered_rect_fixed(50, 9, area);
        frame.render_widget(Clear, modal_area);

        let (label, syncable) = match &self.modal {
            Modal::KeyGenForm { label, syncable } => (label.clone(), *syncable),
            _ => return,
        };

        let lines = vec![
            Line::from(""),
            Line::from(vec![
                Span::raw("  Label: "),
                Span::styled(
                    format!("{}\u{2588}", label),
                    Style::default().fg(Color::Cyan),
                ),
            ]),
            Line::from(vec![
                Span::raw("  Sync via iCloud? "),
                Span::styled(
                    if syncable { "[Y]" } else { "[n]" },
                    Style::default().fg(Color::Yellow),
                ),
                Span::styled(
                    "  (toggle with Tab)",
                    Style::default().fg(Color::DarkGray),
                ),
            ]),
            Line::from(""),
            Line::from(Span::styled(
                "  [enter] generate  [esc] cancel",
                Style::default().fg(Color::DarkGray),
            )),
        ];

        let block = Block::default()
            .title(" Generate New Key ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Green));

        frame.render_widget(Paragraph::new(lines).block(block), modal_area);
    }
}
