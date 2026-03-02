use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

use crate::app::App;

impl App {
    pub fn render_login(&self, frame: &mut Frame, area: Rect) {
        let block = Block::default()
            .title(" PDS Login ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Blue));

        if let Some(session) = &self.session {
            let lines = vec![
                Line::from(""),
                Line::from(vec![
                    Span::raw("  Status: "),
                    Span::styled(
                        "\u{25cf} Connected",
                        Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
                    ),
                ]),
                Line::from(vec![
                    Span::raw("  Handle: @"),
                    Span::styled(&session.handle, Style::default().fg(Color::White)),
                ]),
                Line::from(vec![
                    Span::raw("  DID:    "),
                    Span::styled(&session.did, Style::default().fg(Color::Cyan)),
                ]),
                Line::from(vec![
                    Span::raw("  PDS:    "),
                    Span::styled(&session.pds_endpoint, Style::default().fg(Color::DarkGray)),
                ]),
                Line::from(""),
                Line::from(Span::styled(
                    "  [d] Disconnect   [r] Refresh session",
                    Style::default().fg(Color::DarkGray),
                )),
            ];
            let paragraph = Paragraph::new(lines).block(block);
            frame.render_widget(paragraph, area);
            return;
        }

        let handle_style = if self.login_field == 0 {
            Style::default().fg(Color::Cyan).add_modifier(Modifier::UNDERLINED)
        } else {
            Style::default().fg(Color::White)
        };

        let password_style = if self.login_field == 1 {
            Style::default().fg(Color::Cyan).add_modifier(Modifier::UNDERLINED)
        } else {
            Style::default().fg(Color::White)
        };

        let masked_password = "\u{2022}".repeat(self.login_password.len());

        let lines = vec![
            Line::from(""),
            Line::from(vec![
                Span::raw("  Status: "),
                Span::styled("Not connected", Style::default().fg(Color::DarkGray)),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::raw("  Handle:   "),
                Span::styled(
                    format!("{}\u{2588}", self.login_handle),
                    handle_style,
                ),
            ]),
            Line::from(vec![
                Span::raw("  Password: "),
                Span::styled(
                    format!("{}\u{2588}", masked_password),
                    password_style,
                ),
            ]),
            Line::from(""),
            Line::from(Span::styled(
                "  This authenticates with your PDS for:",
                Style::default().fg(Color::DarkGray),
            )),
            Line::from(Span::styled(
                "  \u{2022} Adding rotation keys via PDS API (easier than direct sign)",
                Style::default().fg(Color::DarkGray),
            )),
            Line::from(Span::styled(
                "  \u{2022} Posting test messages to Bluesky",
                Style::default().fg(Color::DarkGray),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "  Your password is used only for the session and never stored.",
                Style::default().fg(Color::DarkGray),
            )),
        ];

        let paragraph = Paragraph::new(lines).block(block);
        frame.render_widget(paragraph, area);
    }

    pub fn login_keybindings(&self) -> Vec<(&'static str, &'static str)> {
        if self.session.is_some() {
            vec![("d", "disconnect"), ("r", "refresh")]
        } else {
            vec![("tab", "next field"), ("enter", "login"), ("esc", "cancel")]
        }
    }
}
