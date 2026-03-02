use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

use crate::app::App;

impl App {
    pub fn render_identity(&self, frame: &mut Frame, area: Rect) {
        let block = Block::default()
            .title(" DID Identity ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Blue));

        let Some(state) = &self.plc_state else {
            let lines = vec![
                Line::from(""),
                Line::from("  No DID loaded."),
                Line::from(""),
                Line::from(Span::styled(
                    "  Press 'e' to enter a DID, or log in (Tab 6) to auto-load.",
                    Style::default().fg(Color::DarkGray),
                )),
            ];
            let paragraph = Paragraph::new(lines).block(block);
            frame.render_widget(paragraph, area);
            return;
        };

        let mut lines = vec![
            Line::from(""),
            Line::from(vec![
                Span::raw("  DID:     "),
                Span::styled(&state.did, Style::default().fg(Color::Cyan)),
            ]),
        ];

        if let Some(handle) = state.also_known_as.first() {
            let display = handle.strip_prefix("at://").unwrap_or(handle);
            lines.push(Line::from(vec![
                Span::raw("  Handle:  @"),
                Span::styled(display, Style::default().fg(Color::White)),
            ]));
        }

        if let Some(pds) = state.services.get("atproto_pds") {
            lines.push(Line::from(vec![
                Span::raw("  PDS:     "),
                Span::styled(&pds.endpoint, Style::default().fg(Color::DarkGray)),
            ]));
        }

        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "  --- Rotation Keys (by priority) ---",
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(""));

        for (i, key) in state.rotation_keys.iter().enumerate() {
            let truncated = if key.len() > 40 {
                format!("{}...", &key[..40])
            } else {
                key.clone()
            };

            let is_ours = self.keys.iter().any(|k| &k.did_key == key);
            let marker = if is_ours { " * YOUR KEY" } else { "" };

            let is_selected = self.rotation_key_list_state.selected() == Some(i);
            let prefix = if is_selected { "  \u{25b8} " } else { "    " };

            lines.push(Line::from(vec![
                Span::styled(prefix, Style::default().fg(Color::Cyan)),
                Span::styled(format!("{}: ", i), Style::default().fg(Color::DarkGray)),
                Span::styled(
                    truncated,
                    Style::default().fg(if is_ours { Color::Green } else { Color::White }),
                ),
                Span::styled(marker, Style::default().fg(Color::Yellow)),
            ]));
        }

        if !state.verification_methods.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "  --- Verification Methods ---",
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
            )));
            lines.push(Line::from(""));

            for (name, key) in &state.verification_methods {
                let truncated = if key.len() > 50 {
                    format!("{}...", &key[..50])
                } else {
                    key.clone()
                };
                lines.push(Line::from(vec![
                    Span::raw("    "),
                    Span::styled(format!("{}: ", name), Style::default().fg(Color::DarkGray)),
                    Span::styled(truncated, Style::default().fg(Color::White)),
                ]));
            }
        }

        let paragraph = Paragraph::new(lines).block(block);
        frame.render_widget(paragraph, area);
    }

    pub fn identity_keybindings(&self) -> Vec<(&'static str, &'static str)> {
        vec![
            ("e", "edit DID"),
            ("r", "refresh"),
            ("\u{2191}\u{2193}", "select key"),
            ("m", "move key"),
            ("a", "add key"),
            ("x", "remove key"),
        ]
    }
}
