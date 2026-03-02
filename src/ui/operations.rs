use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

use crate::app::App;

impl App {
    pub fn render_sign(&self, frame: &mut Frame, area: Rect) {
        let block = Block::default()
            .title(" PLC Operation Builder ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Blue));

        let Some(op) = &self.pending_operation else {
            let lines = vec![
                Line::from(""),
                Line::from("  No operation staged."),
                Line::from(""),
                Line::from(Span::styled(
                    "  Stage an operation from the Identity tab (Tab 2):",
                    Style::default().fg(Color::DarkGray),
                )),
                Line::from(Span::styled(
                    "    'm' to move a rotation key",
                    Style::default().fg(Color::DarkGray),
                )),
                Line::from(Span::styled(
                    "    'a' to add your Secure Enclave key",
                    Style::default().fg(Color::DarkGray),
                )),
            ];
            let paragraph = Paragraph::new(lines).block(block);
            frame.render_widget(paragraph, area);
            return;
        };

        let mut lines = vec![Line::from("")];

        if let Some(did) = &self.current_did {
            lines.push(Line::from(vec![
                Span::raw("  Target: "),
                Span::styled(did, Style::default().fg(Color::Cyan)),
            ]));
        }

        if let Some(prev) = &op.prev {
            let truncated = if prev.len() > 60 {
                format!("{}...", &prev[..60])
            } else {
                prev.clone()
            };
            lines.push(Line::from(vec![
                Span::raw("  Prev:   "),
                Span::styled(truncated, Style::default().fg(Color::DarkGray)),
            ]));
        }

        if let Some(idx) = self.active_key_index {
            if let Some(key) = self.keys.get(idx) {
                lines.push(Line::from(vec![
                    Span::raw("  Sign with: "),
                    Span::styled(
                        format!("{} ({}...)", key.label, &key.did_key[..30.min(key.did_key.len())]),
                        Style::default().fg(Color::Green),
                    ),
                ]));
            }
        }

        lines.push(Line::from(""));

        // Show diff if available
        if let Some(diff) = &self.operation_diff {
            lines.push(Line::from(Span::styled(
                "  --- Changes ---",
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
            )));
            lines.push(Line::from(""));

            for change in &diff.changes {
                let style = match change.kind.as_str() {
                    "added" => Style::default().fg(Color::Green),
                    "removed" => Style::default().fg(Color::Red),
                    "modified" => Style::default().fg(Color::Yellow),
                    _ => Style::default().fg(Color::White),
                };
                let prefix = match change.kind.as_str() {
                    "added" => "+",
                    "removed" => "-",
                    "modified" => "~",
                    _ => " ",
                };
                lines.push(Line::from(Span::styled(
                    format!("  {} {}", prefix, change.description),
                    style,
                )));
            }
        }

        // Show JSON preview
        if self.show_operation_json {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "  --- Operation JSON ---",
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
            )));
            lines.push(Line::from(""));

            if let Ok(json) = serde_json::to_string_pretty(op) {
                for json_line in json.lines() {
                    lines.push(Line::from(Span::styled(
                        format!("  {}", json_line),
                        Style::default().fg(Color::DarkGray),
                    )));
                }
            }
        }

        let paragraph = Paragraph::new(lines)
            .block(block)
            .scroll((self.sign_scroll, 0));
        frame.render_widget(paragraph, area);
    }

    pub fn sign_keybindings(&self) -> Vec<(&'static str, &'static str)> {
        if self.pending_operation.is_some() {
            vec![
                ("s", "SIGN (Touch ID)"),
                ("j", "toggle JSON"),
                ("esc", "cancel"),
            ]
        } else {
            vec![]
        }
    }
}
