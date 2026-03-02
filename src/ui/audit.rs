use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame,
};

use crate::app::App;

impl App {
    pub fn render_audit(&self, frame: &mut Frame, area: Rect) {
        let title = if let Some(did) = &self.current_did {
            let truncated = if did.len() > 40 {
                format!("{}...", &did[..40])
            } else {
                did.clone()
            };
            format!(" PLC Audit Log --- {} ", truncated)
        } else {
            " PLC Audit Log ".to_string()
        };

        let block = Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Blue));

        let Some(log) = &self.audit_log else {
            let lines = vec![
                Line::from(""),
                Line::from("  No audit log loaded."),
                Line::from(""),
                Line::from(Span::styled(
                    "  Load a DID in the Identity tab (Tab 2) first.",
                    Style::default().fg(Color::DarkGray),
                )),
            ];
            let paragraph = Paragraph::new(lines).block(block);
            frame.render_widget(paragraph, area);
            return;
        };

        if log.is_empty() {
            let paragraph = Paragraph::new("  No operations found.")
                .block(block);
            frame.render_widget(paragraph, area);
            return;
        }

        let items: Vec<ListItem> = log
            .iter()
            .enumerate()
            .rev()
            .map(|(i, entry)| {
                let op_type = entry
                    .get("operation")
                    .and_then(|o| o.get("type"))
                    .and_then(|t| t.as_str())
                    .unwrap_or("unknown");

                let created_at = entry
                    .get("createdAt")
                    .and_then(|t| t.as_str())
                    .unwrap_or("unknown");

                let cid = entry
                    .get("cid")
                    .and_then(|c| c.as_str())
                    .unwrap_or("unknown");

                let is_genesis = i == 0;
                let genesis_marker = if is_genesis { "  (genesis)" } else { "" };

                let is_expanded = self.expanded_audit_entries.contains(&i);

                let mut lines = vec![
                    Line::from(vec![
                        Span::styled(
                            format!("  #{:<3} ", i + 1),
                            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(created_at, Style::default().fg(Color::White)),
                        Span::styled(
                            format!("  {}{}", op_type, genesis_marker),
                            Style::default().fg(Color::DarkGray),
                        ),
                    ]),
                    Line::from(vec![
                        Span::raw("        CID: "),
                        Span::styled(
                            if cid.len() > 30 { format!("{}...", &cid[..30]) } else { cid.to_string() },
                            Style::default().fg(Color::DarkGray),
                        ),
                    ]),
                ];

                if is_expanded {
                    if let Some(op) = entry.get("operation") {
                        if let Ok(json) = serde_json::to_string_pretty(op) {
                            lines.push(Line::from(""));
                            for json_line in json.lines() {
                                lines.push(Line::from(Span::styled(
                                    format!("        {}", json_line),
                                    Style::default().fg(Color::DarkGray),
                                )));
                            }
                        }
                    }
                }

                lines.push(Line::from(""));
                ListItem::new(lines)
            })
            .collect();

        let list = List::new(items)
            .block(block)
            .highlight_style(Style::default().bg(Color::DarkGray));

        let mut state = self.audit_list_state.clone();
        frame.render_stateful_widget(list, area, &mut state);
    }

    pub fn audit_keybindings(&self) -> Vec<(&'static str, &'static str)> {
        vec![
            ("r", "refresh"),
            ("enter", "expand"),
            ("j", "view JSON"),
        ]
    }
}
