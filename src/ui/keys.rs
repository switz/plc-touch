use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame,
};

use crate::app::App;

impl App {
    pub fn render_keys(&self, frame: &mut Frame, area: Rect) {
        let block = Block::default()
            .title(" Secure Enclave Keys ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Blue));

        if self.keys.is_empty() {
            let lines = vec![
                Line::from(""),
                Line::from("  No keys found in Secure Enclave."),
                Line::from(""),
                Line::from(Span::styled(
                    "  Press 'n' to generate a new key.",
                    Style::default().fg(Color::DarkGray),
                )),
                Line::from(""),
                Line::from("  Keys are stored in the Secure Enclave. Syncable keys"),
                Line::from("  are shared across devices via iCloud Keychain."),
            ];
            let paragraph = Paragraph::new(lines).block(block);
            frame.render_widget(paragraph, area);
            return;
        }

        let items: Vec<ListItem> = self
            .keys
            .iter()
            .enumerate()
            .map(|(i, key)| {
                let is_active = self.active_key_index == Some(i);
                let marker = if is_active { " *" } else { "" };
                let lines = vec![
                    Line::from(vec![
                        Span::styled(
                            if is_active { "  \u{25b8} " } else { "    " },
                            Style::default().fg(Color::Cyan),
                        ),
                        Span::styled(
                            &key.label,
                            Style::default()
                                .fg(if is_active { Color::Cyan } else { Color::White })
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(marker, Style::default().fg(Color::Yellow)),
                    ]),
                    Line::from(vec![
                        Span::raw("    "),
                        Span::styled(&key.did_key, Style::default().fg(Color::Gray)),
                    ]),
                    Line::from(vec![
                        Span::raw("    "),
                        Span::styled(
                            if key.syncable {
                                "iCloud Keychain (synced)   Protection: Touch ID"
                            } else {
                                "Secure Enclave (device-only)   Protection: Touch ID"
                            },
                            Style::default().fg(Color::Gray),
                        ),
                    ]),
                    Line::from(""),
                ];
                ListItem::new(lines)
            })
            .collect();

        let list = List::new(items)
            .block(block)
            .highlight_style(Style::default().bg(Color::Rgb(40, 40, 50)));

        let mut state = self.key_list_state.clone();
        frame.render_stateful_widget(list, area, &mut state);
    }

    pub fn keys_keybindings(&self) -> Vec<(&'static str, &'static str)> {
        vec![
            ("n", "new key"),
            ("d", "delete"),
            ("enter", "copy did:key"),
            ("s", "set active"),
        ]
    }
}
