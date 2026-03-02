use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

use crate::app::App;

impl App {
    pub fn render_post(&self, frame: &mut Frame, area: Rect) {
        let block = Block::default()
            .title(" Post to Bluesky ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Blue));

        let inner = block.inner(area);
        frame.render_widget(block, area);

        if self.session.is_none() {
            let lines = vec![
                Line::from(""),
                Line::from("  Not logged in."),
                Line::from(""),
                Line::from(Span::styled(
                    "  Log in via Tab 6 first.",
                    Style::default().fg(Color::DarkGray),
                )),
            ];
            let paragraph = Paragraph::new(lines);
            frame.render_widget(paragraph, inner);
            return;
        }

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(4), // Header
                Constraint::Min(5),   // Text area
                Constraint::Length(3), // Footer
            ])
            .split(inner);

        // Header
        if let Some(session) = &self.session {
            let header = vec![
                Line::from(""),
                Line::from(vec![
                    Span::raw("  Logged in as: @"),
                    Span::styled(&session.handle, Style::default().fg(Color::White)),
                ]),
                Line::from(vec![
                    Span::raw("  DID: "),
                    Span::styled(&session.did, Style::default().fg(Color::Cyan)),
                ]),
            ];
            frame.render_widget(Paragraph::new(header), chunks[0]);
        }

        // Text area
        let textarea_block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray));
        let textarea_inner = textarea_block.inner(chunks[1]);
        frame.render_widget(textarea_block, chunks[1]);

        frame.render_widget(&self.post_textarea, textarea_inner);

        // Footer
        let char_count = self.post_textarea.lines().join("\n").len();
        let count_style = if char_count > 300 {
            Style::default().fg(Color::Red)
        } else {
            Style::default().fg(Color::DarkGray)
        };

        let footer = vec![
            Line::from(vec![
                Span::raw("  "),
                Span::styled(format!("{}/300 characters", char_count), count_style),
            ]),
            Line::from(Span::styled(
                "  Note: Posts via your PDS session. Your SE rotation key is for PLC identity operations (Tab 3), not repo signing.",
                Style::default().fg(Color::DarkGray),
            )),
        ];
        frame.render_widget(Paragraph::new(footer), chunks[2]);
    }

    pub fn post_keybindings(&self) -> Vec<(&'static str, &'static str)> {
        vec![("ctrl+d", "send"), ("esc", "cancel")]
    }
}
