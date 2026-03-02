use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph},
    Frame,
};

/// Create a centered rectangle of given percentage width/height within `r`.
pub fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

/// Create a centered rectangle with fixed width/height within `r`.
pub fn centered_rect_fixed(width: u16, height: u16, r: Rect) -> Rect {
    let x = r.x + r.width.saturating_sub(width) / 2;
    let y = r.y + r.height.saturating_sub(height) / 2;
    Rect::new(x, y, width.min(r.width), height.min(r.height))
}

/// Render the context-sensitive keybind bar at the bottom.
pub fn render_keybind_bar(frame: &mut Frame, area: Rect, bindings: &[(&str, &str)]) {
    let spans: Vec<Span> = bindings
        .iter()
        .enumerate()
        .flat_map(|(i, (key, desc))| {
            let mut v = vec![
                Span::styled(*key, Style::default().fg(Color::Cyan)),
                Span::raw(" "),
                Span::styled(*desc, Style::default().fg(Color::DarkGray)),
            ];
            if i < bindings.len() - 1 {
                v.push(Span::raw("  "));
            }
            v
        })
        .collect();

    let paragraph = Paragraph::new(Line::from(spans))
        .style(Style::default().fg(Color::DarkGray));
    frame.render_widget(paragraph, area);
}

/// Render a simple loading spinner/message.
pub fn render_loading(frame: &mut Frame, area: Rect, message: &str) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Yellow));
    let paragraph = Paragraph::new(format!("  {} ...", message))
        .block(block)
        .style(Style::default().fg(Color::Yellow));
    frame.render_widget(paragraph, area);
}

/// Render a dimmed overlay across the entire frame area.
pub fn render_dim_overlay(frame: &mut Frame, area: Rect) {
    let overlay = Block::default().style(Style::default().bg(Color::Black));
    frame.render_widget(overlay, area);
}

/// Render a confirmation modal.
pub fn render_confirm_modal(frame: &mut Frame, area: Rect, title: &str, message: &str, options: &[(&str, &str)]) {
    let modal_area = centered_rect_fixed(50, 10, area);
    frame.render_widget(Clear, modal_area);

    let mut lines = vec![
        Line::from(""),
        Line::from(Span::styled(message, Style::default().fg(Color::White))),
        Line::from(""),
    ];

    let option_spans: Vec<Span> = options
        .iter()
        .flat_map(|(key, desc)| {
            vec![
                Span::styled(format!("[{}]", key), Style::default().fg(Color::Cyan)),
                Span::raw(format!(" {}  ", desc)),
            ]
        })
        .collect();
    lines.push(Line::from(option_spans));

    let block = Block::default()
        .title(format!(" {} ", title))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Yellow));

    let paragraph = Paragraph::new(lines).block(block);
    frame.render_widget(paragraph, modal_area);
}

/// Render an error modal.
pub fn render_error_modal(frame: &mut Frame, area: Rect, message: &str) {
    let width = (area.width.saturating_sub(4)).min(100);
    let wrap_width = width.saturating_sub(4) as usize; // account for borders + padding
    let wrapped: Vec<Line> = textwrap(message, wrap_width)
        .into_iter()
        .map(|l| Line::from(Span::styled(l, Style::default().fg(Color::Red))))
        .collect();
    let height = (wrapped.len() as u16 + 5).min(area.height.saturating_sub(2));
    let modal_area = centered_rect_fixed(width, height, area);
    frame.render_widget(Clear, modal_area);

    let mut lines = vec![Line::from("")];
    lines.extend(wrapped);
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled("[esc] close", Style::default().fg(Color::DarkGray))));

    let block = Block::default()
        .title(" Error ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Red));

    let paragraph = Paragraph::new(lines).block(block).wrap(ratatui::widgets::Wrap { trim: false });
    frame.render_widget(paragraph, modal_area);
}

fn textwrap(s: &str, max_width: usize) -> Vec<String> {
    if max_width == 0 {
        return vec![s.to_string()];
    }
    let mut lines = Vec::new();
    let mut remaining = s;
    while remaining.len() > max_width {
        let split_at = remaining[..max_width]
            .rfind(' ')
            .unwrap_or(max_width);
        lines.push(remaining[..split_at].to_string());
        remaining = remaining[split_at..].trim_start();
    }
    if !remaining.is_empty() {
        lines.push(remaining.to_string());
    }
    lines
}

/// Render a success modal.
pub fn render_success_modal(frame: &mut Frame, area: Rect, message: &str) {
    let modal_area = centered_rect_fixed(60, 8, area);
    frame.render_widget(Clear, modal_area);

    let lines = vec![
        Line::from(""),
        Line::from(Span::styled(message, Style::default().fg(Color::Green))),
        Line::from(""),
        Line::from(Span::styled("Press any key to continue", Style::default().fg(Color::DarkGray))),
    ];

    let block = Block::default()
        .title(" Success ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Green));

    let paragraph = Paragraph::new(lines).block(block);
    frame.render_widget(paragraph, modal_area);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_centered_rect_50_percent() {
        let outer = Rect::new(0, 0, 100, 50);
        let inner = centered_rect(50, 50, outer);
        assert!(inner.x > 0);
        assert!(inner.y > 0);
        assert!(inner.width > 0);
        assert!(inner.height > 0);
        assert!(inner.x + inner.width <= outer.width);
        assert!(inner.y + inner.height <= outer.height);
    }

    #[test]
    fn test_centered_rect_100_percent() {
        let outer = Rect::new(0, 0, 100, 50);
        let inner = centered_rect(100, 100, outer);
        assert_eq!(inner.width, outer.width);
        assert_eq!(inner.height, outer.height);
    }

    #[test]
    fn test_centered_rect_fixed_basic() {
        let outer = Rect::new(0, 0, 100, 50);
        let inner = centered_rect_fixed(40, 20, outer);
        assert_eq!(inner.width, 40);
        assert_eq!(inner.height, 20);
        assert_eq!(inner.x, 30);
        assert_eq!(inner.y, 15);
    }

    #[test]
    fn test_centered_rect_fixed_larger_than_area() {
        let outer = Rect::new(0, 0, 30, 20);
        let inner = centered_rect_fixed(50, 40, outer);
        assert_eq!(inner.width, 30);
        assert_eq!(inner.height, 20);
    }

    #[test]
    fn test_centered_rect_fixed_with_offset() {
        let outer = Rect::new(10, 5, 100, 50);
        let inner = centered_rect_fixed(40, 20, outer);
        assert_eq!(inner.width, 40);
        assert_eq!(inner.height, 20);
        assert_eq!(inner.x, 40);
        assert_eq!(inner.y, 20);
    }

    #[test]
    fn test_centered_rect_fixed_zero_size() {
        let outer = Rect::new(0, 0, 100, 50);
        let inner = centered_rect_fixed(0, 0, outer);
        assert_eq!(inner.width, 0);
        assert_eq!(inner.height, 0);
        assert_eq!(inner.x, 50);
        assert_eq!(inner.y, 25);
    }
}
