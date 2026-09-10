//! Portable cell rendering derived from the official wordmark, not a replacement logo.
//! Regenerate geometry and colors with `python3 apps/mutte/tools/generate-wordmark.py`.

use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Style},
    text::{Line, Span},
    widgets::Paragraph,
};

use crate::theme::ThemePalette;

pub(crate) const WIDTH: u16 = 40;
pub(crate) const HEIGHT: u16 = 3;
const ARTWORK: &str = include_str!("../assets/wordmark-terminal.txt");

// BEGIN GENERATED GRADIENT
const COMPACT_GRADIENT: [Color; 40] = [
    Color::Rgb(102, 64, 228),
    Color::Rgb(105, 67, 228),
    Color::Rgb(109, 71, 229),
    Color::Rgb(112, 74, 230),
    Color::Rgb(116, 78, 231),
    Color::Rgb(119, 81, 232),
    Color::Rgb(122, 84, 233),
    Color::Rgb(126, 88, 234),
    Color::Rgb(129, 91, 235),
    Color::Rgb(133, 95, 236),
    Color::Rgb(136, 100, 237),
    Color::Rgb(140, 104, 238),
    Color::Rgb(144, 108, 239),
    Color::Rgb(147, 113, 240),
    Color::Rgb(151, 117, 241),
    Color::Rgb(155, 122, 242),
    Color::Rgb(158, 126, 243),
    Color::Rgb(161, 130, 244),
    Color::Rgb(165, 134, 244),
    Color::Rgb(168, 138, 245),
    Color::Rgb(171, 143, 246),
    Color::Rgb(174, 147, 247),
    Color::Rgb(178, 151, 247),
    Color::Rgb(181, 155, 248),
    Color::Rgb(184, 159, 249),
    Color::Rgb(188, 164, 249),
    Color::Rgb(192, 170, 250),
    Color::Rgb(196, 176, 250),
    Color::Rgb(200, 182, 250),
    Color::Rgb(204, 188, 251),
    Color::Rgb(208, 194, 251),
    Color::Rgb(212, 200, 252),
    Color::Rgb(216, 206, 252),
    Color::Rgb(220, 211, 252),
    Color::Rgb(224, 216, 251),
    Color::Rgb(227, 222, 251),
    Color::Rgb(231, 227, 250),
    Color::Rgb(235, 232, 250),
    Color::Rgb(239, 237, 250),
    Color::Rgb(242, 243, 249),
];
// END GENERATED GRADIENT

pub(crate) fn draw(frame: &mut Frame, area: Rect, palette: ThemePalette) {
    let brand_background = palette.bg == ThemePalette::brand_violet().bg;
    let lines = ARTWORK
        .lines()
        .take(usize::from(HEIGHT))
        .map(|row| {
            Line::from(
                row.chars()
                    .zip(COMPACT_GRADIENT.iter().copied())
                    .map(|(symbol, brand_color)| {
                        Span::styled(
                            symbol.to_string(),
                            Style::default().fg(if brand_background {
                                brand_color
                            } else {
                                palette.accent
                            }),
                        )
                    })
                    .collect::<Vec<_>>(),
            )
        })
        .collect::<Vec<_>>();
    frame.render_widget(
        Paragraph::new(lines).style(Style::default().bg(palette.bg)),
        Rect::new(
            area.x,
            area.y,
            area.width.min(WIDTH),
            area.height.min(HEIGHT),
        ),
    );
}
