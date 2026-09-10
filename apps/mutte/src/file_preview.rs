//! Explicit, bounded local previews. Unsupported content is never interpreted
//! as text and files are never launched in another application.
use std::{
    fs::{self, File},
    io::Read,
    path::Path,
};

use anyhow::{Context, Result, bail};
use image::{ImageReader, Rgba, RgbaImage, imageops::FilterType};
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Padding, Paragraph, Wrap},
};

use crate::{
    attachment_picker::modal_area,
    conversation_layout::{truncate_cells, wrap_cells},
    theme::ThemePalette,
};

#[derive(Clone, Copy)]
pub(crate) enum PreviewReturn {
    Attachments,
    AttachmentDetails,
}

const TEXT_PREVIEW_BYTES: u64 = 64 * 1024;
const MAX_IMAGE_PIXELS: u64 = 24_000_000;
const THUMBNAIL_WIDTH: u32 = 192;
const THUMBNAIL_HEIGHT: u32 = 128;

#[derive(Clone, Debug)]
enum FilePreview {
    Text {
        lines: Vec<String>,
        truncated: bool,
    },
    Image {
        pixels: RgbaImage,
        original: (u32, u32),
    },
    Unsupported {
        description: String,
    },
}

impl FilePreview {
    fn load(path: &Path) -> Result<Self> {
        let path = fs::canonicalize(path).context("This file is no longer available")?;
        let metadata = fs::metadata(&path).context("Cannot inspect this file")?;
        if !metadata.is_file() {
            bail!("Only regular files can be previewed")
        }
        if has_extension(&path, &["png", "jpg", "jpeg", "gif", "webp"]) {
            return Self::load_image(&path);
        }
        if has_extension(
            &path,
            &[
                "txt", "md", "markdown", "json", "jsonl", "toml", "yaml", "yml", "csv", "tsv",
                "log", "rs", "swift", "js", "ts", "tsx", "jsx", "html", "css", "xml", "sh", "zsh",
                "fish", "py", "go", "c", "h", "cpp", "hpp", "java", "kt",
            ],
        ) {
            return Self::load_text(&path);
        }
        let kind = path
            .extension()
            .and_then(|value| value.to_str())
            .map(str::to_ascii_uppercase)
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "this binary".into());
        Ok(Self::Unsupported {
            description: format!("No safe inline preview for {kind} files."),
        })
    }

    fn load_text(path: &Path) -> Result<Self> {
        let mut bytes = Vec::new();
        File::open(path)
            .context("Cannot read this file")?
            .take(TEXT_PREVIEW_BYTES + 1)
            .read_to_end(&mut bytes)
            .context("Cannot read this file")?;
        let truncated = bytes.len() as u64 > TEXT_PREVIEW_BYTES;
        bytes.truncate(TEXT_PREVIEW_BYTES as usize);
        let text = std::str::from_utf8(&bytes).context("This text file is not valid UTF-8")?;
        Ok(Self::Text {
            lines: text.lines().map(str::to_owned).collect(),
            truncated,
        })
    }

    fn load_image(path: &Path) -> Result<Self> {
        let original = ImageReader::open(path)
            .context("Cannot read this image")?
            .with_guessed_format()
            .context("Cannot recognize this image")?
            .into_dimensions()
            .context("Cannot read image dimensions")?;
        if u64::from(original.0) * u64::from(original.1) > MAX_IMAGE_PIXELS {
            bail!("This image is too large to preview safely")
        }
        let pixels = ImageReader::open(path)
            .context("Cannot read this image")?
            .with_guessed_format()
            .context("Cannot recognize this image")?
            .decode()
            .context("Cannot decode this image")?
            .resize(THUMBNAIL_WIDTH, THUMBNAIL_HEIGHT, FilterType::Triangle)
            .to_rgba8();
        Ok(Self::Image { pixels, original })
    }
}

pub(crate) struct PreviewDialog {
    preview: FilePreview,
    filename: String,
    pub(crate) return_mode: PreviewReturn,
    scroll: u16,
}

impl PreviewDialog {
    pub(crate) fn new(path: &Path, filename: String, return_mode: PreviewReturn) -> Result<Self> {
        Ok(Self {
            preview: FilePreview::load(path)?,
            filename,
            return_mode,
            scroll: 0,
        })
    }

    pub(crate) fn scroll_up(&mut self) {
        self.scroll = self.scroll.saturating_sub(1);
    }
    pub(crate) fn scroll_down(&mut self) {
        self.scroll = self.scroll.saturating_add(1);
    }
    pub(crate) fn home(&mut self) {
        self.scroll = 0;
    }

    pub(crate) fn draw(&self, frame: &mut Frame, palette: ThemePalette) {
        let area = modal_area(frame.area(), 88, 30);
        frame.render_widget(Clear, area);
        let block = Block::new()
            .borders(Borders::ALL)
            .title(" File preview ")
            .border_style(Style::default().fg(palette.focus))
            .style(Style::default().bg(palette.panel))
            .padding(Padding::horizontal(1));
        let inner = block.inner(area);
        frame.render_widget(block, area);
        let rows = Layout::vertical([
            Constraint::Length(2),
            Constraint::Min(2),
            Constraint::Length(2),
        ])
        .split(inner);
        frame.render_widget(
            Paragraph::new(vec![
                Line::styled(
                    truncate_cells(&self.filename, rows[0].width as usize),
                    Style::default().fg(palette.text).bold(),
                ),
                Line::styled(
                    "Local only · no auto-open or upload",
                    Style::default().fg(palette.muted),
                ),
            ]),
            rows[0],
        );
        match &self.preview {
            FilePreview::Text { lines, truncated } => {
                let mut rendered = lines
                    .iter()
                    .flat_map(|line| wrap_cells(line, rows[1].width as usize))
                    .map(Line::raw)
                    .collect::<Vec<_>>();
                if *truncated {
                    rendered.push(Line::default());
                    rendered.push(Line::styled(
                        "— preview stopped after 64 KiB —",
                        Style::default().fg(palette.warning),
                    ));
                }
                let max_scroll = rendered
                    .len()
                    .saturating_sub(rows[1].height as usize)
                    .min(u16::MAX as usize) as u16;
                frame.render_widget(
                    Paragraph::new(rendered).scroll((self.scroll.min(max_scroll), 0)),
                    rows[1],
                );
            }
            FilePreview::Image { pixels, original } => {
                draw_image(frame, rows[1], pixels, *original, palette)
            }
            FilePreview::Unsupported { description } => frame.render_widget(
                Paragraph::new(vec![
                    Line::styled(description, Style::default().fg(palette.secondary)),
                    Line::default(),
                    Line::styled(
                        "The file can still be sent or downloaded without previewing it.",
                        Style::default().fg(palette.muted),
                    ),
                ])
                .alignment(Alignment::Center)
                .wrap(Wrap { trim: false }),
                rows[1],
            ),
        }
        let hint = match &self.preview {
            FilePreview::Text { .. } => "↑↓ scroll text · Home first line",
            FilePreview::Image { .. } => "True-color terminal-cell thumbnail",
            FilePreview::Unsupported { .. } => "Metadata only · content was not read",
        };
        frame.render_widget(
            Paragraph::new(vec![
                Line::styled("Esc close preview", Style::default().fg(palette.focus)),
                Line::styled(hint, Style::default().fg(palette.muted)),
            ]),
            rows[2],
        );
    }
}

fn draw_image(
    frame: &mut Frame,
    area: Rect,
    image: &RgbaImage,
    original: (u32, u32),
    palette: ThemePalette,
) {
    let available = (
        u32::from(area.width).max(1),
        u32::from(area.height).saturating_mul(2).max(1),
    );
    let scale = (available.0 as f64 / image.width() as f64)
        .min(available.1 as f64 / image.height() as f64)
        .min(1.0);
    let size = (
        ((image.width() as f64 * scale).floor() as u32).max(1),
        ((image.height() as f64 * scale).floor() as u32).max(1),
    );
    let rows = size.1.div_ceil(2);
    let backdrop = color_rgb(palette.panel);
    let lines = (0..rows)
        .map(|row| {
            Line::from(
                (0..size.0)
                    .map(|column| {
                        let x = (column * image.width() / size.0).min(image.width() - 1);
                        let y = (row * 2 * image.height() / size.1).min(image.height() - 1);
                        let top = composite(*image.get_pixel(x, y), backdrop);
                        let bottom = if row * 2 + 1 < size.1 {
                            let y =
                                ((row * 2 + 1) * image.height() / size.1).min(image.height() - 1);
                            composite(*image.get_pixel(x, y), backdrop)
                        } else {
                            backdrop
                        };
                        Span::styled(
                            "▀",
                            Style::default()
                                .fg(Color::Rgb(top.0, top.1, top.2))
                                .bg(Color::Rgb(bottom.0, bottom.1, bottom.2)),
                        )
                    })
                    .collect::<Vec<_>>(),
            )
        })
        .collect::<Vec<_>>();
    frame.render_widget(
        Paragraph::new(lines),
        Rect::new(
            area.x + area.width.saturating_sub(size.0 as u16) / 2,
            area.y + area.height.saturating_sub(rows as u16) / 2,
            size.0 as u16,
            rows as u16,
        ),
    );
    if area.height > rows as u16 {
        frame.render_widget(
            Paragraph::new(format!("{}×{}", original.0, original.1))
                .alignment(Alignment::Right)
                .style(Style::default().fg(palette.muted)),
            Rect::new(area.x, area.bottom().saturating_sub(1), area.width, 1),
        );
    }
}

fn color_rgb(color: Color) -> (u8, u8, u8) {
    match color {
        Color::Rgb(r, g, b) => (r, g, b),
        _ => (18, 21, 30),
    }
}

fn composite(pixel: Rgba<u8>, backdrop: (u8, u8, u8)) -> (u8, u8, u8) {
    let alpha = u16::from(pixel.0[3]);
    let blend = |front: u8, back: u8| {
        ((u16::from(front) * alpha + u16::from(back) * (255 - alpha)) / 255) as u8
    };
    (
        blend(pixel.0[0], backdrop.0),
        blend(pixel.0[1], backdrop.1),
        blend(pixel.0[2], backdrop.2),
    )
}

fn has_extension(path: &Path, accepted: &[&str]) -> bool {
    path.extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| accepted.iter().any(|item| value.eq_ignore_ascii_case(item)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::ImageFormat;
    use uuid::Uuid;

    struct Fixture(std::path::PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("mutte-preview-test-{}", Uuid::new_v4()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn text_is_bounded_and_binary_is_not_interpreted() {
        let fixture = Fixture::new();
        let text = fixture.0.join("notes.txt");
        fs::write(&text, "quiet\n设计\n".repeat(10_000)).unwrap();
        assert!(matches!(
            FilePreview::load(&text).unwrap(),
            FilePreview::Text {
                truncated: true,
                ..
            }
        ));
        let binary = fixture.0.join("archive.zip");
        fs::write(&binary, [0, 159, 146, 150]).unwrap();
        assert!(matches!(
            FilePreview::load(&binary).unwrap(),
            FilePreview::Unsupported { .. }
        ));
    }

    #[test]
    fn image_is_downsampled_and_dimensions_are_retained() {
        let fixture = Fixture::new();
        let path = fixture.0.join("gradient.png");
        RgbaImage::from_fn(320, 200, |x, y| Rgba([x as u8, y as u8, 180, 255]))
            .save_with_format(&path, ImageFormat::Png)
            .unwrap();
        let FilePreview::Image { pixels, original } = FilePreview::load(&path).unwrap() else {
            panic!("expected image preview")
        };
        assert_eq!(original, (320, 200));
        assert!(pixels.width() <= THUMBNAIL_WIDTH && pixels.height() <= THUMBNAIL_HEIGHT);
    }
}
