//! Local file chooser. Browsing reads directory entries/metadata only; file
//! contents are read by the encrypted transfer layer after explicit Send.
use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use mutte_protocol::MAX_ATTACHMENT_BYTES;
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::Style,
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Padding, Paragraph, Wrap},
};
use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthStr;

use crate::{
    conversation_layout::{truncate_cells, wrap_cells},
    theme::ThemePalette,
};

const MAX_ENTRIES: usize = 10_000;

#[derive(Clone, Debug)]
pub(crate) struct ChosenFile {
    pub(crate) path: PathBuf,
    pub(crate) filename: String,
    pub(crate) bytes: u64,
    modified: Option<std::time::SystemTime>,
}

impl ChosenFile {
    fn inspect(path: &Path) -> Result<Self> {
        let path = fs::canonicalize(path).context("This file is no longer available")?;
        let metadata = fs::metadata(&path).context("Cannot inspect this file")?;
        if !metadata.is_file() {
            bail!("Choose a regular file, not a folder or special device")
        }
        if metadata.len() > MAX_ATTACHMENT_BYTES {
            bail!("This file exceeds the 32 MiB limit")
        }
        let filename = path
            .file_name()
            .and_then(|name| name.to_str())
            .context("The filename must be valid UTF-8")?
            .to_owned();
        if filename.len() > 255 || filename.chars().any(char::is_control) {
            bail!("This filename is not supported")
        }
        // Verify readability, without hashing, encrypting, or uploading anything.
        fs::File::open(&path).context("You do not have permission to read this file")?;
        Ok(Self {
            path,
            filename,
            bytes: metadata.len(),
            modified: metadata.modified().ok(),
        })
    }

    pub(crate) fn validate_unchanged(&self) -> Result<()> {
        let current = Self::inspect(&self.path)?;
        if current.path != self.path
            || current.bytes != self.bytes
            || current.modified != self.modified
        {
            bail!("The file changed. Go back and select it again before sending")
        }
        Ok(())
    }
}

#[derive(Debug)]
struct Entry {
    path: PathBuf,
    label: String,
    directory: bool,
    link: bool,
}

#[derive(Debug)]
enum Mode {
    Browse,
    Location(String),
    Review(ChosenFile),
}

pub(crate) enum PickerAction {
    None,
    Cancel,
    Preview(ChosenFile),
    Send(ChosenFile),
}

pub(crate) struct AttachmentPicker {
    pub(crate) directory: PathBuf,
    entries: Vec<Entry>,
    selected: usize,
    filter: String,
    hidden: bool,
    truncated: bool,
    mode: Mode,
    review_action: usize,
    review_scroll: u16,
    error: Option<String>,
}

impl AttachmentPicker {
    pub(crate) fn new(directory: PathBuf) -> Self {
        let mut picker = Self {
            directory,
            entries: Vec::new(),
            selected: 0,
            filter: String::new(),
            hidden: false,
            truncated: false,
            mode: Mode::Browse,
            review_action: 0,
            review_scroll: 0,
            error: None,
        };
        if let Err(error) = picker.load(picker.directory.clone()) {
            picker.error = Some(error.to_string());
        }
        picker
    }

    pub(crate) fn initial_directory() -> PathBuf {
        if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
            let downloads = home.join("Downloads");
            return if downloads.is_dir() { downloads } else { home };
        }
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    }

    fn load(&mut self, directory: PathBuf) -> Result<()> {
        let directory = fs::canonicalize(directory).context("That folder is unavailable")?;
        let listing =
            fs::read_dir(&directory).context("Cannot open that folder (check permissions)")?;
        let mut entries = Vec::new();
        let mut truncated = false;
        for item in listing {
            let item = item.context("Could not finish reading this folder")?;
            if !self.hidden && item.file_name().to_string_lossy().starts_with('.') {
                continue;
            }
            if entries.len() >= MAX_ENTRIES {
                truncated = true;
                break;
            }
            let kind = item.file_type().context("Cannot inspect a folder entry")?;
            // Do not traverse links or inspect file contents while browsing.
            if !(kind.is_dir() || kind.is_file() || kind.is_symlink()) {
                continue;
            }
            entries.push(Entry {
                path: item.path(),
                label: item.file_name().to_string_lossy().into_owned(),
                directory: kind.is_dir(),
                link: kind.is_symlink(),
            });
        }
        entries.sort_by(|a, b| {
            b.directory
                .cmp(&a.directory)
                .then_with(|| a.label.to_lowercase().cmp(&b.label.to_lowercase()))
                .then_with(|| a.path.cmp(&b.path))
        });
        self.directory = directory;
        self.entries = entries;
        self.truncated = truncated;
        self.filter.clear();
        self.selected = 0;
        self.error = None;
        Ok(())
    }

    fn visible(&self) -> Vec<&Entry> {
        let query = self.filter.to_lowercase();
        self.entries
            .iter()
            .filter(|entry| entry.label.to_lowercase().contains(&query))
            .collect()
    }

    pub(crate) fn set_error(&mut self, message: String) {
        self.error = Some(message);
    }

    fn enter(&mut self, path: PathBuf) -> Result<()> {
        if fs::metadata(&path)
            .context("That item is unavailable")?
            .is_dir()
        {
            self.load(path)?;
            self.mode = Mode::Browse;
        } else {
            self.mode = Mode::Review(ChosenFile::inspect(&path)?);
            self.review_action = 0;
            self.review_scroll = 0;
            self.error = None;
        }
        Ok(())
    }

    pub(crate) fn on_key(&mut self, key: KeyEvent) -> PickerAction {
        let result = self.handle_key(key);
        match result {
            Ok(action) => action,
            Err(error) => {
                self.error = Some(error.to_string());
                PickerAction::None
            }
        }
    }

    fn handle_key(&mut self, key: KeyEvent) -> Result<PickerAction> {
        if let Mode::Location(value) = &mut self.mode {
            match key.code {
                KeyCode::Esc => self.mode = Mode::Browse,
                KeyCode::Backspace => {
                    value.pop();
                }
                KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    value.clear()
                }
                KeyCode::Char(c)
                    if !key
                        .modifiers
                        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
                {
                    value.push(c)
                }
                KeyCode::Enter => {
                    let path = if let Some(tail) = value.strip_prefix("~/") {
                        std::env::var_os("HOME")
                            .map(PathBuf::from)
                            .context("Home folder is unavailable")?
                            .join(tail)
                    } else {
                        PathBuf::from(value.as_str())
                    };
                    let path = if path.is_absolute() {
                        path
                    } else {
                        self.directory.join(path)
                    };
                    self.enter(path)?;
                }
                _ => {}
            }
            return Ok(PickerAction::None);
        }
        if let Mode::Review(file) = &self.mode {
            match key.code {
                KeyCode::Esc => {
                    self.mode = Mode::Browse;
                    self.error = None;
                }
                KeyCode::Tab | KeyCode::Right => self.review_action = (self.review_action + 1) % 3,
                KeyCode::BackTab | KeyCode::Left => {
                    self.review_action = (self.review_action + 2) % 3
                }
                KeyCode::Up => self.review_scroll = self.review_scroll.saturating_sub(1),
                KeyCode::Down => self.review_scroll = self.review_scroll.saturating_add(1),
                KeyCode::Home => self.review_scroll = 0,
                KeyCode::Char('p' | 'P') => {
                    file.validate_unchanged()?;
                    return Ok(PickerAction::Preview(file.clone()));
                }
                KeyCode::Enter => match self.review_action {
                    0 => {
                        file.validate_unchanged()?;
                        return Ok(PickerAction::Send(file.clone()));
                    }
                    1 => {
                        self.mode = Mode::Browse;
                        self.error = None;
                    }
                    _ => return Ok(PickerAction::Cancel),
                },
                _ => {}
            }
            return Ok(PickerAction::None);
        }
        match key.code {
            KeyCode::Esc => return Ok(PickerAction::Cancel),
            KeyCode::Char('l') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.mode = Mode::Location(self.directory.to_string_lossy().into_owned());
                self.error = None;
            }
            KeyCode::Up => self.selected = self.selected.saturating_sub(1),
            KeyCode::Down => {
                self.selected = (self.selected + 1).min(self.visible().len().saturating_sub(1))
            }
            KeyCode::PageUp => self.selected = self.selected.saturating_sub(8),
            KeyCode::PageDown => {
                self.selected = (self.selected + 8).min(self.visible().len().saturating_sub(1))
            }
            KeyCode::Home => self.selected = 0,
            KeyCode::End => self.selected = self.visible().len().saturating_sub(1),
            KeyCode::Left => {
                if let Some(parent) = self.directory.parent() {
                    self.load(parent.to_owned())?;
                }
            }
            KeyCode::Backspace if self.filter.is_empty() => {
                if let Some(parent) = self.directory.parent() {
                    self.load(parent.to_owned())?;
                }
            }
            KeyCode::Backspace => {
                self.filter.pop();
                self.selected = 0;
            }
            KeyCode::Enter | KeyCode::Right => {
                if let Some(entry) = self.visible().get(self.selected) {
                    self.enter(entry.path.clone())?;
                }
            }
            KeyCode::F(5) => {
                self.hidden = !self.hidden;
                self.load(self.directory.clone())?;
            }
            KeyCode::Char('g') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                let home = std::env::var_os("HOME").context("Home folder is unavailable")?;
                self.load(PathBuf::from(home))?;
            }
            KeyCode::Char('d') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                let home = std::env::var_os("HOME").context("Home folder is unavailable")?;
                self.load(PathBuf::from(home).join("Downloads"))?;
            }
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.filter.clear();
                self.selected = 0;
            }
            KeyCode::Char(c)
                if !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                self.filter.push(c);
                self.selected = 0;
            }
            _ => {}
        }
        Ok(PickerAction::None)
    }

    pub(crate) fn draw(&self, frame: &mut Frame, recipient: &str, palette: ThemePalette) {
        let area = modal_area(frame.area(), 78, 26);
        frame.render_widget(Clear, area);
        let title = if matches!(self.mode, Mode::Review(_)) {
            " Send attachment "
        } else {
            " Attach a file "
        };
        let block = Block::default()
            .borders(Borders::ALL)
            .title(title)
            .border_style(Style::default().fg(palette.focus))
            .style(Style::default().bg(palette.panel))
            .padding(Padding::horizontal(1));
        let inner = block.inner(area);
        frame.render_widget(block, area);
        let rows = Layout::vertical([
            Constraint::Length(2),
            Constraint::Min(2),
            Constraint::Length(2),
            Constraint::Length(2),
        ])
        .split(inner);
        let (handle, scope) = recipient
            .rsplit_once(" · ")
            .unwrap_or((recipient, "main chat"));
        frame.render_widget(
            Paragraph::new(vec![
                Line::styled(
                    truncate_cells(&format!("To {handle}"), rows[0].width as usize),
                    Style::default().fg(palette.accent),
                ),
                Line::styled(
                    format!("{scope} · message draft kept"),
                    Style::default().fg(palette.muted),
                ),
            ]),
            rows[0],
        );
        let footer = match &self.mode {
            Mode::Review(file) => {
                let mut lines = wrap_cells(&file.filename, rows[1].width as usize)
                    .into_iter()
                    .map(|s| Line::styled(s, Style::default().fg(palette.text).bold()))
                    .collect::<Vec<_>>();
                lines.push(Line::styled(
                    format_bytes(file.bytes),
                    Style::default().fg(palette.secondary),
                ));
                lines.push(Line::default());
                lines.extend(
                    wrap_cells(&file.path.to_string_lossy(), rows[1].width as usize)
                        .into_iter()
                        .map(|s| Line::styled(s, Style::default().fg(palette.muted))),
                );
                lines.push(Line::default());
                lines.push(Line::styled(
                    "Encrypted before upload · 32 MiB maximum",
                    Style::default().fg(palette.secondary),
                ));
                lines.push(Line::styled(
                    "Your message draft is kept; this file sends separately.",
                    Style::default().fg(palette.muted),
                ));
                let lines = lines
                    .into_iter()
                    .flat_map(|line| {
                        let style = line.style;
                        wrap_cells(&line.to_string(), rows[1].width as usize)
                            .into_iter()
                            .map(move |line| Line::styled(line, style))
                    })
                    .collect::<Vec<_>>();
                let max_scroll = lines
                    .len()
                    .saturating_sub(rows[1].height as usize)
                    .min(u16::MAX as usize) as u16;
                frame.render_widget(
                    Paragraph::new(lines).scroll((self.review_scroll.min(max_scroll), 0)),
                    rows[1],
                );
                vec![
                    Line::from(
                        ["Send file", "Choose another", "Cancel"]
                            .iter()
                            .enumerate()
                            .map(|(i, label)| {
                                Span::styled(
                                    format!(" {label} "),
                                    Style::default()
                                        .fg(if i == self.review_action {
                                            palette.focus
                                        } else {
                                            palette.muted
                                        })
                                        .bg(if i == self.review_action {
                                            palette.selected
                                        } else {
                                            palette.panel
                                        }),
                                )
                            })
                            .collect::<Vec<_>>(),
                    ),
                    Line::styled(
                        "P preview · Tab choose · Enter confirm · Esc back",
                        Style::default().fg(palette.muted),
                    ),
                ]
            }
            Mode::Browse | Mode::Location(_) => {
                let parts = Layout::vertical([
                    Constraint::Length(1),
                    Constraint::Length(2),
                    Constraint::Min(1),
                ])
                .split(rows[1]);
                let location = match &self.mode {
                    Mode::Location(value) => format!("Location: {value}▏"),
                    _ => self.directory.to_string_lossy().into_owned(),
                };
                frame.render_widget(
                    Paragraph::new(tail_cells(&location, parts[0].width as usize)).style(
                        Style::default().fg(if matches!(self.mode, Mode::Location(_)) {
                            palette.focus
                        } else {
                            palette.secondary
                        }),
                    ),
                    parts[0],
                );
                frame.render_widget(
                    Paragraph::new(truncate_cells(
                        &format!(
                            "Filter: {}{}",
                            self.filter,
                            if self.filter.is_empty() {
                                "type a filename…"
                            } else {
                                ""
                            }
                        ),
                        parts[1].width as usize,
                    ))
                    .style(Style::default().fg(palette.muted)),
                    parts[1],
                );
                let visible = self.visible();
                if visible.is_empty() {
                    frame.render_widget(
                        Paragraph::new(if self.filter.is_empty() {
                            "This folder is empty"
                        } else {
                            "No matching files · Ctrl+U clears filter"
                        })
                        .style(Style::default().fg(palette.muted)),
                        parts[2],
                    );
                } else {
                    let items = visible
                        .iter()
                        .map(|entry| {
                            ListItem::new(Line::from(vec![
                                Span::styled(
                                    if entry.directory {
                                        "DIR  "
                                    } else if entry.link {
                                        "LINK "
                                    } else {
                                        "FILE "
                                    },
                                    Style::default().fg(palette.accent),
                                ),
                                Span::styled(
                                    truncate_cells(
                                        &entry.label,
                                        parts[2].width.saturating_sub(7) as usize,
                                    ),
                                    Style::default().fg(palette.text),
                                ),
                            ]))
                        })
                        .collect::<Vec<_>>();
                    let list = List::new(items)
                        .highlight_symbol("› ")
                        .highlight_style(Style::default().bg(palette.selected));
                    frame.render_stateful_widget(
                        list,
                        parts[2],
                        &mut ListState::default().with_selected(Some(self.selected)),
                    );
                }
                if matches!(self.mode, Mode::Location(_)) {
                    vec![
                        Line::raw("Enter open path · Ctrl+U clear · Esc back"),
                        Line::raw("Paths are literal; no shell commands are evaluated."),
                    ]
                } else {
                    vec![
                        Line::raw("↑↓ move · Enter choose · ← up · Esc cancel"),
                        Line::raw("Ctrl+L path · F5 hidden · type to filter"),
                    ]
                }
            }
        };
        if let Some(error) = &self.error {
            frame.render_widget(
                Paragraph::new(error.as_str())
                    .style(Style::default().fg(palette.danger))
                    .wrap(Wrap { trim: false }),
                rows[2],
            );
        } else if self.truncated {
            frame.render_widget(
                Paragraph::new(
                    "Large folder: first 10,000 entries shown. Use Ctrl+L for an exact path.",
                )
                .style(Style::default().fg(palette.warning))
                .wrap(Wrap { trim: false }),
                rows[2],
            );
        } else if matches!(self.mode, Mode::Review(_)) {
            frame.render_widget(
                Paragraph::new("↑↓ scroll details · encrypted before upload")
                    .style(Style::default().fg(palette.muted)),
                rows[2],
            );
        }
        frame.render_widget(
            Paragraph::new(footer).style(Style::default().fg(palette.muted)),
            rows[3],
        );
    }
}

fn tail_cells(text: &str, width: usize) -> String {
    let clean = text.chars().filter(|c| !c.is_control()).collect::<String>();
    if clean.width() <= width {
        return clean;
    }
    if width == 0 {
        return String::new();
    }
    let mut used = 1;
    let mut suffix = Vec::new();
    for grapheme in clean.graphemes(true).rev() {
        if used + grapheme.width() > width {
            break;
        }
        used += grapheme.width();
        suffix.push(grapheme);
    }
    format!("…{}", suffix.into_iter().rev().collect::<String>())
}

pub(crate) fn modal_area(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width.saturating_sub(2));
    let height = height.min(area.height.saturating_sub(2));
    Rect::new(
        area.x + (area.width - width) / 2,
        area.y + (area.height - height) / 2,
        width,
        height,
    )
}

pub(crate) fn format_bytes(bytes: u64) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.1} MiB", bytes as f64 / 1048576.0)
    } else if bytes >= 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} bytes")
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use uuid::Uuid;

    pub(crate) struct Fixture(pub(crate) PathBuf);
    impl Fixture {
        pub(crate) fn new() -> Self {
            let root = std::env::temp_dir().join(format!("mutte-picker-test-{}", Uuid::new_v4()));
            fs::create_dir(&root).unwrap();
            fs::create_dir(root.join("Documents")).unwrap();
            fs::write(root.join("photo 夏.jpg"), b"synthetic picker fixture").unwrap();
            fs::write(root.join("notes $(literal).txt"), b"not a shell command").unwrap();
            fs::write(root.join(".hidden.txt"), b"hidden fixture").unwrap();
            Self(fs::canonicalize(root).unwrap())
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
    fn key(picker: &mut AttachmentPicker, code: KeyCode) -> PickerAction {
        picker.on_key(KeyEvent::new(code, KeyModifiers::NONE))
    }
    fn type_text(picker: &mut AttachmentPicker, text: &str) {
        for c in text.chars() {
            key(picker, KeyCode::Char(c));
        }
    }

    #[test]
    fn long_location_keeps_end_and_cursor_visible_in_terminal_cells() {
        let text = format!("{}设计/e\u{301}.txt▏", "/long/path".repeat(8));
        for width in [0, 1, 14, 24, 46] {
            let tail = tail_cells(&text, width);
            assert!(tail.width() <= width);
            if width > 1 {
                assert!(tail.ends_with('▏'));
            }
        }
    }

    #[test]
    fn folders_first_hidden_toggle_and_filter_preserve_real_paths() {
        let fixture = Fixture::new();
        let mut picker = AttachmentPicker::new(fixture.0.clone());
        assert_eq!(picker.visible()[0].label, "Documents");
        assert_eq!(picker.visible().len(), 3);
        key(&mut picker, KeyCode::F(5));
        assert_eq!(picker.visible().len(), 4);
        type_text(&mut picker, "夏");
        assert_eq!(picker.visible().len(), 1);
        assert_eq!(picker.visible()[0].path, fixture.0.join("photo 夏.jpg"));
    }

    #[test]
    fn choosing_a_file_requires_separate_send_confirmation_and_cancel_is_safe() {
        let fixture = Fixture::new();
        let mut picker = AttachmentPicker::new(fixture.0.clone());
        type_text(&mut picker, "photo");
        assert!(matches!(
            key(&mut picker, KeyCode::Enter),
            PickerAction::None
        ));
        assert!(matches!(picker.mode, Mode::Review(_)));
        assert!(
            matches!(key(&mut picker, KeyCode::Enter), PickerAction::Send(file) if file.path == fixture.0.join("photo 夏.jpg"))
        );
        key(&mut picker, KeyCode::Tab);
        key(&mut picker, KeyCode::Tab);
        assert!(matches!(
            key(&mut picker, KeyCode::Enter),
            PickerAction::Cancel
        ));
        assert_eq!(
            fs::read(fixture.0.join("photo 夏.jpg")).unwrap(),
            b"synthetic picker fixture"
        );
    }

    #[test]
    fn folder_navigation_and_literal_path_entry_do_not_execute_shell_text() {
        let fixture = Fixture::new();
        let mut picker = AttachmentPicker::new(fixture.0.clone());
        key(&mut picker, KeyCode::Enter);
        assert!(picker.directory.ends_with("Documents"));
        key(&mut picker, KeyCode::Left);
        picker.on_key(KeyEvent::new(KeyCode::Char('l'), KeyModifiers::CONTROL));
        picker.on_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
        type_text(&mut picker, "notes $(literal).txt");
        key(&mut picker, KeyCode::Enter);
        assert!(
            matches!(&picker.mode, Mode::Review(file) if file.filename == "notes $(literal).txt")
        );
        assert!(fixture.0.join("notes $(literal).txt").is_file());
    }

    #[test]
    fn disappeared_changed_and_oversized_files_never_reach_send() {
        let fixture = Fixture::new();
        assert!(ChosenFile::inspect(&fixture.0).is_err());
        let file = ChosenFile::inspect(&fixture.0.join("photo 夏.jpg")).unwrap();
        fs::write(&file.path, b"changed").unwrap();
        assert!(file.validate_unchanged().is_err());
        fs::remove_file(&file.path).unwrap();
        assert!(file.validate_unchanged().is_err());
        let large = fixture.0.join("large.bin");
        fs::File::create(&large)
            .unwrap()
            .set_len(MAX_ATTACHMENT_BYTES + 1)
            .unwrap();
        assert!(
            ChosenFile::inspect(&large)
                .unwrap_err()
                .to_string()
                .contains("32 MiB")
        );
    }

    #[test]
    fn invalid_paths_and_empty_results_explain_errors_without_losing_location() {
        let fixture = Fixture::new();
        let mut picker = AttachmentPicker::new(fixture.0.clone());
        assert!(picker.load(fixture.0.join("missing")).is_err());
        assert_eq!(picker.directory, fixture.0);
        type_text(&mut picker, "nothing matches");
        assert!(picker.visible().is_empty());
        assert!(matches!(
            key(&mut picker, KeyCode::Enter),
            PickerAction::None
        ));
        assert!(matches!(
            key(&mut picker, KeyCode::Esc),
            PickerAction::Cancel
        ));
    }

    #[test]
    fn picker_and_confirmation_render_at_small_and_large_terminal_sizes() {
        use ratatui::{Terminal, backend::TestBackend};
        let fixture = Fixture::new();
        for (width, height) in [(52, 16), (80, 24), (140, 40)] {
            let mut picker = AttachmentPicker::new(fixture.0.clone());
            for review in [false, true] {
                if review {
                    type_text(&mut picker, "photo");
                    key(&mut picker, KeyCode::Enter);
                }
                let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
                terminal
                    .draw(|frame| {
                        picker.draw(frame, "@mira · current thread", ThemePalette::default())
                    })
                    .unwrap();
                let screen = terminal
                    .backend()
                    .buffer()
                    .content()
                    .iter()
                    .map(|cell| cell.symbol())
                    .collect::<String>();
                assert!(screen.contains("@mira"));
                assert!(screen.contains("current thread"));
                assert!(screen.contains(if review { "Send file" } else { "Attach a file" }));
                assert!(screen.contains(if review { "Cancel" } else { "Esc cancel" }));
            }
        }
    }
}
