//! Cell-based transcript layout, independent of focus and terminal I/O.
//!
//! Stack individual, content-sized rectangular blocks into sender groups. Every message
//! owns its shape, timestamp, selection range, replies, and scroll anchor.
use std::{collections::HashMap, ops::Range};

use mutte_client::polls::{PollState, is_poll_event};
use mutte_client::{
    ConversationSnapshot, MessageReaction, MessageSnapshot, is_reaction_for_known_message,
    reactions_for,
};
use mutte_store::DeliveryState;
use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Paragraph},
};
use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthStr;
use uuid::Uuid;

use crate::theme::ThemePalette;

pub(crate) const LANE_MAX_WIDTH: u16 = 72;
const BLOCK_MAX_WIDTH: usize = 54;
const BLOCK_MIN_WIDTH: usize = 14;
const INSET: u16 = 2;

#[derive(Clone, Copy, Debug)]
enum BubbleEdge {
    Top,
    Bottom,
}

#[derive(Debug)]
struct Row {
    line: Line<'static>,
    x: u16,
    width: u16,
    inset: u16,
    background: Color,
    owner: Option<Uuid>,
    message_start: bool,
    edge: Option<BubbleEdge>,
    outline: bool,
}

#[derive(Debug)]
struct MessageRows {
    id: Uuid,
    range: Range<usize>,
    group_start: usize,
    author: String,
}

#[derive(Debug)]
pub(crate) struct Transcript {
    rows: Vec<Row>,
    messages: Vec<MessageRows>,
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct LayoutOptions {
    pub(crate) references: bool,
    pub(crate) explicit_ownership: bool,
}

impl Transcript {
    pub(crate) fn new(
        chat: &ConversationSnapshot,
        width: u16,
        palette: ThemePalette,
        options: LayoutOptions,
    ) -> Self {
        let width = width.max(1);
        let mut transcript = Self {
            rows: Vec::new(),
            messages: Vec::new(),
        };
        let visible = chat
            .messages
            .iter()
            .filter(|message| !is_reaction_for_known_message(&chat.messages, message))
            .filter(|message| !is_poll_event(&chat.messages, message))
            .filter(|message| match chat.active_thread {
                Some(root) => message.id == root || message.thread_root == Some(root),
                None => message.thread_root.is_none(),
            })
            .collect::<Vec<_>>();
        let by_id = chat
            .messages
            .iter()
            .map(|message| (message.id, message))
            .collect::<HashMap<_, _>>();
        let mut threads = HashMap::<Uuid, (usize, usize)>::new();
        for message in &chat.messages {
            if is_reaction_for_known_message(&chat.messages, message)
                || is_poll_event(&chat.messages, message)
            {
                continue;
            }
            if let Some(root) = message.thread_root {
                let stats = threads.entry(root).or_default();
                stats.0 += 1;
                stats.1 += usize::from(!message.mine && !message.locally_read);
            }
        }
        let first_unread = visible
            .iter()
            .find(|message| !message.mine && !message.locally_read)
            .map(|message| message.id);
        let cap = if width < 60 {
            usize::from(width.saturating_sub(2).max(1))
        } else {
            (usize::from(width) * 3 / 4).min(BLOCK_MAX_WIDTH)
        };
        let mut index = 0;
        while index < visible.len() {
            let first = visible[index];
            if index > 0 {
                transcript.spacer(width, palette);
            }
            if index == 0
                || visible[index - 1].timestamp.date_naive() != first.timestamp.date_naive()
            {
                transcript.lane_row(
                    format!("{}", first.timestamp.format("%A · %B %-d")),
                    width,
                    palette.muted,
                    palette,
                );
                transcript.spacer(width, palette);
            }
            if first_unread == Some(first.id) {
                transcript.lane_row("── New messages ──".into(), width, palette.accent, palette);
            }
            let mut end = index + 1;
            while end < visible.len()
                && Some(visible[end].id) != first_unread
                && continues_sender_group(visible[end - 1], visible[end])
            {
                end += 1;
            }
            let group = &visible[index..end];
            let background = if first.mine {
                palette.keycap
            } else {
                palette.panel
            };
            let group_start = transcript.rows.len();
            for (group_index, message) in group.iter().enumerate() {
                let poll_body = PollState::fold(message, &chat.messages).map(|poll| poll.summary());
                let body_text = poll_body.as_deref().unwrap_or(&message.text);
                let author = if message.mine { "You" } else { &message.author };
                let show_author = group_index == 0 && (!message.mine || options.explicit_ownership);
                let caption = message_caption(message, options.explicit_ownership, palette);
                let reply_label = message
                    .thread_root
                    .is_none()
                    .then(|| {
                        threads.get(&message.id).map(|(replies, unread)| {
                            let mut label = format!(
                                "{replies} repl{}",
                                if *replies == 1 { "y" } else { "ies" }
                            );
                            if *unread > 0 {
                                label.push_str(&format!(" · {unread} unread"));
                            }
                            label
                        })
                    })
                    .flatten();
                let body_width = cell_measure(body_text);
                let quote_width = message.reply_to.map_or(0, |id| {
                    by_id
                        .get(&id)
                        .map_or(cell_measure("Original unavailable") + 2, |original| {
                            cell_measure(&original.text)
                                .max(cell_measure(if original.mine {
                                    "You"
                                } else {
                                    &original.author
                                }))
                                .saturating_add(2)
                        })
                });
                let attachment_width = message.attachment.as_ref().map_or(0, |file| {
                    cell_measure(&format!(
                        "{} · {}",
                        file.metadata.filename,
                        format_bytes(file.metadata.plaintext_size)
                    ))
                });
                let reactions = reactions_for(&chat.messages, message.id);
                let reaction_width = reactions
                    .iter()
                    .map(|reaction| cell_measure(&format!("{} {}", reaction.emoji, reaction.count)))
                    .sum::<usize>()
                    .saturating_add(reactions.len().saturating_sub(1) * 2);
                let mut measured = body_width
                    .max(quote_width)
                    .max(attachment_width)
                    .max(reaction_width)
                    .max(caption.width())
                    .max(reply_label.as_deref().map_or(0, cell_measure))
                    .max(if show_author { cell_measure(author) } else { 0 });
                // Let a short message and its own time share a line. Long text
                // still wraps at a readable measure instead of widening the lane.
                let footer_width = reply_label.as_deref().map_or(body_width, cell_measure);
                if message.attachment.is_none()
                    && footer_width + 2 + caption.width()
                        <= cap.saturating_sub(usize::from(INSET) * 2)
                {
                    measured = measured.max(footer_width + 2 + caption.width());
                }
                let block_width = (measured + usize::from(INSET) * 2)
                    .max(BLOCK_MIN_WIDTH)
                    .min(cap) as u16;
                let inset = INSET.min(block_width.saturating_sub(1) / 2);
                let content_width = usize::from(block_width.saturating_sub(inset * 2).max(1));
                let x = if message.mine {
                    width.saturating_sub(block_width)
                } else {
                    0
                };
                let start = transcript.rows.len();
                transcript.bubble_edge(x, block_width, background, message.id, BubbleEdge::Top);
                if show_author {
                    for line in wrap_cells(author, content_width) {
                        transcript.block_row(
                            line,
                            x,
                            block_width,
                            inset,
                            palette.accent,
                            background,
                            Some(message.id),
                        );
                    }
                }
                if options.references {
                    transcript.block_row(
                        format!("#{}", &message.id.simple().to_string()[..8]),
                        x,
                        block_width,
                        inset,
                        palette.muted,
                        background,
                        Some(message.id),
                    );
                }
                if let Some(reply_to) = message.reply_to {
                    let (author, body) =
                        by_id
                            .get(&reply_to)
                            .map_or(("Original unavailable", None), |original| {
                                (
                                    if original.mine {
                                        "You"
                                    } else {
                                        original.author.as_str()
                                    },
                                    Some(original.text.as_str()),
                                )
                            });
                    let quote_width = content_width.saturating_sub(2).max(1);
                    for line in wrap_cells(author, quote_width) {
                        transcript.block_row(
                            format!("│ {line}"),
                            x,
                            block_width,
                            inset,
                            palette.accent,
                            background,
                            Some(message.id),
                        );
                    }
                    if let Some(body) = body {
                        let lines = wrap_cells(body, quote_width);
                        let truncated = lines.len() > 2;
                        for (number, line) in lines.iter().take(2).enumerate() {
                            let line = if truncated && number == 1 {
                                truncate_cells(&format!("{line}…"), quote_width)
                            } else {
                                line.clone()
                            };
                            transcript.block_row(
                                format!("│ {line}"),
                                x,
                                block_width,
                                inset,
                                palette.muted,
                                background,
                                Some(message.id),
                            );
                        }
                    }
                }
                let generated_file_label = message
                    .attachment
                    .as_ref()
                    .is_some_and(|file| message.text == format!("📎 {}", file.metadata.filename));
                if (!message.text.is_empty() && !generated_file_label)
                    || message.attachment.is_none()
                {
                    for line in wrap_cells(body_text, content_width) {
                        transcript.block_row(
                            line,
                            x,
                            block_width,
                            inset,
                            palette.text,
                            background,
                            Some(message.id),
                        );
                    }
                }
                if let Some(file) = &message.attachment {
                    let metadata = format!(
                        "{} · {}",
                        file.metadata.filename,
                        format_bytes(file.metadata.plaintext_size)
                    );
                    let location = if file.local_path.is_some() {
                        "Local file · select + A for details"
                    } else if file.download_requested {
                        "Download queued · select + A for details"
                    } else {
                        "Encrypted · not downloaded · select + A"
                    };
                    for line in wrap_cells(&format!("{metadata}\n{location}"), content_width) {
                        transcript.block_row(
                            line,
                            x,
                            block_width,
                            inset,
                            palette.secondary,
                            background,
                            Some(message.id),
                        );
                    }
                }
                for line in reaction_lines(&reactions, content_width, palette) {
                    transcript.block_line(
                        line,
                        x,
                        block_width,
                        inset,
                        background,
                        Some(message.id),
                    );
                }
                if let Some(label) = reply_label {
                    for line in wrap_cells(&label, content_width) {
                        transcript.block_row(
                            line,
                            x,
                            block_width,
                            inset,
                            palette.accent,
                            background,
                            Some(message.id),
                        );
                    }
                }
                let last_row = transcript.rows.last_mut().expect("bubble has content");
                if last_row.line.width() + 2 + caption.width() <= content_width {
                    last_row.line.spans.push(Span::raw(
                        " ".repeat(content_width - last_row.line.width() - caption.width()),
                    ));
                    last_row.line.spans.extend(caption.spans);
                } else if caption.width() <= content_width {
                    transcript.block_row(
                        String::new(),
                        x,
                        block_width,
                        inset,
                        palette.muted,
                        background,
                        Some(message.id),
                    );
                    transcript.rows.last_mut().unwrap().line = caption.right_aligned();
                } else {
                    // Narrow terminals and explicit no-color status labels may
                    // need more than one line. Never hide queued/cancelled state.
                    let color = if message.delivery == DeliveryState::Cancelled {
                        palette.danger
                    } else {
                        palette.muted
                    };
                    for line in wrap_cells(&caption.to_string(), content_width) {
                        transcript.block_row(
                            line,
                            x,
                            block_width,
                            inset,
                            color,
                            background,
                            Some(message.id),
                        );
                    }
                }
                transcript.bubble_edge(x, block_width, background, message.id, BubbleEdge::Bottom);
                transcript.rows[start + 1].message_start = true;
                for row in &mut transcript.rows[start..] {
                    row.outline = options.explicit_ownership;
                }
                transcript.messages.push(MessageRows {
                    id: message.id,
                    range: start..transcript.rows.len(),
                    group_start,
                    author: if message.mine {
                        "You".into()
                    } else {
                        message.author.clone()
                    },
                });
            }
            index = end;
        }
        if visible.is_empty() {
            transcript.lane_row("No messages yet".into(), width, palette.text, palette);
            for line in wrap_cells(
                "Start with something small. It will be encrypted before it leaves.",
                usize::from(width),
            ) {
                transcript.lane_row(line, width, palette.muted, palette);
            }
        }
        transcript
    }

    fn spacer(&mut self, width: u16, palette: ThemePalette) {
        self.lane_row(String::new(), width, palette.muted, palette);
    }

    fn lane_row(&mut self, text: String, width: u16, color: Color, palette: ThemePalette) {
        self.rows.push(Row {
            line: Line::styled(text, Style::default().fg(color)).centered(),
            x: 0,
            width,
            inset: 0,
            background: palette.bg,
            owner: None,
            message_start: false,
            edge: None,
            outline: false,
        });
    }

    #[allow(clippy::too_many_arguments)]
    fn block_row(
        &mut self,
        text: String,
        x: u16,
        width: u16,
        inset: u16,
        color: Color,
        background: Color,
        owner: Option<Uuid>,
    ) {
        self.block_line(
            Line::styled(text, Style::default().fg(color)),
            x,
            width,
            inset,
            background,
            owner,
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn block_line(
        &mut self,
        line: Line<'static>,
        x: u16,
        width: u16,
        inset: u16,
        background: Color,
        owner: Option<Uuid>,
    ) {
        self.rows.push(Row {
            line,
            x,
            width,
            inset,
            background,
            owner,
            message_start: false,
            edge: None,
            outline: false,
        });
    }

    fn bubble_edge(
        &mut self,
        x: u16,
        width: u16,
        background: Color,
        owner: Uuid,
        edge: BubbleEdge,
    ) {
        self.block_row(
            String::new(),
            x,
            width,
            0,
            background,
            background,
            Some(owner),
        );
        self.rows.last_mut().unwrap().edge = Some(edge);
    }

    pub(crate) fn height(&self) -> usize {
        self.rows.len()
    }

    pub(crate) fn render(
        &self,
        frame: &mut Frame,
        area: Rect,
        top: usize,
        selected: Option<Uuid>,
        palette: ThemePalette,
    ) {
        for (index, row) in self
            .rows
            .iter()
            .skip(top)
            .take(usize::from(area.height))
            .enumerate()
        {
            let rect = Rect::new(
                area.x + row.x,
                area.y + index as u16,
                row.width.min(area.width.saturating_sub(row.x)),
                1,
            );
            let is_selected = row.owner.is_some() && row.owner == selected;
            let bg = if is_selected {
                palette.selected
            } else {
                row.background
            };
            if let Some(edge) = row.edge {
                let (left, middle, right) = match (edge, row.outline) {
                    (BubbleEdge::Top, false) => ("▄", "▄", "▄"),
                    (BubbleEdge::Bottom, false) => ("▀", "▀", "▀"),
                    (BubbleEdge::Top, true) => ("┌", "─", "┐"),
                    (BubbleEdge::Bottom, true) => ("└", "─", "┘"),
                };
                let shape = if rect.width < 2 {
                    middle.into()
                } else {
                    format!(
                        "{left}{}{right}",
                        middle.repeat(usize::from(rect.width - 2))
                    )
                };
                frame.render_widget(
                    Paragraph::new(shape).style(
                        Style::default()
                            .fg(if row.outline { palette.muted } else { bg })
                            .bg(palette.bg),
                    ),
                    rect,
                );
                continue;
            }
            frame.render_widget(Block::new().style(Style::default().bg(bg)), rect);
            let inner = Rect::new(
                rect.x + row.inset,
                rect.y,
                rect.width.saturating_sub(row.inset * 2),
                1,
            );
            frame.render_widget(
                Paragraph::new(row.line.clone()).style(Style::default().bg(bg)),
                inner,
            );
            if row.outline {
                for x in [rect.x, rect.right().saturating_sub(1)] {
                    frame.render_widget(
                        Paragraph::new("│").style(Style::default().fg(palette.muted).bg(bg)),
                        Rect::new(x, rect.y, 1, 1),
                    );
                }
            }
            if is_selected && (row.message_start || index == 0) {
                frame.render_widget(
                    Paragraph::new("▶").style(Style::default().fg(palette.focus).bg(bg)),
                    Rect::new(rect.x, rect.y, 1, 1),
                );
            }
        }
    }

    fn range(&self, id: Uuid) -> Option<&Range<usize>> {
        self.messages
            .iter()
            .find(|message| message.id == id)
            .map(|message| &message.range)
    }

    pub(crate) fn continued_author(&self, top: usize) -> Option<&str> {
        let owner = self.rows.get(top)?.owner?;
        self.messages
            .iter()
            .find(|message| message.id == owner && message.group_start < top)
            .map(|message| message.author.as_str())
    }
}

#[derive(Default, Debug)]
pub(crate) struct TranscriptViewport {
    anchor: Option<(Uuid, isize)>,
    top: usize,
    max_top: usize,
    manual_back: u16,
    initialized: bool,
}

impl TranscriptViewport {
    /// Clamp wheel movement to rendered history so overscrolling cannot build
    /// up an invisible offset that must be unwound before the view moves again.
    pub(crate) fn scroll_offset(&self, current: u16, older: bool, rows: u16) -> u16 {
        if older {
            current.saturating_add(usize::from(rows).min(self.top) as u16)
        } else if usize::from(rows) >= self.max_top.saturating_sub(self.top) {
            0
        } else {
            current.saturating_sub(rows)
        }
    }

    pub(crate) fn position(
        &mut self,
        transcript: &Transcript,
        height: u16,
        selected: Option<Uuid>,
        scroll_back: u16,
    ) -> usize {
        let height = usize::from(height).max(1);
        let max_top = transcript.rows.len().saturating_sub(height);
        let anchored = self
            .anchor
            .and_then(|(id, offset)| {
                transcript
                    .range(id)
                    .map(|range| range.start.saturating_add_signed(offset))
            })
            .unwrap_or(self.top);
        let mut top = if !self.initialized {
            max_top.saturating_sub(usize::from(scroll_back))
        } else {
            anchored.min(max_top)
        };
        if let Some(range) = selected.and_then(|id| transcript.range(id)) {
            // Keep a selected message in place while it fits; only scroll as far
            // as needed. Tall messages start at their first line, never their tail.
            if range.start < top || range.len() >= height {
                top = range.start;
            } else if range.end > top + height {
                top = range.end.saturating_sub(height);
            }
        } else if scroll_back == 0 {
            top = max_top;
        } else if self.initialized && scroll_back != self.manual_back {
            top = top.saturating_add_signed(self.manual_back as isize - scroll_back as isize);
        }
        top = top.min(max_top);
        self.anchor = transcript
            .messages
            .iter()
            .find(|message| message.range.end > top)
            .map(|message| (message.id, top as isize - message.range.start as isize));
        self.top = top;
        self.max_top = max_top;
        self.manual_back = scroll_back;
        self.initialized = true;
        top
    }
}

pub(crate) fn continues_sender_group(
    previous: &MessageSnapshot,
    message: &MessageSnapshot,
) -> bool {
    let gap = message.timestamp.signed_duration_since(previous.timestamp);
    previous.mine == message.mine
        && previous.author == message.author
        && previous.timestamp.date_naive() == message.timestamp.date_naive()
        && previous.thread_root == message.thread_root
        && gap >= chrono::Duration::zero()
        && gap <= chrono::Duration::minutes(5)
}

pub(crate) fn delivery_label(state: DeliveryState) -> &'static str {
    match state {
        DeliveryState::Pending => "queued",
        DeliveryState::Sent => "sent",
        DeliveryState::Delivered => "delivered",
        DeliveryState::Read => "read",
        DeliveryState::Received => "received",
        DeliveryState::Cancelled => "cancelled after key change",
    }
}

fn message_caption(
    message: &MessageSnapshot,
    explicit: bool,
    palette: ThemePalette,
) -> Line<'static> {
    let mut spans = vec![Span::styled(
        message.timestamp.format("%H:%M").to_string(),
        Style::default().fg(palette.muted),
    )];
    if message.mine {
        let state = if explicit {
            format!(" · {}", delivery_label(message.delivery))
        } else {
            match message.delivery {
                DeliveryState::Delivered => " ✓".into(),
                DeliveryState::Read => " ✓✓".into(),
                state => format!(" · {}", delivery_label(state)),
            }
        };
        let color = match message.delivery {
            DeliveryState::Read => palette.accent,
            DeliveryState::Pending => palette.warning,
            DeliveryState::Cancelled => palette.danger,
            _ => palette.muted,
        };
        spans.push(Span::styled(state, Style::default().fg(color)));
    }
    Line::from(spans)
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}

fn printable(text: &str) -> String {
    text.replace("\r\n", "\n")
        .chars()
        .flat_map(|c| match c {
            '\t' => "    ".chars().collect::<Vec<_>>(),
            '\n' => vec![c],
            c if c.is_control() => vec!['�'],
            c => vec![c],
        })
        .collect()
}

fn cell_measure(text: &str) -> usize {
    printable(text)
        .split('\n')
        .map(UnicodeWidthStr::width)
        .max()
        .unwrap_or(0)
}

/// Word-wrap in terminal cells, falling back to grapheme boundaries for long
/// words. Preserve paragraph breaks, indentation, combining marks and emoji.
pub(crate) fn wrap_cells(text: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let text = printable(text);
    let mut lines = Vec::new();
    for paragraph in text.split('\n') {
        let graphemes = paragraph.graphemes(true).collect::<Vec<_>>();
        if graphemes.is_empty() {
            lines.push(String::new());
            continue;
        }
        let mut start = 0;
        while start < graphemes.len() {
            let mut end = start;
            let mut cells = 0;
            let mut last_space = None;
            let mut saw_word = false;
            while end < graphemes.len() {
                let next_width = graphemes[end].width();
                if cells + next_width > width {
                    break;
                }
                cells += next_width;
                let whitespace = graphemes[end].chars().all(char::is_whitespace);
                if whitespace && saw_word {
                    last_space = Some(end + 1);
                }
                saw_word |= !whitespace;
                end += 1;
            }
            if end == start {
                // Only relevant below two columns: do not split a wide grapheme
                // or let it overwrite another block.
                lines.push("�".into());
                start += 1;
                continue;
            }
            if end < graphemes.len()
                && let Some(space) = last_space
                && space > start
            {
                end = space;
            }
            lines.push(graphemes[start..end].concat());
            start = end;
        }
    }
    lines
}

fn reaction_lines(
    reactions: &[MessageReaction],
    width: usize,
    palette: ThemePalette,
) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    let mut spans = Vec::new();
    let mut used = 0;
    for reaction in reactions {
        let label = format!("{} {}", reaction.emoji, reaction.count);
        let label_width = cell_measure(&label);
        let separator = usize::from(!spans.is_empty()) * 2;
        if !spans.is_empty() && used + separator + label_width > width {
            lines.push(Line::from(std::mem::take(&mut spans)));
            used = 0;
        }
        if !spans.is_empty() {
            spans.push(Span::raw("  "));
            used += 2;
        }
        spans.push(Span::styled(
            truncate_cells(&label, width.max(1)),
            Style::default().fg(if reaction.mine {
                palette.accent
            } else {
                palette.secondary
            }),
        ));
        used += label_width.min(width);
    }
    if !spans.is_empty() {
        lines.push(Line::from(spans));
    }
    lines
}

pub(crate) fn truncate_cells(text: &str, width: usize) -> String {
    let text = printable(text).replace('\n', " ");
    if text.width() <= width {
        return text;
    }
    if width == 0 {
        return String::new();
    }
    let mut value = String::new();
    let mut used = 0;
    for grapheme in text.graphemes(true) {
        if used + grapheme.width() > width - 1 {
            break;
        }
        value.push_str(grapheme);
        used += grapheme.width();
    }
    value.push('…');
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Local, TimeZone};
    use mutte_client::VerificationState;
    use ratatui::{Terminal, backend::TestBackend};

    fn message(id: u128, mine: bool, text: &str, minute: u32) -> MessageSnapshot {
        MessageSnapshot {
            id: Uuid::from_u128(id),
            author: if mine { "You" } else { "@mira" }.into(),
            text: text.into(),
            mine,
            timestamp: Local.with_ymd_and_hms(2026, 9, 2, 21, minute, 0).unwrap(),
            delivery: if mine {
                DeliveryState::Read
            } else {
                DeliveryState::Received
            },
            attachment: None,
            reply_to: None,
            thread_root: None,
            locally_read: true,
        }
    }

    fn chat(messages: Vec<MessageSnapshot>) -> ConversationSnapshot {
        ConversationSnapshot {
            conversation_id: Some(Uuid::from_u128(100)),
            name: "Mira".into(),
            handle: "mira".into(),
            status: "quiet".into(),
            unread: 0,
            messages,
            verification: VerificationState::Verified,
            active_thread: None,
            scroll_back: 0,
        }
    }

    fn layout(chat: &ConversationSnapshot, width: u16) -> Transcript {
        Transcript::new(
            chat,
            width,
            ThemePalette::default(),
            LayoutOptions::default(),
        )
    }

    fn text(transcript: &Transcript) -> String {
        transcript
            .rows
            .iter()
            .map(|row| row.line.to_string())
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn sender_groups_stop_at_five_minutes_and_do_not_join_reversed_times() {
        let first = message(1, true, "first", 1);
        let mut second = message(2, true, "second", 6);
        assert!(continues_sender_group(&first, &second));
        second.timestamp += chrono::Duration::seconds(1);
        assert!(!continues_sender_group(&first, &second));
        second.timestamp = first.timestamp - chrono::Duration::seconds(1);
        assert!(!continues_sender_group(&first, &second));
    }

    #[test]
    fn bubbles_size_individually_but_share_the_senders_outer_edge() {
        let chat = chat(vec![
            message(1, false, "incoming", 0),
            message(
                2,
                true,
                "A longer outgoing message with two lines of readable text",
                1,
            ),
            message(3, true, "okay", 2),
        ]);
        for width in [40, 46, 60, 74, 88] {
            let transcript = layout(&chat, width);
            let long = transcript.range(Uuid::from_u128(2)).unwrap();
            let short = transcript.range(Uuid::from_u128(3)).unwrap();
            assert!(transcript.rows[short.start].width < transcript.rows[long.start].width);
            for range in [long, short] {
                let rows = &transcript.rows[range.clone()];
                assert!(
                    rows.iter()
                        .all(|row| row.x > 0 && row.x + row.width == width)
                );
                assert!(matches!(rows[0].edge, Some(BubbleEdge::Top)));
                assert!(matches!(
                    rows.last().unwrap().edge,
                    Some(BubbleEdge::Bottom)
                ));
                assert!(
                    rows.iter()
                        .filter(|row| row.edge.is_none())
                        .all(|row| row.inset == INSET)
                );
            }
            assert_eq!(
                long.end, short.start,
                "same-sender bubbles stack without a divider row"
            );
            for row in &transcript.rows {
                assert!(row.x + row.width <= width);
                assert!(
                    row.line.width() <= usize::from(row.width.saturating_sub(row.inset * 2)),
                    "{width}: {:?}",
                    row.line
                );
            }
        }
    }

    #[test]
    fn wrapping_preserves_unicode_clusters_whitespace_and_long_words() {
        for source in [
            "你好，世界 👩🏽‍💻 café e\u{301} 🏳️‍🌈",
            "https://example.com/averylongunbrokenpathwithoutspaces",
            "    indentation and  repeated spaces",
            "one\n\nthree\n",
        ] {
            for width in [2, 5, 12, 38, 60] {
                let lines = wrap_cells(source, width);
                assert!(
                    lines.iter().all(|line| line.width() <= width),
                    "{width}: {lines:?}"
                );
                assert_eq!(lines.concat(), source.replace('\n', ""));
                assert!(
                    lines
                        .iter()
                        .all(|line| !line.starts_with('\u{301}') && !line.starts_with('\u{200d}'))
                );
            }
        }
        assert!(wrap_cells("    verylongwordwithoutbreaks", 12)[0].starts_with("    very"));
        assert_eq!(wrap_cells("a\n\nb\n", 8), vec!["a", "", "b", ""]);
        assert_eq!(wrap_cells("\tcode", 12), vec!["    code"]);
    }

    #[test]
    fn truncation_is_cell_bounded_and_terminal_controls_are_not_forwarded() {
        for width in 0..20 {
            let value = truncate_cells("👩🏽‍💻 你好 e\u{301} long caption", width);
            assert!(value.width() <= width);
            assert!(!value.ends_with('\u{200d}'));
        }
        let lines = wrap_cells("safe\u{1b}[2J\rtext\0", 40);
        assert!(!lines.concat().chars().any(char::is_control));
    }

    #[test]
    fn unread_boundary_is_single_and_hidden_threads_do_not_move_it() {
        let first = message(1, false, "read", 0);
        let mut second = message(2, false, "new first", 1);
        second.locally_read = false;
        let mut third = message(3, false, "new second", 2);
        third.locally_read = false;
        let mut hidden = message(4, false, "thread only", 1);
        hidden.thread_root = Some(first.id);
        hidden.locally_read = false;
        let chat = chat(vec![first, hidden, second, third]);
        let rendered = text(&layout(&chat, 88));
        assert_eq!(rendered.matches("New messages").count(), 1);
        assert_eq!(rendered.matches("@mira").count(), 2);
        assert!(rendered.contains("1 reply · 1 unread"));
        assert!(!rendered.contains("thread only"));
        assert!(!chat.messages[2].locally_read);
    }

    #[test]
    fn each_bubble_owns_its_time_and_receipt_including_queued_and_cancelled() {
        let mut pending = message(1, true, "Waiting offline", 0);
        pending.delivery = DeliveryState::Pending;
        let mut cancelled = message(2, true, "Key changed", 1);
        cancelled.delivery = DeliveryState::Cancelled;
        let chat = chat(vec![pending, cancelled, message(3, true, "Latest read", 2)]);
        let transcript = layout(&chat, 60);
        let rendered = text(&transcript);
        assert!(rendered.contains("queued"));
        assert!(rendered.contains("cancelled after key"));
        assert_eq!(rendered.matches("21:02 ✓✓").count(), 1);
        for (id, time) in [(1, "21:00"), (2, "21:01"), (3, "21:02")] {
            let range = transcript.range(Uuid::from_u128(id)).unwrap();
            let owned = transcript.rows[range.clone()]
                .iter()
                .map(|row| row.line.to_string())
                .collect::<String>();
            assert!(owned.contains(time));
            assert!(
                transcript.rows[range.clone()]
                    .iter()
                    .all(|row| row.owner == Some(Uuid::from_u128(id)))
            );
        }
        for id in [1, 2] {
            let range = transcript.range(Uuid::from_u128(id)).unwrap();
            assert!(transcript.rows[range.clone()].iter().any(|row| {
                row.line
                    .to_string()
                    .contains(if id == 1 { "queued" } else { "cancelled" })
            }));
        }
    }

    #[test]
    fn reply_preview_is_contained_limited_and_honest_when_original_is_missing() {
        let first = message(1, false, &"Original text ".repeat(30), 0);
        let mut reply = message(2, true, "Reply body", 1);
        reply.reply_to = Some(first.id);
        let mut missing = message(3, true, "Missing original reply", 2);
        missing.reply_to = Some(Uuid::from_u128(999));
        let transcript = layout(&chat(vec![first, reply, missing]), 88);
        let rows = &transcript.rows[transcript.range(Uuid::from_u128(2)).unwrap().clone()];
        assert_eq!(
            rows.iter()
                .filter(|row| row.line.to_string().starts_with("│ "))
                .count(),
            3
        );
        assert!(rows.iter().any(|row| row.line.to_string().ends_with('…')));
        assert!(
            rows.iter()
                .all(|row| row.x == rows[0].x && row.width == rows[0].width)
        );
        assert!(text(&transcript).contains("Original unavailable"));
        assert!(!text(&transcript).contains("select + T"));
    }

    #[test]
    fn selection_only_changes_target_cells_not_transcript_geometry() {
        let chat = chat(vec![
            message(1, false, "one", 0),
            message(2, false, "two", 1),
            message(3, false, "three", 2),
        ]);
        let palette = ThemePalette::default();
        let transcript = layout(&chat, 80);
        let draw = |selected| {
            let mut terminal = Terminal::new(TestBackend::new(80, 30)).unwrap();
            terminal
                .draw(|frame| transcript.render(frame, frame.area(), 0, selected, palette))
                .unwrap();
            terminal.backend().buffer().clone()
        };
        let resting = draw(None);
        let selected = draw(Some(Uuid::from_u128(2)));
        let target = transcript.range(Uuid::from_u128(2)).unwrap();
        for y in 0..30 {
            for x in 0..80 {
                let before = resting.cell((x, y)).unwrap();
                let after = selected.cell((x, y)).unwrap();
                if before != after {
                    assert!(target.contains(&usize::from(y)));
                    assert!(x < transcript.rows[target.start].width);
                }
                if after.symbol() != "▶" {
                    assert_eq!(before.symbol(), after.symbol());
                }
            }
        }
    }

    #[test]
    fn square_message_edges_span_the_full_width_in_color_and_monochrome() {
        let chat = chat(vec![
            message(1, false, "incoming", 0),
            message(2, true, "outgoing", 1),
        ]);
        let palette = ThemePalette::default();
        for outline in [false, true] {
            let transcript = Transcript::new(
                &chat,
                60,
                palette,
                LayoutOptions {
                    explicit_ownership: outline,
                    references: false,
                },
            );
            for selected in [None, Some(Uuid::from_u128(2))] {
                let mut terminal = Terminal::new(TestBackend::new(60, 30)).unwrap();
                terminal
                    .draw(|frame| transcript.render(frame, frame.area(), 0, selected, palette))
                    .unwrap();
                let buffer = terminal.backend().buffer();
                for message in &transcript.messages {
                    for (y, edge) in [
                        (message.range.start, BubbleEdge::Top),
                        (message.range.end - 1, BubbleEdge::Bottom),
                    ] {
                        let row = &transcript.rows[y];
                        for column in 0..row.width {
                            let expected = match (edge, outline, column) {
                                (BubbleEdge::Top, false, _) => "▄",
                                (BubbleEdge::Bottom, false, _) => "▀",
                                (BubbleEdge::Top, true, 0) => "┌",
                                (BubbleEdge::Bottom, true, 0) => "└",
                                (BubbleEdge::Top, true, x) if x == row.width - 1 => "┐",
                                (BubbleEdge::Bottom, true, x) if x == row.width - 1 => "┘",
                                _ => "─",
                            };
                            let cell = buffer.cell((row.x + column, y as u16)).unwrap();
                            assert_eq!(cell.symbol(), expected);
                            assert_eq!(
                                cell.fg,
                                if outline {
                                    palette.muted
                                } else if selected == Some(message.id) {
                                    palette.selected
                                } else {
                                    row.background
                                }
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn explicit_ownership_survives_color_disabled_terminals() {
        let chat = chat(vec![
            message(1, false, "incoming", 0),
            message(2, true, "own", 1),
        ]);
        let transcript = Transcript::new(
            &chat,
            46,
            ThemePalette::default(),
            LayoutOptions {
                explicit_ownership: true,
                references: false,
            },
        );
        assert!(text(&transcript).contains("You\n"));
        assert!(text(&transcript).contains("@mira"));
        assert!(text(&transcript).contains("21:01 · read"));
        assert!(
            transcript
                .rows
                .iter()
                .filter(|row| row.owner.is_some())
                .all(|row| row.outline)
        );
    }

    #[test]
    fn delivery_states_are_distinguishable_without_using_color_alone() {
        let palette = ThemePalette::default();
        let mut message = message(1, true, "status", 1);
        let mut states = Vec::new();
        for state in [
            DeliveryState::Pending,
            DeliveryState::Sent,
            DeliveryState::Delivered,
            DeliveryState::Read,
            DeliveryState::Cancelled,
        ] {
            message.delivery = state;
            let caption = message_caption(&message, false, palette).to_string();
            assert!(
                !states.contains(&caption),
                "{state:?} shares another state's receipt"
            );
            states.push(caption);
            assert!(
                message_caption(&message, true, palette)
                    .to_string()
                    .contains(delivery_label(state))
            );
        }
    }

    #[test]
    fn short_messages_put_their_own_timestamp_inside_the_body_row() {
        let transcript = layout(
            &chat(vec![
                message(1, true, "okay", 29),
                message(2, true, "one more", 30),
            ]),
            72,
        );
        for (id, body, time) in [(1, "okay", "21:29"), (2, "one more", "21:30")] {
            let range = transcript.range(Uuid::from_u128(id)).unwrap();
            assert_eq!(range.len(), 3, "one body line between two square edges");
            let line = transcript.rows[range.start + 1].line.to_string();
            assert!(line.starts_with(body) && line.ends_with(&format!("{time} ✓✓")));
        }
    }

    #[test]
    fn clipped_group_retains_author_context_without_inserting_message_rows() {
        let chat = chat(vec![
            message(1, false, "first", 0),
            message(2, false, "second", 1),
        ]);
        let transcript = layout(&chat, 88);
        let top = transcript.range(Uuid::from_u128(2)).unwrap().start;
        assert_eq!(transcript.continued_author(top), Some("@mira"));
        assert_eq!(transcript.continued_author(0), None);
        assert_eq!(text(&transcript).matches("@mira").count(), 1);
    }

    #[test]
    fn attachment_metadata_wraps_without_clipping_or_exposing_file_secrets() {
        let mut attachment = message(1, true, "", 0);
        let filename = "设计-".to_owned() + &"long-filename-".repeat(5) + ".pdf";
        attachment.attachment = Some(mutte_store::VaultAttachment {
            metadata: mutte_protocol::AttachmentMetadata {
                version: 1,
                attachment_id: Uuid::from_u128(77),
                filename: filename.clone(),
                plaintext_size: 2048,
                chunk_count: 1,
                file_key: "fixture-key-not-for-display".into(),
                plaintext_hash: "fixture-hash-not-for-display".into(),
            },
            local_path: None,
            download_requested: false,
        });
        for width in [40, 46, 60, 74, 88] {
            let transcript = layout(&chat(vec![attachment.clone()]), width);
            let range = transcript.range(attachment.id).unwrap();
            let metadata = transcript.rows[range.clone()]
                .iter()
                .map(|row| row.line.to_string())
                .collect::<String>();
            assert!(metadata.contains(&filename));
            assert!(metadata.contains("2.0 KiB"));
            assert!(metadata.contains("Encrypted · not downloaded"));
            assert!(!metadata.contains("fixture-key") && !metadata.contains("fixture-hash"));
            assert!(transcript.rows.iter().all(
                |row| row.line.width() <= usize::from(row.width.saturating_sub(row.inset * 2))
            ));
        }
    }

    #[test]
    fn viewport_preserves_selected_anchor_on_arrival_resize_and_manual_scroll() {
        let mut chat = chat(
            (0..40)
                .map(|index| {
                    message(
                        index + 1,
                        index % 2 == 0,
                        &format!("Message {index} with enough words to wrap at a narrow width"),
                        (index % 60) as u32,
                    )
                })
                .collect(),
        );
        let mut viewport = TranscriptViewport::default();
        let selected = Uuid::from_u128(20);
        let first = layout(&chat, 88);
        let top = viewport.position(&first, 12, Some(selected), 0);
        let relative = first.range(selected).unwrap().start as isize - top as isize;
        chat.messages
            .push(message(1000, true, "A new message at the tail", 45));
        let updated = layout(&chat, 88);
        let new_top = viewport.position(&updated, 12, Some(selected), 0);
        assert_eq!(
            updated.range(selected).unwrap().start as isize - new_top as isize,
            relative
        );
        let narrow = layout(&chat, 46);
        let top = viewport.position(&narrow, 12, Some(selected), 0);
        let range = narrow.range(selected).unwrap();
        assert!(range.start >= top && range.end <= top + 12);
        viewport.position(&narrow, 12, None, 0);
        let scrolled = viewport.position(&narrow, 12, None, 8);
        let before_anchor = viewport.anchor;
        chat.messages
            .push(message(1001, false, "Another new arrival", 46));
        let newest = layout(&chat, 46);
        assert_eq!(viewport.position(&newest, 12, None, 8), scrolled);
        assert_eq!(viewport.anchor, before_anchor);
    }

    #[test]
    fn nearby_selection_does_not_jump_to_the_top_of_the_viewport() {
        let chat = chat(
            (0..30)
                .map(|index| message(index + 1, true, &format!("Message {index}"), index as u32))
                .collect(),
        );
        let transcript = layout(&chat, 88);
        let mut viewport = TranscriptViewport::default();
        let top = viewport.position(&transcript, 12, Some(Uuid::from_u128(15)), 0);
        assert_eq!(
            viewport.position(&transcript, 12, Some(Uuid::from_u128(16)), 0),
            top
        );
    }
}
