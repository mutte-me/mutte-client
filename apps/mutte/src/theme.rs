use std::{
    collections::HashMap,
    env, fs,
    path::PathBuf,
    time::{Duration, Instant},
};

use ratatui::style::Color;

const THEME_CHECK_INTERVAL: Duration = Duration::from_millis(500);
const MINIMUM_TEXT_CONTRAST: f64 = 4.5;
const MINIMUM_LINE_CONTRAST: f64 = 3.0;
const MINIMUM_SURFACE_CONTRAST: f64 = 1.12;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ThemePalette {
    pub(crate) bg: Color,
    pub(crate) panel: Color,
    pub(crate) selected: Color,
    pub(crate) keycap: Color,
    pub(crate) line: Color,
    pub(crate) line_strong: Color,
    pub(crate) text: Color,
    pub(crate) secondary: Color,
    pub(crate) muted: Color,
    pub(crate) mint: Color,
    pub(crate) success: Color,
    pub(crate) warning: Color,
    pub(crate) focus: Color,
    pub(crate) danger: Color,
}

impl ThemePalette {
    pub(crate) const fn trust_lens() -> Self {
        Self {
            bg: Color::Rgb(13, 22, 21),
            panel: Color::Rgb(18, 30, 26),
            selected: Color::Rgb(29, 43, 32),
            keycap: Color::Rgb(23, 37, 31),
            line: Color::Rgb(75, 75, 64),
            line_strong: Color::Rgb(120, 115, 100),
            text: Color::Rgb(227, 203, 168),
            secondary: Color::Rgb(181, 168, 136),
            muted: Color::Rgb(145, 139, 113),
            mint: Color::Rgb(115, 166, 132),
            success: Color::Rgb(155, 218, 99),
            warning: Color::Rgb(200, 179, 136),
            focus: Color::Rgb(213, 201, 144),
            danger: Color::Rgb(211, 138, 124),
        }
    }

    pub(crate) fn contrasting_text(self, fill: Color) -> Color {
        if contrast_ratio(color_rgb(self.bg), color_rgb(fill))
            >= contrast_ratio(color_rgb(self.text), color_rgb(fill))
        {
            self.bg
        } else {
            self.text
        }
    }

    fn from_colors_toml(contents: &str) -> Option<Self> {
        let colors = parse_colors(contents);
        let bg = *colors.get("background")?;
        let foreground = *colors.get("foreground")?;
        let lighter_background = colors.get("lighter_background").copied().unwrap_or(bg);
        let selection = colors
            .get("selection")
            .copied()
            .unwrap_or(lighter_background);
        let accent = colors
            .get("accent")
            .or_else(|| colors.get("blue"))
            .copied()
            .unwrap_or(foreground);
        let secondary = colors
            .get("light_foreground")
            .copied()
            .unwrap_or(foreground);
        let muted = colors
            .get("dark_foreground")
            .or_else(|| colors.get("muted"))
            .copied()
            .unwrap_or(secondary);
        let line = colors.get("muted").copied().unwrap_or(muted);
        let focus = colors
            .get("bright_foreground")
            .copied()
            .unwrap_or(foreground);
        let success = colors
            .get("bright_green")
            .or_else(|| colors.get("green"))
            .copied()
            .unwrap_or(accent);
        let warning = colors
            .get("bright_yellow")
            .or_else(|| colors.get("yellow"))
            .or_else(|| colors.get("orange"))
            .copied()
            .unwrap_or(foreground);
        let danger = colors
            .get("bright_red")
            .or_else(|| colors.get("red"))
            .copied()
            .unwrap_or(foreground);
        let panel = contrasting_surface(mix(bg, lighter_background, 35), bg);
        let selected = contrasting_surface(selection, bg);
        let keycap = contrasting_surface(mix(bg, selection, 60), bg);
        let text_surfaces = [bg, panel, selected, keycap];

        Some(Self {
            bg: bg.into(),
            panel: panel.into(),
            selected: selected.into(),
            keycap: keycap.into(),
            line: ensure_contrast(line, bg, MINIMUM_LINE_CONTRAST).into(),
            line_strong: ensure_contrast(secondary, bg, MINIMUM_LINE_CONTRAST).into(),
            text: ensure_contrast_across(foreground, &text_surfaces, MINIMUM_TEXT_CONTRAST).into(),
            secondary: ensure_contrast_across(secondary, &text_surfaces, MINIMUM_TEXT_CONTRAST)
                .into(),
            muted: ensure_contrast_across(muted, &text_surfaces, MINIMUM_TEXT_CONTRAST).into(),
            mint: ensure_contrast_across(accent, &text_surfaces, MINIMUM_TEXT_CONTRAST).into(),
            success: ensure_contrast_across(success, &text_surfaces, MINIMUM_TEXT_CONTRAST).into(),
            warning: ensure_contrast_across(warning, &text_surfaces, MINIMUM_TEXT_CONTRAST).into(),
            focus: ensure_contrast_across(focus, &text_surfaces, MINIMUM_TEXT_CONTRAST).into(),
            danger: ensure_contrast_across(danger, &text_surfaces, MINIMUM_TEXT_CONTRAST).into(),
        })
    }
}

impl Default for ThemePalette {
    fn default() -> Self {
        Self::trust_lens()
    }
}

#[derive(Debug)]
pub(crate) struct ThemeManager {
    palette: ThemePalette,
    colors_path: Option<PathBuf>,
    last_contents: Option<String>,
    next_check: Instant,
}

impl ThemeManager {
    pub(crate) fn discover() -> Self {
        let explicit_path = env::var_os("MUTTE_THEME_FILE")
            .filter(|path| !path.is_empty())
            .map(PathBuf::from);
        Self::from_colors_path(explicit_path.or_else(omarchy_colors_path))
    }

    fn from_colors_path(colors_path: Option<PathBuf>) -> Self {
        let mut manager = Self {
            palette: ThemePalette::default(),
            colors_path,
            last_contents: None,
            next_check: Instant::now() + THEME_CHECK_INTERVAL,
        };
        manager.refresh_from_disk();
        manager
    }

    pub(crate) const fn palette(&self) -> ThemePalette {
        self.palette
    }

    pub(crate) fn refresh_if_due(&mut self, now: Instant) -> bool {
        if now < self.next_check {
            return false;
        }
        self.next_check = now + THEME_CHECK_INTERVAL;
        self.refresh_from_disk()
    }

    fn refresh_from_disk(&mut self) -> bool {
        let Some(path) = &self.colors_path else {
            return false;
        };
        let Ok(contents) = fs::read_to_string(path) else {
            // Omarchy swaps the current theme directory atomically. Keeping the
            // last good palette avoids a one-frame fallback during that swap.
            return false;
        };
        if self.last_contents.as_ref() == Some(&contents) {
            return false;
        }
        let Some(palette) = ThemePalette::from_colors_toml(&contents) else {
            return false;
        };
        let changed = palette != self.palette;
        self.palette = palette;
        self.last_contents = Some(contents);
        changed
    }
}

#[cfg(target_os = "linux")]
fn omarchy_colors_path() -> Option<PathBuf> {
    let state_home = env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/state")))?;
    Some(state_home.join("omarchy/current/theme/colors.toml"))
}

#[cfg(not(target_os = "linux"))]
const fn omarchy_colors_path() -> Option<PathBuf> {
    None
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Rgb {
    red: u8,
    green: u8,
    blue: u8,
}

impl From<Rgb> for Color {
    fn from(value: Rgb) -> Self {
        Self::Rgb(value.red, value.green, value.blue)
    }
}

fn color_rgb(color: Color) -> Rgb {
    match color {
        Color::Rgb(red, green, blue) => Rgb { red, green, blue },
        _ => unreachable!("Mutte palettes only contain RGB colors"),
    }
}

fn parse_colors(contents: &str) -> HashMap<&str, Rgb> {
    contents
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let (key, value) = line.split_once('=')?;
            let value = value.trim();
            let quote = value.chars().next()?;
            if !matches!(quote, '\'' | '"') {
                return None;
            }
            let value = value.get(1..)?.split(quote).next()?;
            parse_hex(value).map(|color| (key.trim(), color))
        })
        .collect()
}

fn parse_hex(value: &str) -> Option<Rgb> {
    let value = value.strip_prefix('#').unwrap_or(value);
    if value.len() != 6 || !value.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    Some(Rgb {
        red: u8::from_str_radix(&value[0..2], 16).ok()?,
        green: u8::from_str_radix(&value[2..4], 16).ok()?,
        blue: u8::from_str_radix(&value[4..6], 16).ok()?,
    })
}

fn mix(from: Rgb, to: Rgb, percentage: u16) -> Rgb {
    let percentage = percentage.min(100);
    let remainder = 100 - percentage;
    let channel = |from: u8, to: u8| {
        u8::try_from((u16::from(from) * remainder + u16::from(to) * percentage + 50) / 100)
            .expect("mixed color channel remains within u8")
    };
    Rgb {
        red: channel(from.red, to.red),
        green: channel(from.green, to.green),
        blue: channel(from.blue, to.blue),
    }
}

fn contrasting_surface(surface: Rgb, background: Rgb) -> Rgb {
    ensure_contrast(surface, background, MINIMUM_SURFACE_CONTRAST)
}

fn ensure_contrast(foreground: Rgb, background: Rgb, minimum: f64) -> Rgb {
    ensure_contrast_across(foreground, &[background], minimum)
}

fn ensure_contrast_across(foreground: Rgb, backgrounds: &[Rgb], minimum: f64) -> Rgb {
    if backgrounds
        .iter()
        .all(|background| contrast_ratio(foreground, *background) >= minimum)
    {
        return foreground;
    }
    let black = Rgb {
        red: 0,
        green: 0,
        blue: 0,
    };
    let white = Rgb {
        red: 255,
        green: 255,
        blue: 255,
    };
    let minimum_contrast = |candidate| {
        backgrounds
            .iter()
            .map(|background| contrast_ratio(candidate, *background))
            .fold(f64::INFINITY, f64::min)
    };
    let target = if minimum_contrast(black) >= minimum_contrast(white) {
        black
    } else {
        white
    };
    (1..=100)
        .map(|percentage| mix(foreground, target, percentage))
        .find(|candidate| minimum_contrast(*candidate) >= minimum)
        .unwrap_or(target)
}

fn contrast_ratio(first: Rgb, second: Rgb) -> f64 {
    let first = relative_luminance(first);
    let second = relative_luminance(second);
    (first.max(second) + 0.05) / (first.min(second) + 0.05)
}

fn relative_luminance(color: Rgb) -> f64 {
    let channel = |value: u8| {
        let value = f64::from(value) / 255.0;
        if value <= 0.04045 {
            value / 12.92
        } else {
            ((value + 0.055) / 1.055).powf(2.4)
        }
    };
    0.2126 * channel(color.red) + 0.7152 * channel(color.green) + 0.0722 * channel(color.blue)
}

#[cfg(test)]
mod tests {
    use std::{fs, time::Instant};

    use uuid::Uuid;

    use super::*;

    const DARK_THEME: &str = r##"
background = "#111c18"
lighter_background = "#23372B"
selection = "#32473B"
foreground = "#C1C497"
light_foreground = "#D6D5BC"
dark_foreground = "#81B8A8"
bright_foreground = "#F7E8B2"
muted = "#53685B"
accent = "#509475"
green = "#549e6a"
bright_green = "#63b07a"
yellow = "#459451"
bright_yellow = "#E5C736"
red = "#FF5345"
bright_red = "#db9f9c"
"##;

    const LIGHT_THEME: &str = r##"
background = "#FFFCF0"
lighter_background = "#E6E4D9"
selection = "#CECDC3"
foreground = "#100F0F"
light_foreground = "#403E3C"
dark_foreground = "#878580"
bright_foreground = "#100F0F"
muted = "#B7B5AC"
accent = "#205EA6"
green = "#879A39"
yellow = "#D0A215"
red = "#D14D41"
"##;

    #[test]
    fn parses_dark_and_light_omarchy_palettes() {
        let dark = ThemePalette::from_colors_toml(DARK_THEME).expect("dark theme");
        let light = ThemePalette::from_colors_toml(LIGHT_THEME).expect("light theme");

        assert_eq!(dark.bg, Color::Rgb(17, 28, 24));
        assert_eq!(light.bg, Color::Rgb(255, 252, 240));
        assert_ne!(dark.selected, dark.bg);
        assert_ne!(light.selected, light.bg);
    }

    #[test]
    fn missing_omarchy_state_uses_the_trust_lens_fallback() {
        let manager = ThemeManager::from_colors_path(None);

        assert_eq!(manager.palette(), ThemePalette::trust_lens());
    }

    #[test]
    fn derived_text_roles_meet_accessible_contrast() {
        for source in [DARK_THEME, LIGHT_THEME] {
            let palette = ThemePalette::from_colors_toml(source).expect("valid theme");
            for background in [palette.bg, palette.panel, palette.selected, palette.keycap] {
                for color in [
                    palette.text,
                    palette.secondary,
                    palette.muted,
                    palette.mint,
                    palette.success,
                    palette.warning,
                    palette.focus,
                    palette.danger,
                ] {
                    assert!(
                        contrast_ratio(color_rgb(color), color_rgb(background))
                            >= MINIMUM_TEXT_CONTRAST
                    );
                }
            }
        }
    }

    #[test]
    fn manager_reloads_after_an_atomic_theme_replacement() {
        let directory = env::temp_dir().join(format!("mutte-theme-{}", Uuid::new_v4()));
        fs::create_dir_all(&directory).expect("temporary theme directory");
        let colors_path = directory.join("colors.toml");
        fs::write(&colors_path, DARK_THEME).expect("dark theme fixture");
        let mut manager = ThemeManager::from_colors_path(Some(colors_path.clone()));
        assert_eq!(manager.palette().bg, Color::Rgb(17, 28, 24));

        let replacement = directory.join("next-colors.toml");
        fs::write(&replacement, LIGHT_THEME).expect("light theme fixture");
        fs::rename(replacement, &colors_path).expect("atomic fixture swap");

        assert!(manager.refresh_from_disk());
        assert_eq!(manager.palette().bg, Color::Rgb(255, 252, 240));
        assert!(!manager.refresh_if_due(Instant::now()));
        fs::remove_dir_all(directory).expect("remove temporary theme directory");
    }

    #[test]
    fn invalid_replacement_keeps_the_last_good_palette() {
        let directory = env::temp_dir().join(format!("mutte-theme-{}", Uuid::new_v4()));
        fs::create_dir_all(&directory).expect("temporary theme directory");
        let colors_path = directory.join("colors.toml");
        fs::write(&colors_path, DARK_THEME).expect("dark theme fixture");
        let mut manager = ThemeManager::from_colors_path(Some(colors_path.clone()));
        let original = manager.palette();

        fs::write(&colors_path, "mode = \"dark\"\n").expect("invalid theme fixture");

        assert!(!manager.refresh_from_disk());
        assert_eq!(manager.palette(), original);
        fs::remove_dir_all(directory).expect("remove temporary theme directory");
    }
}
