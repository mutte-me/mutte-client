use std::{env, process::Command};

#[cfg(target_os = "macos")]
use anyhow::Context;
use anyhow::{Result, bail};

const MAX_DEVICE_NAME_BYTES: usize = 80;

/// Open the relay's authentication ceremony with the host platform's browser.
///
/// Omarchy remains an optional first-class integration, while ordinary Linux
/// desktops and macOS use their native URL launchers.
pub fn open_browser(url: &str) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        for (program, args) in [
            ("omarchy", vec!["launch", "browser", url]),
            ("xdg-open", vec![url]),
        ] {
            if Command::new(program).args(args).spawn().is_ok() {
                return Ok(());
            }
        }
        bail!("open browser; neither Omarchy nor xdg-open is available")
    }

    #[cfg(target_os = "macos")]
    {
        Command::new("open")
            .arg(url)
            .spawn()
            .context("open browser with macOS Launch Services")?;
        Ok(())
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = url;
        bail!("automatic browser launch is supported on Linux and macOS; use --no-browser")
    }
}

/// Produce a useful, non-product-specific name for a newly linked terminal.
/// The explicit override is helpful for hosts whose machine name is generic.
pub fn device_name(override_name: Option<&str>) -> Result<String> {
    let name = if let Some(name) = override_name.map(str::trim).filter(|name| !name.is_empty()) {
        name.to_owned()
    } else {
        let host = env::var("HOSTNAME")
            .ok()
            .filter(|host| !host.trim().is_empty())
            .or_else(hostname_from_command)
            .unwrap_or_else(|| "terminal".into());
        format!("{} · {}", host.trim(), platform_label())
    };
    if name.len() > MAX_DEVICE_NAME_BYTES {
        bail!("device name must be at most {MAX_DEVICE_NAME_BYTES} UTF-8 bytes")
    }
    Ok(name)
}

fn hostname_from_command() -> Option<String> {
    let output = Command::new("hostname").output().ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout)
        .ok()
        .map(|host| host.trim().to_owned())
        .filter(|host| !host.is_empty())
}

const fn platform_label() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        "Linux"
    }
    #[cfg(target_os = "macos")]
    {
        "macOS"
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        "Terminal"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_device_name_is_trimmed() {
        assert_eq!(
            device_name(Some("  desk terminal  ")).unwrap(),
            "desk terminal"
        );
        assert!(device_name(Some(&"x".repeat(MAX_DEVICE_NAME_BYTES + 1))).is_err());
    }

    #[test]
    fn default_device_name_identifies_the_platform() {
        let name = device_name(None).unwrap();
        assert!(name.ends_with(platform_label()));
        assert!(name.contains(" · "));
    }
}
