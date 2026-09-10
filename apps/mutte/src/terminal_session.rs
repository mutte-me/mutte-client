use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
};
use ratatui::DefaultTerminal;

/// Keeps terminal scroll gestures inside Mutte and restores shell input on exit.
pub struct TerminalSession {
    terminal: DefaultTerminal,
    active: Arc<AtomicBool>,
}

impl TerminalSession {
    pub fn new() -> io::Result<Self> {
        let terminal = match ratatui::try_init() {
            Ok(terminal) => terminal,
            Err(error) => {
                // Initialization can fail after raw mode or the alternate screen
                // was enabled, before a session exists to clean it up.
                ratatui::restore();
                return Err(error);
            }
        };
        let session = Self {
            terminal,
            active: Arc::new(AtomicBool::new(true)),
        };

        // Ratatui's installed hook restores raw mode and the alternate screen.
        // Disable our extra input mode first, before that hook prints the panic.
        let previous_hook = std::panic::take_hook();
        let active = Arc::clone(&session.active);
        std::panic::set_hook(Box::new(move |info| {
            if active.swap(false, Ordering::SeqCst) {
                let _ = execute!(io::stdout(), DisableMouseCapture);
            }
            previous_hook(info);
        }));

        // Construct the guard first so a partial write or flush failure also
        // disables capture and restores the terminal when this returns an error.
        execute!(io::stdout(), EnableMouseCapture)?;
        Ok(session)
    }

    pub fn terminal(&mut self) -> &mut DefaultTerminal {
        &mut self.terminal
    }
}

impl Drop for TerminalSession {
    fn drop(&mut self) {
        if self.active.swap(false, Ordering::SeqCst) {
            let _ = execute!(io::stdout(), DisableMouseCapture);
            ratatui::restore();
        }
    }
}
