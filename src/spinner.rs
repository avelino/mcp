use indicatif::{ProgressBar, ProgressStyle};
use std::io::IsTerminal;
use std::time::Duration;

pub struct Spinner {
    bar: ProgressBar,
}

impl Spinner {
    pub fn start(message: &str) -> Self {
        if !std::io::stderr().is_terminal() {
            return Self {
                bar: ProgressBar::hidden(),
            };
        }

        let bar = ProgressBar::new_spinner();
        bar.set_style(
            ProgressStyle::default_spinner()
                .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"])
                .template("{spinner} {msg}")
                .unwrap(),
        );
        bar.set_message(message.to_string());
        bar.enable_steady_tick(Duration::from_millis(80));
        Self { bar }
    }

    pub fn stop(self) {
        self.bar.finish_and_clear();
    }
}

impl Drop for Spinner {
    fn drop(&mut self) {
        self.bar.finish_and_clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spinner_start_stop_no_panic() {
        let spinner = Spinner::start("loading...");
        std::thread::sleep(Duration::from_millis(200));
        spinner.stop();
    }

    #[test]
    fn test_spinner_drop_stops_cleanly() {
        let spinner = Spinner::start("loading...");
        std::thread::sleep(Duration::from_millis(100));
        drop(spinner);
    }
}
