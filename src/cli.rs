//! Plain (non-TUI) terminal front-end.

use crate::events::{Event, Summary};
use anyhow::Result;
use indicatif::{HumanBytes, ProgressBar, ProgressStyle};
use std::future::Future;
use std::time::Duration;
use tokio::sync::mpsc;

fn color(code: &str, text: &str) -> String {
    use std::io::IsTerminal;
    if std::io::stderr().is_terminal() && std::env::var_os("NO_COLOR").is_none() {
        format!("\x1b[{code}m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

pub fn fail_mark() -> String {
    color("1;31", "✘")
}

pub fn describe(s: &Summary, verb: &str) -> String {
    let rate = if s.secs > 0.0 { s.bytes as f64 / s.secs } else { 0.0 };
    let ratio = if s.bytes > 0 { 100.0 * s.wire_bytes as f64 / s.bytes as f64 } else { 100.0 };
    format!(
        "{verb} {} file{} ({}) in {:.1}s — {}/s, {} on the wire (compressed to {})",
        s.files,
        if s.files == 1 { "" } else { "s" },
        HumanBytes(s.bytes),
        s.secs,
        HumanBytes(rate as u64),
        HumanBytes(s.wire_bytes),
        if ratio > 0.0 && ratio < 1.0 { "<1%".to_string() } else { format!("{ratio:.0}%") }
    )
}

pub async fn run<F>(fut: F, receiving: bool) -> Result<()>
where
    F: FnOnce(mpsc::UnboundedSender<Event>) -> std::pin::Pin<Box<dyn Future<Output = Result<Summary>> + Send>>,
{
    let (tx, mut rx) = mpsc::unbounded_channel();
    let task = tokio::spawn(fut(tx));
    let spinner = ProgressBar::new_spinner();
    spinner.enable_steady_tick(Duration::from_millis(100));
    let mut bar: Option<ProgressBar> = None;
    let mut ctrl_c = std::pin::pin!(tokio::signal::ctrl_c());
    loop {
        tokio::select! {
            _ = &mut ctrl_c => {
                spinner.finish_and_clear();
                if let Some(b) = &bar { b.abandon(); }
                task.abort();
                anyhow::bail!("cancelled");
            }
            ev = rx.recv() => {
                let Some(ev) = ev else { break };
                match ev {
                    Event::Code { code: c, browser } => {
                        spinner.suspend(|| {
                            println!();
                            println!("  Wormhole code:  {}", color("1;32", &c));
                            println!();
                            println!("  On the other computer run:");
                            println!("      wormhole send {c} <files…>");
                            if browser {
                                println!("  or send from a browser:");
                                println!("      {}#{c}", crate::mailbox::WEB_URL);
                            }
                            println!();
                        });
                    }
                    Event::Status(s) => spinner.set_message(s),
                    Event::Warn(w) => spinner.suspend(|| eprintln!("  {} {w}", color("33", "warning:"))),
                    Event::Connected { peer, lan } => spinner.suspend(|| {
                        println!("  Connected to {peer} ({})", if lan { "local network" } else { "direct over the internet" })
                    }),
                    Event::Offer(o) => spinner.suspend(|| {
                        let mut names = o.names.join(", ");
                        if names.len() > 70 { names.truncate(67); names.push_str("..."); }
                        println!("  Receiving {} file{} ({}): {names}", o.files, if o.files == 1 { "" } else { "s" }, HumanBytes(o.bytes));
                    }),
                    Event::Progress { done, total } => {
                        let b = bar.get_or_insert_with(|| {
                            spinner.finish_and_clear();
                            let b = ProgressBar::new(total);
                            b.set_style(
                                ProgressStyle::with_template(
                                    "  {wide_bar:.cyan/blue} {bytes}/{total_bytes} {bytes_per_sec} eta {eta}",
                                )
                                .unwrap()
                                .progress_chars("█▉▊▋▌▍▎▏ "),
                            );
                            b
                        });
                        b.set_position(done.min(total));
                    }
                }
            }
        }
    }
    spinner.finish_and_clear();
    let res = task.await?;
    if let Some(b) = &bar {
        if res.is_ok() { b.finish() } else { b.abandon() }
    }
    let s = res?;
    println!("  {} {}", color("1;32", "✔"), describe(&s, if receiving { "Received" } else { "Sent" }));
    if receiving {
        println!("  Saved: {}", s.names.join(", "));
    }
    Ok(())
}
