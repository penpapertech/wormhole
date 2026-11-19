mod auth;
mod cli;
mod code;
mod connect;
mod events;
mod mailbox;
mod session;
mod stun;
mod transfer;
mod tui;
mod webrtc;

use anyhow::Result;
use clap::{Parser, Subcommand};
use session::Options;
use std::path::PathBuf;

/// Peer-to-peer file transfer that works across NATs, using a short one-time code.
#[derive(Parser)]
#[command(name = "wormhole", version, about, after_help = EXAMPLES)]
struct Cli {
    /// Rendezvous mailbox URL, or `off` for local-network only.
    #[arg(long, global = true, env = "WORMHOLE_MAILBOX")]
    mailbox: Option<String>,

    #[command(subcommand)]
    cmd: Option<Cmd>,
}

const EXAMPLES: &str = "\
Examples:
  wormhole                            interactive TUI (receive, or drag & drop files to send)
  wormhole receive                    print a code and keep receiving into the current folder
                                      with that code until Ctrl+C (--once: stop after one)
  wormhole send 7-purple-sausage a.pdf
  wormhole send 7-purple-sausage -R *  send everything here, including folders
  wormhole send 7-purple-sausage      open the TUI to drag & drop files";

#[derive(Subcommand)]
enum Cmd {
    /// Wait for files: prints a code to give to senders. Keeps accepting transfers with the same
    /// code until Ctrl+C.
    #[command(visible_alias = "r", alias = "recv")]
    Receive {
        /// Directory to save into.
        #[arg(short, long, default_value = ".")]
        out: PathBuf,
        /// Exit after one transfer, and let the code expire (after 30 minutes) if nobody sends.
        #[arg(long)]
        once: bool,
        /// Don't accept browser (WebRTC) senders.
        #[arg(long)]
        no_webrtc: bool,
    },
    /// Send files and folders to a waiting receiver.
    #[command(visible_alias = "s")]
    Send {
        /// The code shown by the receiver.
        code: Option<String>,
        /// Files/folders to send. Without any, opens the TUI to drag & drop.
        files: Vec<PathBuf>,
        /// Send directories recursively.
        #[arg(short = 'R', short_alias = 'r', long)]
        recursive: bool,
    },
    /// Open the interactive terminal UI.
    Tui,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut opts = Options { mailbox: cli.mailbox, no_webrtc: false };
    let rt = tokio::runtime::Runtime::new()?;
    match cli.cmd {
        None | Some(Cmd::Tui) => tui::run(rt.handle().clone(), opts, None),
        Some(Cmd::Send { code, files, .. }) if files.is_empty() => {
            tui::run(rt.handle().clone(), opts, Some(code.unwrap_or_default()))
        }
        Some(Cmd::Send { code, files, recursive }) => {
            let code = code.unwrap_or_default();
            let res = rt.block_on(cli::run(
                move |tx| Box::pin(session::send(opts, code, files, recursive, tx)),
                false,
                false,
            ));
            exit_on_err(res)
        }
        Some(Cmd::Receive { out, once, no_webrtc }) => {
            opts.no_webrtc = no_webrtc;
            let res = rt.block_on(cli::run(move |tx| Box::pin(session::receive(opts, out, once, tx)), true, !once));
            exit_on_err(res)
        }
    }
}

fn exit_on_err(res: Result<()>) -> Result<()> {
    if let Err(e) = res {
        eprintln!("  {} {e:#}", cli::fail_mark());
        std::process::exit(1);
    }
    Ok(())
}
