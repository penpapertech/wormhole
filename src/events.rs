//! Events emitted by the transfer engine; consumed by the CLI or the TUI.

use crate::transfer::Offer;
use std::net::SocketAddr;
use tokio::sync::mpsc::UnboundedSender;

#[derive(Debug, Clone)]
pub struct Summary {
    pub files: u64,
    pub bytes: u64,
    pub wire_bytes: u64,
    pub secs: f64,
    pub names: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum Event {
    /// Receiver: the code to give to the sender.
    Code(String),
    Status(String),
    Warn(String),
    Connected { peer: SocketAddr, lan: bool },
    Offer(Offer),
    Progress { done: u64, total: u64 },
}

pub type Tx = UnboundedSender<Event>;

pub fn emit(tx: &Tx, ev: Event) {
    let _ = tx.send(ev);
}

pub fn status(tx: &Tx, s: impl Into<String>) {
    emit(tx, Event::Status(s.into()));
}

pub fn warn(tx: &Tx, s: impl Into<String>) {
    emit(tx, Event::Warn(s.into()));
}
