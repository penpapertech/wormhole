//! Interactive terminal UI. Dragging files onto most terminals pastes their paths, which we
//! collect into the send list (bracketed paste, or typed input followed by Enter).

use crate::cli::describe;
use crate::events::{Event, Summary};
use crate::session::{self, Options};
use crate::transfer::Offer;
use anyhow::{bail, Result};
use indicatif::HumanBytes;
use ratatui::crossterm::event::{
    self, DisableBracketedPaste, EnableBracketedPaste, Event as TermEvent, KeyCode, KeyEvent,
    KeyEventKind, KeyModifiers,
};
use ratatui::crossterm::execute;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Gauge, List, ListItem, Paragraph, Wrap};
use ratatui::Frame;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio::runtime::Handle;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

#[derive(PartialEq)]
enum Mode {
    Menu,
    SendForm,
    Running,
}

#[derive(PartialEq, Clone, Copy)]
enum Focus {
    Code,
    Files,
}

struct Run {
    receiving: bool,
    code: Option<String>,
    status: String,
    log: Vec<(bool, String)>,
    connected: Option<String>,
    offer: Option<Offer>,
    progress: (u64, u64),
    started: Option<Instant>,
    result: Option<Result<Summary, String>>,
    rx: mpsc::UnboundedReceiver<Event>,
    task: Option<JoinHandle<Result<Summary>>>,
}

struct App {
    handle: Handle,
    opts: Options,
    mode: Mode,
    menu_sel: usize,
    focus: Focus,
    code_input: String,
    file_input: String,
    files: Vec<PathBuf>,
    form_msg: Option<String>,
    run: Option<Run>,
    quit: bool,
}

pub fn run(handle: Handle, opts: Options, send_code: Option<String>) -> Result<()> {
    if !std::io::stdout().is_terminal() {
        bail!("the interactive UI needs a terminal; use `wormhole receive` or `wormhole send <code> <files>`");
    }
    let mut app = App {
        handle,
        opts,
        mode: Mode::Menu,
        menu_sel: 0,
        focus: Focus::Code,
        code_input: String::new(),
        file_input: String::new(),
        files: Vec::new(),
        form_msg: None,
        run: None,
        quit: false,
    };
    if let Some(c) = send_code {
        app.mode = Mode::SendForm;
        if !c.is_empty() {
            app.code_input = c;
            app.focus = Focus::Files;
        }
    }

    let mut terminal = ratatui::init();
    let _ = execute!(std::io::stdout(), EnableBracketedPaste);
    let res = (|| -> Result<()> {
        while !app.quit {
            app.pump();
            terminal.draw(|f| app.draw(f))?;
            if event::poll(Duration::from_millis(80))? {
                match event::read()? {
                    TermEvent::Key(k) if k.kind != KeyEventKind::Release => app.key(k),
                    TermEvent::Paste(s) => app.paste(&s),
                    _ => {}
                }
            }
        }
        Ok(())
    })();
    let _ = execute!(std::io::stdout(), DisableBracketedPaste);
    ratatui::restore();
    if let Some(run) = app.run.take() {
        if let Some(t) = run.task {
            t.abort();
        }
    }
    res
}

/// Turn dropped/pasted text into existing paths. Handles shell quoting/escaping and file:// URLs.
pub fn parse_dropped(text: &str) -> Vec<PathBuf> {
    let text = text.trim();
    if text.is_empty() {
        return vec![];
    }
    let clean = |s: &str| -> PathBuf {
        let s = s.strip_prefix("file://").unwrap_or(s);
        PathBuf::from(percent_decode(s))
    };
    let whole = clean(text.trim_matches(|c| c == '\'' || c == '"'));
    if whole.exists() {
        return vec![whole];
    }
    let mut tokens: Vec<String> = Vec::new();
    for line in text.lines() {
        match shell_words::split(line) {
            Ok(t) => tokens.extend(t),
            Err(_) => tokens.push(line.to_string()),
        }
    }
    tokens.iter().map(|t| clean(t)).filter(|p| p.exists()).collect()
}

fn percent_decode(s: &str) -> String {
    if !s.contains('%') {
        return s.to_string();
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() && s.is_char_boundary(i + 3) {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

impl App {
    fn start(&mut self, receiving: bool) {
        let (tx, rx) = mpsc::unbounded_channel();
        let opts = self.opts.clone();
        let task = if receiving {
            self.handle.spawn(session::receive(opts, PathBuf::from("."), tx))
        } else {
            let code = self.code_input.trim().to_string();
            let files = self.files.clone();
            self.handle.spawn(session::send(opts, code, files, true, tx))
        };
        self.run = Some(Run {
            receiving,
            code: if receiving { None } else { Some(self.code_input.trim().to_string()) },
            status: "Starting…".into(),
            log: vec![],
            connected: None,
            offer: None,
            progress: (0, 0),
            started: None,
            result: None,
            rx,
            task: Some(task),
        });
        self.mode = Mode::Running;
    }

    fn pump(&mut self) {
        let Some(run) = &mut self.run else { return };
        while let Ok(ev) = run.rx.try_recv() {
            match ev {
                Event::Code(c) => run.code = Some(c),
                Event::Status(s) => run.status = s,
                Event::Warn(w) => run.log.push((true, w)),
                Event::Connected { peer, lan } => {
                    run.connected = Some(format!(
                        "{peer} ({})",
                        if lan { "local network" } else { "direct over the internet" }
                    ))
                }
                Event::Offer(o) => run.offer = Some(o),
                Event::Progress { done, total } => {
                    run.started.get_or_insert_with(Instant::now);
                    run.progress = (done.min(total), total);
                    run.status = if run.receiving { "Receiving…" } else { "Sending…" }.into();
                }
            }
        }
        if run.task.as_ref().is_some_and(|t| t.is_finished()) {
            let t = run.task.take().unwrap();
            run.result = Some(match self.handle.block_on(t) {
                Ok(Ok(s)) => Ok(s),
                Ok(Err(e)) => Err(format!("{e:#}")),
                Err(e) => Err(e.to_string()),
            });
        }
    }

    fn add_paths(&mut self, text: &str) -> bool {
        let paths = parse_dropped(text);
        if paths.is_empty() {
            self.form_msg = Some(format!("Not found: {}", text.trim()));
            return false;
        }
        for p in paths {
            if !self.files.contains(&p) {
                self.files.push(p);
            }
        }
        self.form_msg = None;
        true
    }

    fn try_send(&mut self) {
        if let Err(e) = crate::code::Code::parse(&self.code_input) {
            self.form_msg = Some(e.to_string());
            self.focus = Focus::Code;
        } else if self.files.is_empty() {
            self.form_msg = Some("Add at least one file (drag it onto this window)".into());
            self.focus = Focus::Files;
        } else {
            self.start(false);
        }
    }

    fn paste(&mut self, s: &str) {
        match self.mode {
            Mode::SendForm if self.focus == Focus::Code => {
                // Dropping files while the code field is focused still adds them.
                if !parse_dropped(s).is_empty() {
                    self.add_paths(s);
                } else {
                    self.code_input = s.trim().to_string();
                }
            }
            Mode::SendForm => {
                if !self.add_paths(s) {
                    self.file_input.push_str(s.trim());
                }
            }
            Mode::Menu => {
                // Dropping a file on the menu jumps straight into send mode.
                if !parse_dropped(s).is_empty() {
                    self.mode = Mode::SendForm;
                    self.add_paths(s);
                    self.focus = Focus::Code;
                }
            }
            Mode::Running => {}
        }
    }

    fn key(&mut self, k: KeyEvent) {
        if k.modifiers.contains(KeyModifiers::CONTROL) && matches!(k.code, KeyCode::Char('c')) {
            self.quit = true;
            return;
        }
        match self.mode {
            Mode::Menu => match k.code {
                KeyCode::Up | KeyCode::Char('k') => self.menu_sel = self.menu_sel.saturating_sub(1),
                KeyCode::Down | KeyCode::Char('j') => self.menu_sel = (self.menu_sel + 1).min(1),
                KeyCode::Char('r') => self.start(true),
                KeyCode::Char('s') => self.mode = Mode::SendForm,
                KeyCode::Enter => {
                    if self.menu_sel == 0 {
                        self.start(true)
                    } else {
                        self.mode = Mode::SendForm
                    }
                }
                KeyCode::Char('q') | KeyCode::Esc => self.quit = true,
                _ => {}
            },
            Mode::SendForm => match k.code {
                KeyCode::Esc => {
                    self.mode = Mode::Menu;
                    self.form_msg = None;
                }
                KeyCode::Tab | KeyCode::BackTab => {
                    self.focus = if self.focus == Focus::Code { Focus::Files } else { Focus::Code }
                }
                KeyCode::Char('s') if k.modifiers.contains(KeyModifiers::CONTROL) => self.try_send(),
                KeyCode::Delete => {
                    self.files.pop();
                }
                KeyCode::Enter => match self.focus {
                    Focus::Code => {
                        if self.files.is_empty() {
                            self.focus = Focus::Files;
                        } else {
                            self.try_send();
                        }
                    }
                    Focus::Files => {
                        if self.file_input.trim().is_empty() {
                            self.try_send();
                        } else {
                            let t = std::mem::take(&mut self.file_input);
                            if !self.add_paths(&t) {
                                self.file_input = t;
                            }
                        }
                    }
                },
                KeyCode::Backspace => {
                    let buf = if self.focus == Focus::Code { &mut self.code_input } else { &mut self.file_input };
                    if buf.pop().is_none() && self.focus == Focus::Files {
                        self.files.pop();
                    }
                }
                KeyCode::Char(c) => {
                    if self.focus == Focus::Code { self.code_input.push(c) } else { self.file_input.push(c) }
                }
                _ => {}
            },
            Mode::Running => {
                let done = self.run.as_ref().is_some_and(|r| r.result.is_some());
                match k.code {
                    KeyCode::Char('q') if done => self.quit = true,
                    KeyCode::Esc | KeyCode::Enter if done => {
                        let ok = self.run.as_ref().and_then(|r| r.result.as_ref()).is_some_and(|r| r.is_ok());
                        let was_send = self.run.as_ref().is_some_and(|r| !r.receiving);
                        self.run = None;
                        if was_send && ok {
                            self.files.clear();
                            self.code_input.clear();
                            self.focus = Focus::Code;
                        }
                        self.mode = if was_send && !ok { Mode::SendForm } else { Mode::Menu };
                    }
                    KeyCode::Esc => {
                        if let Some(t) = self.run.as_mut().and_then(|r| r.task.take()) {
                            t.abort();
                        }
                        let was_send = self.run.as_ref().is_some_and(|r| !r.receiving);
                        self.run = None;
                        self.mode = if was_send { Mode::SendForm } else { Mode::Menu };
                    }
                    _ => {}
                }
            }
        }
    }

    fn draw(&self, f: &mut Frame) {
        let [header, body, footer] =
            Layout::vertical([Constraint::Length(1), Constraint::Min(5), Constraint::Length(1)]).areas(f.area());
        f.render_widget(
            Line::from(vec![
                " wormhole ".bold().black().on_cyan(),
                "  peer-to-peer file transfer".dim(),
            ]),
            header,
        );
        let hint = match self.mode {
            Mode::Menu => "↑/↓ select · Enter open · r receive · s send · q quit",
            Mode::SendForm => "Tab switch field · Enter add path / send · Del remove last · Ctrl-S send · Esc back",
            Mode::Running => {
                if self.run.as_ref().is_some_and(|r| r.result.is_some()) {
                    "Enter/Esc back · q quit"
                } else {
                    "Esc cancel · Ctrl-C quit"
                }
            }
        };
        f.render_widget(Line::from(hint).dim(), footer);
        match self.mode {
            Mode::Menu => self.draw_menu(f, body),
            Mode::SendForm => self.draw_form(f, body),
            Mode::Running => self.draw_run(f, body),
        }
    }

    fn draw_menu(&self, f: &mut Frame, area: Rect) {
        let area = center(area, 60, 10);
        let items = [
            ("Receive files", "get a code, files are saved in the current folder"),
            ("Send files", "enter a code, drag & drop files"),
        ];
        let lines: Vec<ListItem> = items
            .iter()
            .enumerate()
            .map(|(i, (t, d))| {
                let sel = i == self.menu_sel;
                ListItem::new(vec![
                    Line::from(vec![
                        Span::raw(if sel { " ▶ " } else { "   " }),
                        if sel { t.bold().cyan() } else { t.bold() },
                    ]),
                    Line::from(format!("     {d}")).dim(),
                    Line::raw(""),
                ])
            })
            .collect();
        f.render_widget(
            List::new(lines).block(Block::bordered().border_type(BorderType::Rounded).title(" What do you want to do? ")),
            area,
        );
    }

    fn draw_form(&self, f: &mut Frame, area: Rect) {
        let area = center(area, 90, area.height);
        let [code_a, files_a, input_a, msg_a] = Layout::vertical([
            Constraint::Length(3),
            Constraint::Min(4),
            Constraint::Length(3),
            Constraint::Length(1),
        ])
        .areas(area);
        let fstyle = |on: bool| if on { Style::new().fg(Color::Cyan) } else { Style::new().fg(Color::DarkGray) };
        let cursor = |on: bool| if on { "▏" } else { "" };

        let code_on = self.focus == Focus::Code;
        f.render_widget(
            Paragraph::new(Line::from(vec![
                self.code_input.clone().bold().green(),
                Span::raw(cursor(code_on)),
            ]))
            .block(Block::bordered().border_type(BorderType::Rounded).border_style(fstyle(code_on)).title(" Code from the receiver ")),
            code_a,
        );

        let mut items: Vec<ListItem> = self
            .files
            .iter()
            .map(|p| {
                let (icon, size) = match std::fs::metadata(p) {
                    Ok(m) if m.is_dir() => ("📁", "folder".to_string()),
                    Ok(m) => ("📄", HumanBytes(m.len()).to_string()),
                    Err(_) => ("⚠", "missing".to_string()),
                };
                ListItem::new(Line::from(vec![
                    Span::raw(format!(" {icon} ")),
                    Span::raw(p.display().to_string()),
                    format!("  {size}").dim(),
                ]))
            })
            .collect();
        if items.is_empty() {
            items.push(ListItem::new(Line::from("   Drag & drop files or folders onto this window…").dim()));
        }
        f.render_widget(
            List::new(items).block(
                Block::bordered()
                    .border_type(BorderType::Rounded)
                    .title(format!(" Files to send ({}) ", self.files.len())),
            ),
            files_a,
        );

        let files_on = self.focus == Focus::Files;
        f.render_widget(
            Paragraph::new(Line::from(vec![Span::raw(self.file_input.clone()), Span::raw(cursor(files_on))]))
                .block(
                    Block::bordered()
                        .border_type(BorderType::Rounded)
                        .border_style(fstyle(files_on))
                        .title(" Path (drop or type, Enter to add · empty Enter sends) "),
                ),
            input_a,
        );
        if let Some(m) = &self.form_msg {
            f.render_widget(Line::from(format!(" {m}")).yellow(), msg_a);
        }
    }

    fn draw_run(&self, f: &mut Frame, area: Rect) {
        let Some(run) = &self.run else { return };
        let area = center(area, 90, area.height);
        let [code_a, info_a, gauge_a, log_a] = Layout::vertical([
            Constraint::Length(if run.receiving { 6 } else { 3 }),
            Constraint::Length(5),
            Constraint::Length(3),
            Constraint::Min(2),
        ])
        .areas(area);

        let code = run.code.clone().unwrap_or_else(|| "…".into());
        let mut lines = vec![Line::from(code.clone().bold().green()).alignment(Alignment::Center)];
        if run.receiving {
            lines.push(Line::raw(""));
            lines.push(Line::from("On the other computer run:").dim().alignment(Alignment::Center));
            lines.push(Line::from(format!("wormhole send {code} <files…>")).alignment(Alignment::Center));
        }
        f.render_widget(
            Paragraph::new(lines).block(
                Block::bordered()
                    .border_type(BorderType::Rounded)
                    .title(if run.receiving { " Your code " } else { " Sending to " }),
            ),
            code_a,
        );

        let mut info = vec![];
        match &run.result {
            None => info.push(Line::from(vec!["● ".cyan(), Span::raw(run.status.clone())])),
            Some(Ok(s)) => {
                info.push(Line::from(vec![
                    "✔ ".green().bold(),
                    Span::raw(describe(s, if run.receiving { "Received" } else { "Sent" })),
                ]));
                if run.receiving {
                    info.push(Line::from(format!("  Saved: {}", s.names.join(", "))));
                }
            }
            Some(Err(e)) => info.push(Line::from(vec!["✘ ".red().bold(), e.clone().red()])),
        }
        if let Some(c) = &run.connected {
            info.push(Line::from(format!("  Connected to {c}")).dim());
        }
        if let Some(o) = &run.offer {
            info.push(
                Line::from(format!(
                    "  {} file(s), {}: {}",
                    o.files,
                    HumanBytes(o.bytes),
                    o.names.join(", ")
                ))
                .dim(),
            );
        }
        f.render_widget(Paragraph::new(info).wrap(Wrap { trim: false }), info_a);

        let (done, total) = run.progress;
        if total > 0 {
            let ratio = if total == 0 { 0.0 } else { done as f64 / total as f64 };
            let speed = run
                .started
                .map(|s| s.elapsed().as_secs_f64())
                .filter(|s| *s > 0.2)
                .map(|s| format!("  {}/s", HumanBytes((done as f64 / s) as u64)))
                .unwrap_or_default();
            f.render_widget(
                Gauge::default()
                    .block(Block::bordered().border_type(BorderType::Rounded))
                    .gauge_style(Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD))
                    .ratio(ratio.clamp(0.0, 1.0))
                    .label(format!("{} / {}{speed}", HumanBytes(done), HumanBytes(total))),
                gauge_a,
            );
        }
        let log: Vec<ListItem> = run
            .log
            .iter()
            .rev()
            .take(log_a.height as usize)
            .rev()
            .map(|(w, s)| ListItem::new(Line::from(format!(" {} {s}", if *w { "!" } else { "·" })).yellow()))
            .collect();
        f.render_widget(List::new(log), log_a);
    }
}

fn center(area: Rect, w: u16, h: u16) -> Rect {
    let w = w.min(area.width);
    let h = h.min(area.height);
    Rect { x: area.x + (area.width - w) / 2, y: area.y + (area.height - h) / 2, width: w, height: h }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dropped_paths() {
        let d = std::env::temp_dir().join(format!("wh drop {}", rand::random::<u32>()));
        std::fs::create_dir_all(&d).unwrap();
        let a = d.join("a b.txt");
        let b = d.join("c.txt");
        std::fs::write(&a, "x").unwrap();
        std::fs::write(&b, "y").unwrap();
        // macOS Terminal style: backslash-escaped
        let esc = |p: &PathBuf| p.display().to_string().replace(' ', "\\ ");
        assert_eq!(parse_dropped(&format!("{} {} ", esc(&a), esc(&b))), vec![a.clone(), b.clone()]);
        // GNOME style: single-quoted
        assert_eq!(parse_dropped(&format!("'{}' '{}'", a.display(), b.display())), vec![a.clone(), b.clone()]);
        // URL style
        let url = format!("file://{}", a.display().to_string().replace(' ', "%20"));
        assert_eq!(parse_dropped(&url), vec![a.clone()]);
        // raw unquoted path with spaces
        assert_eq!(parse_dropped(&a.display().to_string()), vec![a.clone()]);
        std::fs::remove_dir_all(d).unwrap();
    }
}
