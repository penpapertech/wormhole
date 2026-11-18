"""Drive the TUI through a pseudo-terminal.
1) CLI receiver + TUI sender (file dropped via bracketed paste).
2) TUI receiver + CLI sender.
Usage: python3 tests/tui_smoke.py target/release/wormhole"""
import os, pty, re, select, subprocess, sys, tempfile, time, signal

BIN = os.path.abspath(sys.argv[1])
CODE_RE = re.compile(rb"\b(\d+-[a-z]+-[a-z]+)\b")


def spawn_tui(args, cwd):
    pid, fd = pty.fork()
    if pid == 0:
        os.chdir(cwd)
        os.environ["TERM"] = "xterm-256color"
        os.execv(BIN, [BIN] + args)
    os.set_blocking(fd, False)
    import fcntl, struct, termios
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))
    os.kill(pid, signal.SIGWINCH)
    return pid, fd


class Screen:
    """Just enough of a VT100 to follow ratatui's output (cursor moves + text)."""

    def __init__(self, rows=40, cols=120):
        self.rows, self.cols = rows, cols
        self.grid = [[" "] * cols for _ in range(rows)]
        self.r = self.c = 0
        self.pending = b""

    def feed(self, data):
        data = self.pending + data
        self.pending = b""
        i = 0
        while i < len(data):
            if data[i] == 0x1b:
                m = re.match(rb"\x1b\[([0-9;?]*)([A-Za-z])", data[i:])
                if not m:
                    if len(data) - i < 16:
                        self.pending = data[i:]
                        return
                    i += 1
                    continue
                if m.group(2) == b"H":
                    parts = [int(x) if x else 1 for x in m.group(1).split(b";")] if m.group(1) else [1, 1]
                    self.r, self.c = parts[0] - 1, (parts[1] if len(parts) > 1 else 1) - 1
                elif m.group(2) == b"J" and m.group(1) in (b"2", b""):
                    self.grid = [[" "] * self.cols for _ in range(self.rows)]
                i += len(m.group(0))
                continue
            b = data[i]
            n = 1 if b < 0x80 else 2 if b >> 5 == 6 else 3 if b >> 4 == 14 else 4
            if i + n > len(data):
                self.pending = data[i:]
                return
            ch = data[i:i + n].decode("utf-8", "replace")
            i += n
            if ch in "\r\n":
                continue
            if 0 <= self.r < self.rows and 0 <= self.c < self.cols:
                self.grid[self.r][self.c] = ch
            self.c += 1

    def text(self):
        return "\n".join("".join(row) for row in self.grid)


SCREENS = {}


def read_until(fd, pattern, timeout=40):
    scr = SCREENS.setdefault(fd, Screen())
    end = time.time() + timeout
    pat = pattern.decode() if isinstance(pattern, bytes) else pattern
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.2)
        if r:
            try:
                scr.feed(os.read(fd, 65536))
            except OSError:
                break
        m = re.search(pat, scr.text())
        if m:
            return m, scr.text()
    raise SystemExit(f"timeout waiting for {pat!r}; screen:\n{scr.text()}")


with tempfile.TemporaryDirectory() as w:
    src, dst = os.path.join(w, "src"), os.path.join(w, "dst")
    os.makedirs(src); os.makedirs(dst)
    f = os.path.join(src, "dropped file.txt")
    open(f, "w").write("dropped via tui\n")

    # 1) CLI receiver, TUI sender
    rx = subprocess.Popen([BIN, "receive"], cwd=dst, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    line = b""
    while not CODE_RE.search(line):
        line += rx.stdout.readline()
    code = CODE_RE.search(line).group(1).decode()
    pid, fd = spawn_tui(["send", code], src)
    read_until(fd, rb"Files to send")
    os.write(fd, b"\x1b[200~" + f.replace(" ", "\\ ").encode() + b" \x1b[201~")
    read_until(fd, r"dropped file\.txt\s+16 B")
    os.write(fd, b"\r")
    read_until(fd, rb"Sent 1 file")
    os.write(fd, b"q")
    os.waitpid(pid, 0)
    rx.wait(timeout=20)
    assert open(os.path.join(dst, "dropped file.txt")).read() == "dropped via tui\n"
    print("TUI send: OK")

    # 2) TUI receiver, CLI sender
    dst2 = os.path.join(w, "dst2"); os.makedirs(dst2)
    pid, fd = spawn_tui([], dst2)
    read_until(fd, rb"Receive files")
    os.write(fd, b"\r")
    m, _ = read_until(fd, rb"wormhole send (\d+-[a-z]+-[a-z]+)")
    code = m.group(1)
    out = subprocess.run([BIN, "send", code, f], capture_output=True, timeout=60)
    assert out.returncode == 0, out
    read_until(fd, rb"Received 1 file")
    os.write(fd, b"q")
    os.waitpid(pid, 0)
    assert open(os.path.join(dst2, "dropped file.txt")).read() == "dropped via tui\n"
    print("TUI receive: OK")
