/* Turning a terminal transcript into the lines a person saw.

   A transcript is the bytes the device printed, and those are not text: they
   are instructions to a terminal. A shell edits the line in place — a
   backspace is "\b \b", a character inserted mid-line is a cursor move and an
   insert-character sequence, a recalled history entry is the old line erased
   and redrawn — and a line longer than the terminal is wrapped by the terminal,
   with the shell moving the cursor by rows on the assumption that it did. Read
   as a stream of characters, the transcript shows commands that were never run:
   "echo hello world" typed with a correction comes out "echo hello", and a long
   command overwrites its own prompt.

   So the bytes are played through a model of the terminal, at the size it had
   at each point in the session, and what scrolls off its top is the
   transcript — exactly a terminal's scrollback. Two departures, both so that
   nothing shown is lost from the evidence:

   - Clearing the screen (`clear`, Ctrl-L) keeps what was on it. A terminal
     throws it away; a transcript must not.
   - A full-screen program (vi, less, top) draws on a separate screen that the
     shell's comes back from unchanged. What it showed is kept as a block,
     marked as such, after the line that started it: the lines it scrolled
     through and its last screen. Its cursor-addressed redraws cannot be laid out
     as a scrolling log; the video recording, where there is one, has those. */

export interface TranscriptLine {
  text: string;
  /** Set on the rows that bracket what a full-screen program showed. */
  marker?: "fullscreen-start" | "fullscreen-end";
}

export interface TranscriptManifestLike {
  cols: number;
  rows: number;
  chunks: { offset_ms: number; len: number }[];
  resizes?: { at: number; cols: number; rows: number }[];
  initial_cols?: number;
  initial_rows?: number;
}

export interface RenderedTranscript {
  lines: TranscriptLine[];
  /** The line the cursor was on once each manifest chunk had been applied. */
  chunkLine: number[];
}

const WIDE_TAIL = "\u0000";
const MAX_STRING = 4096;

const St = { Ground: 0, Esc: 1, EscInter: 2, CSI: 3, OSC: 4, Str: 5 } as const;

export function charWidth(cp: number): number {
  if (cp === 0x200b || cp === 0x200c || cp === 0x200d || cp === 0xfeff) return 0;
  if ((cp >= 0x300 && cp <= 0x36f) || (cp >= 0x1ab0 && cp <= 0x1aff) || (cp >= 0x20d0 && cp <= 0x20ff) || (cp >= 0xfe20 && cp <= 0xfe2f))
    return 0;
  if (
    (cp >= 0x1100 && cp <= 0x115f) ||
    (cp >= 0x2e80 && cp <= 0x303e) ||
    (cp >= 0x3041 && cp <= 0x33ff) ||
    (cp >= 0x3400 && cp <= 0x4dbf) ||
    (cp >= 0x4e00 && cp <= 0x9fff) ||
    (cp >= 0xa000 && cp <= 0xa4cf) ||
    (cp >= 0xac00 && cp <= 0xd7a3) ||
    (cp >= 0xf900 && cp <= 0xfaff) ||
    (cp >= 0xfe30 && cp <= 0xfe4f) ||
    (cp >= 0xff00 && cp <= 0xff60) ||
    (cp >= 0xffe0 && cp <= 0xffe6) ||
    (cp >= 0x1f300 && cp <= 0x1f64f) ||
    (cp >= 0x1f900 && cp <= 0x1f9ff) ||
    (cp >= 0x20000 && cp <= 0x3fffd)
  )
    return 2;
  return 1;
}

function blankRow(cols: number): string[] {
  return new Array<string>(cols).fill("");
}

function rowText(row: string[]): string {
  let s = "";
  for (const c of row) {
    if (c === WIDE_TAIL) continue;
    s += c === "" ? " " : c;
  }
  return s.trimEnd();
}

class Terminal {
  cols: number;
  rows: number;
  grid: string[][];
  x = 0;
  y = 0;
  wrapNext = false;
  autowrap = true;
  insert = false;
  top = 0;
  bot: number;
  savedX = 0;
  savedY = 0;

  /** Rows that have left the shell's screen, in order: the transcript. */
  history: string[] = [];
  /** What full-screen programs showed, each placed before an absolute row: the
   *  one the cursor was on when the program started, which is where the shell's
   *  output resumes once it exits. */
  blocks: { before: number; lines: string[] }[] = [];

  alt = false;
  main: string[][] | null = null;
  mainX = 0;
  mainY = 0;
  mainSavedX = 0;
  mainSavedY = 0;
  block: { before: number; lines: string[] } | null = null;

  state: number = St.Ground;
  params = "";
  priv = "";
  inter = "";
  strEsc = false;
  strLen = 0;

  constructor(cols: number, rows: number) {
    this.cols = Math.max(2, cols);
    this.rows = Math.max(1, rows);
    this.bot = this.rows - 1;
    this.grid = Array.from({ length: this.rows }, () => blankRow(this.cols));
  }

  /** The cursor's row counted from the start of the session. */
  absRow(): number {
    return this.alt && this.block ? this.block.before : this.history.length + this.y;
  }

  resize(cols: number, rows: number) {
    cols = Math.max(2, cols);
    rows = Math.max(1, rows);
    const regrid = (g: string[][], y: number, keepLost: boolean): [string[][], number] => {
      // Fewer rows: the top ones leave, as a terminal scrolls them off.
      let shift = 0;
      if (y >= rows) shift = y - rows + 1;
      if (keepLost) for (let i = 0; i < shift; i++) this.history.push(rowText(g[i]));
      const out: string[][] = [];
      for (let r = 0; r < rows; r++) {
        const src = g[r + shift];
        const row = blankRow(cols);
        if (src) for (let c = 0; c < Math.min(cols, src.length); c++) row[c] = src[c];
        if (src && cols < src.length && src[cols] === WIDE_TAIL) row[cols - 1] = "";
        out.push(row);
      }
      return [out, Math.min(y - shift, rows - 1)];
    };
    if (this.alt && this.main) {
      [this.grid, this.y] = regrid(this.grid, this.y, false);
      [this.main, this.mainY] = regrid(this.main, this.mainY, true);
    } else {
      [this.grid, this.y] = regrid(this.grid, this.y, true);
    }
    this.cols = cols;
    this.rows = rows;
    this.x = Math.min(this.x, cols - 1);
    this.top = 0;
    this.bot = rows - 1;
    this.wrapNext = false;
  }

  write(s: string) {
    for (const ch of s) {
      const cp = ch.codePointAt(0) as number;
      switch (this.state) {
        case St.Ground:
          this.ground(ch, cp);
          break;
        case St.Esc:
          this.esc(ch);
          break;
        case St.EscInter:
          this.state = St.Ground;
          break;
        case St.CSI:
          if (cp >= 0x30 && cp <= 0x3f) {
            if ("?><=".includes(ch) && this.params === "") this.priv = ch;
            else if (this.params.length < 64) this.params += ch;
          } else if (cp >= 0x20 && cp <= 0x2f) this.inter = ch;
          else if (cp >= 0x40 && cp <= 0x7e) {
            this.state = St.Ground;
            this.csi(ch);
          } else if (cp === 0x1b) this.state = St.Esc;
          else if (cp === 0x18 || cp === 0x1a) this.state = St.Ground;
          else this.ground(ch, cp);
          break;
        case St.OSC:
        case St.Str:
          this.strLen++;
          if (cp === 0x07 && this.state === St.OSC) this.state = St.Ground;
          else if (this.strEsc && ch === "\\") this.state = St.Ground;
          else if (this.strLen > MAX_STRING) this.state = St.Ground;
          this.strEsc = cp === 0x1b;
          break;
      }
    }
  }

  ground(ch: string, cp: number) {
    switch (cp) {
      case 0x1b:
        this.state = St.Esc;
        return;
      case 0x0d:
        this.x = 0;
        this.wrapNext = false;
        return;
      case 0x0a:
      case 0x0b:
      case 0x0c:
        this.index();
        return;
      case 0x08:
        if (this.wrapNext) this.wrapNext = false;
        else if (this.x > 0) this.x--;
        return;
      case 0x09:
        this.x = Math.min(this.cols - 1, (Math.floor(this.x / 8) + 1) * 8);
        this.wrapNext = false;
        return;
    }
    // Other C0 and C1 controls draw nothing.
    if (cp < 0x20 || cp === 0x7f || (cp >= 0x80 && cp < 0xa0)) return;
    this.put(ch, cp);
  }

  esc(ch: string) {
    this.state = St.Ground;
    switch (ch) {
      case "[":
        this.state = St.CSI;
        this.params = "";
        this.priv = "";
        this.inter = "";
        return;
      case "]":
        this.state = St.OSC;
        this.strEsc = false;
        this.strLen = 0;
        return;
      case "P":
      case "X":
      case "^":
      case "_":
        this.state = St.Str;
        this.strEsc = false;
        this.strLen = 0;
        return;
      case "(":
      case ")":
      case "*":
      case "+":
      case "-":
      case ".":
      case "/":
      case "#":
      case "%":
      case " ":
        this.state = St.EscInter;
        return;
      case "7":
        this.savedX = this.x;
        this.savedY = this.y;
        return;
      case "8":
        this.x = Math.min(this.savedX, this.cols - 1);
        this.y = Math.min(this.savedY, this.rows - 1);
        this.wrapNext = false;
        return;
      case "D":
        this.index();
        return;
      case "E":
        this.x = 0;
        this.index();
        return;
      case "M":
        this.wrapNext = false;
        if (this.y === this.top) this.scrollDown(this.top, 1);
        else if (this.y > 0) this.y--;
        return;
      case "c":
        this.keepScreen();
        this.x = this.y = 0;
        this.top = 0;
        this.bot = this.rows - 1;
        this.autowrap = true;
        this.insert = false;
        return;
    }
  }

  index() {
    this.wrapNext = false;
    if (this.y === this.bot) this.scrollUp(this.top, 1);
    else if (this.y < this.rows - 1) this.y++;
  }

  put(ch: string, cp: number) {
    const w = charWidth(cp);
    if (w === 0) return;
    if (this.wrapNext && this.autowrap) {
      this.x = 0;
      this.index();
    }
    this.wrapNext = false;
    if (w === 2 && this.x === this.cols - 1) {
      if (!this.autowrap) return;
      this.grid[this.y][this.x] = "";
      this.x = 0;
      this.index();
    }
    const row = this.grid[this.y];
    if (this.insert) {
      row.splice(this.x, 0, ...new Array<string>(w).fill(""));
      row.length = this.cols;
    }
    this.clearHalf(this.x);
    row[this.x] = ch;
    if (w === 2) {
      this.clearHalf(this.x + 1);
      row[this.x + 1] = WIDE_TAIL;
    }
    this.x += w;
    if (this.x >= this.cols) {
      this.x = this.cols - 1;
      this.wrapNext = true;
    }
  }

  clearHalf(x: number) {
    const row = this.grid[this.y];
    if (x < 0 || x >= row.length) return;
    if (row[x] === WIDE_TAIL && x > 0) row[x - 1] = "";
    if (x + 1 < row.length && row[x + 1] === WIDE_TAIL) row[x + 1] = "";
  }

  param(i: number, def: number): number {
    const v = this.params.split(/[;:]/)[i];
    const n = v === undefined || v === "" ? 0 : Math.min(parseInt(v, 10) || 0, 1 << 16);
    return n === 0 ? def : n;
  }

  csi(final: string) {
    if (this.inter) return;
    if (this.priv) {
      if (this.priv === "?" && (final === "h" || final === "l")) this.privateModes(final === "h");
      return;
    }
    const n = this.param(0, 1);
    const clampY = (v: number) => Math.max(0, Math.min(v, this.rows - 1));
    const row = this.grid[this.y];
    switch (final) {
      case "A":
        this.y = Math.max(this.y >= this.top ? this.top : 0, this.y - n);
        break;
      case "B":
      case "e":
        this.y = Math.min(this.y <= this.bot ? this.bot : this.rows - 1, this.y + n);
        break;
      case "C":
      case "a":
        this.x = Math.min(this.cols - 1, this.x + n);
        break;
      case "D":
        this.x = Math.max(0, this.x - n);
        break;
      case "E":
        this.y = clampY(this.y + n);
        this.x = 0;
        break;
      case "F":
        this.y = clampY(this.y - n);
        this.x = 0;
        break;
      case "G":
      case "`":
        this.x = Math.max(0, Math.min(n - 1, this.cols - 1));
        break;
      case "d":
        this.y = clampY(n - 1);
        break;
      case "H":
      case "f":
        this.y = clampY(this.param(0, 1) - 1);
        this.x = Math.max(0, Math.min(this.param(1, 1) - 1, this.cols - 1));
        break;
      case "J":
        this.eraseDisplay(this.param(0, 0));
        break;
      case "K":
        this.eraseLine(this.param(0, 0));
        break;
      case "P": {
        const k = Math.min(n, this.cols - this.x);
        row.splice(this.x, k);
        while (row.length < this.cols) row.push("");
        break;
      }
      case "@": {
        const k = Math.min(n, this.cols - this.x);
        row.splice(this.x, 0, ...new Array<string>(k).fill(""));
        row.length = this.cols;
        break;
      }
      case "X":
        row.fill("", this.x, Math.min(this.cols, this.x + n));
        break;
      case "L":
        if (this.y >= this.top && this.y <= this.bot) {
          this.scrollDown(this.y, n);
          this.x = 0;
        }
        break;
      case "M":
        if (this.y >= this.top && this.y <= this.bot) {
          this.scrollUp(this.y, n, true);
          this.x = 0;
        }
        break;
      case "S":
        this.scrollUp(this.top, n);
        break;
      case "T":
        if (this.params.split(";").length <= 1) this.scrollDown(this.top, n);
        break;
      case "r": {
        const t = this.param(0, 1) - 1;
        const b = this.param(1, this.rows) - 1;
        if (t < b && b < this.rows) {
          this.top = t;
          this.bot = b;
          this.x = this.y = 0;
        }
        break;
      }
      case "s":
        this.savedX = this.x;
        this.savedY = this.y;
        break;
      case "u":
        this.x = Math.min(this.savedX, this.cols - 1);
        this.y = Math.min(this.savedY, this.rows - 1);
        break;
      case "h":
      case "l":
        if (this.param(0, 0) === 4) this.insert = final === "h";
        break;
      default:
        return;
    }
    this.wrapNext = false;
  }

  privateModes(on: boolean) {
    for (const p of this.params.split(";")) {
      const n = parseInt(p, 10);
      if (n === 7) this.autowrap = on;
      else if (n === 1049) {
        if (on) {
          this.savedX = this.x;
          this.savedY = this.y;
        }
        this.setAlt(on);
        if (!on) {
          this.x = Math.min(this.savedX, this.cols - 1);
          this.y = Math.min(this.savedY, this.rows - 1);
        }
      } else if (n === 1047 || n === 47) this.setAlt(on);
    }
  }

  setAlt(on: boolean) {
    if (on === this.alt) return;
    if (on) {
      this.main = this.grid;
      this.mainX = this.x;
      this.mainY = this.y;
      this.mainSavedX = this.savedX;
      this.mainSavedY = this.savedY;
      this.block = { before: this.history.length + this.y, lines: [] };
      this.grid = Array.from({ length: this.rows }, () => blankRow(this.cols));
    } else {
      this.closeBlock();
      this.grid = this.main as string[][];
      this.x = this.mainX;
      this.y = this.mainY;
      this.savedX = this.mainSavedX;
      this.savedY = this.mainSavedY;
      this.main = null;
    }
    this.alt = on;
    this.wrapNext = false;
    this.top = 0;
    this.bot = this.rows - 1;
  }

  /** Ends a full-screen program's block with the screen it left behind. */
  closeBlock() {
    if (!this.block) return;
    const lines = [...this.block.lines, ...this.grid.map(rowText)];
    // A program that starts with the cursor low on the screen scrolls blank rows
    // off the top before its first line; they were never content.
    while (lines.length && lines[0] === "") lines.shift();
    while (lines.length && lines[lines.length - 1] === "") lines.pop();
    if (lines.length) this.blocks.push({ before: this.block.before, lines });
    this.block = null;
  }

  /** Clearing the shell's screen keeps what was on it (see the header). */
  keepScreen() {
    if (this.alt) {
      this.grid = Array.from({ length: this.rows }, () => blankRow(this.cols));
      return;
    }
    let last = -1;
    this.grid.forEach((r, i) => {
      if (rowText(r) !== "") last = i;
    });
    for (let i = 0; i <= last; i++) this.history.push(rowText(this.grid[i]));
    this.grid = Array.from({ length: this.rows }, () => blankRow(this.cols));
  }

  eraseLine(mode: number) {
    const row = this.grid[this.y];
    if (mode === 0) row.fill("", this.x);
    else if (mode === 1) row.fill("", 0, this.x + 1);
    else if (mode === 2) row.fill("");
  }

  eraseDisplay(mode: number) {
    if (mode === 0) {
      this.eraseLine(0);
      for (let y = this.y + 1; y < this.rows; y++) this.grid[y].fill("");
    } else if (mode === 1) {
      for (let y = 0; y < this.y; y++) this.grid[y].fill("");
      this.eraseLine(1);
    } else if (mode === 2) {
      this.keepScreen();
    }
    // 3 clears a terminal's scrollback. The transcript is the scrollback, and
    // the evidence: it stays.
  }

  /** Moves rows from..bot up by n. Rows leaving the top of the whole screen
   *  are kept: the shell's go to the transcript, a full-screen program's to its
   *  block. deleting marks a delete-lines, where the rows are removed, not
   *  scrolled past. */
  scrollUp(from: number, n: number, deleting = false) {
    n = Math.min(n, this.bot - from + 1);
    if (n <= 0) return;
    const out = this.grid.splice(from, n);
    if (from === 0 && !deleting) {
      const kept = out.map(rowText);
      if (this.alt) this.block?.lines.push(...kept);
      else this.history.push(...kept);
    }
    const fresh = Array.from({ length: n }, () => blankRow(this.cols));
    this.grid.splice(this.bot - n + 1, 0, ...fresh);
  }

  scrollDown(from: number, n: number) {
    n = Math.min(n, this.bot - from + 1);
    if (n <= 0) return;
    this.grid.splice(this.bot - n + 1, n);
    this.grid.splice(from, 0, ...Array.from({ length: n }, () => blankRow(this.cols)));
  }

  /** The transcript so far: what scrolled off, then the screen as it stands. */
  finish(): { rows: string[]; blocks: { before: number; lines: string[] }[] } {
    if (this.alt) {
      this.closeBlock();
      this.grid = this.main ?? this.grid;
      this.y = this.mainY;
      this.alt = false;
    }
    const screen = this.grid.map(rowText);
    let last = this.y;
    screen.forEach((r, i) => {
      if (r !== "") last = Math.max(last, i);
    });
    return { rows: [...this.history, ...screen.slice(0, last + 1)], blocks: this.blocks };
  }
}

/** Lays a transcript out as the lines a person saw. */
export function renderTranscript(bytes: Uint8Array, m: TranscriptManifestLike): RenderedTranscript {
  const resizes = m.resizes ?? [];
  // Without a size history every byte is laid out at the last size, which is
  // all an older transcript recorded.
  const t = resizes.length
    ? new Terminal(m.initial_cols || 80, m.initial_rows || 24)
    : new Terminal(m.cols || 80, m.rows || 24);
  const decoder = new TextDecoder("utf-8", { fatal: false });
  const chunkAbs: number[] = [];
  let at = 0;
  let next = 0;
  const chunks = m.chunks?.length ? m.chunks : [{ offset_ms: 0, len: bytes.length }];
  for (const c of chunks) {
    while (next < resizes.length && resizes[next].at <= at) {
      t.resize(resizes[next].cols, resizes[next].rows);
      next++;
    }
    const end = Math.min(bytes.length, at + c.len);
    t.write(decoder.decode(bytes.subarray(at, end), { stream: true }));
    at = end;
    chunkAbs.push(t.absRow());
  }
  // Anything past the index (it should not happen) is still shown.
  if (at < bytes.length) t.write(decoder.decode(bytes.subarray(at), { stream: true }));
  t.write(decoder.decode());
  const { rows, blocks } = t.finish();

  const byAnchor = new Map<number, string[][]>();
  for (const b of blocks) {
    const a = Math.min(b.before, rows.length);
    byAnchor.set(a, [...(byAnchor.get(a) ?? []), b.lines]);
  }
  const lines: TranscriptLine[] = [];
  const display: number[] = [];
  const insertBlocks = (r: number) => {
    for (const block of byAnchor.get(r) ?? []) {
      lines.push({ text: "", marker: "fullscreen-start" });
      for (const l of block) lines.push({ text: l });
      lines.push({ text: "", marker: "fullscreen-end" });
    }
  };
  rows.forEach((text, r) => {
    insertBlocks(r);
    display.push(lines.length);
    lines.push({ text });
  });
  insertBlocks(rows.length);
  const chunkLine = chunkAbs.map((r) => display[Math.min(r, display.length - 1)] ?? 0);
  return { lines, chunkLine };
}
