#!/usr/bin/env python3
"""Analyze an Erlang crash dump (erl_crash.dump) and diagnose the likely
cause of an out-of-memory (OOM) situation.

The Erlang VM writes a crash dump when it terminates abnormally. When the
node dies because it (or the OS) ran out of memory, the evidence lives in a
handful of places:

  * the "Slogan:" line          - the VM's own reason for dying
  * the "=memory" section       - a breakdown of where memory went
  * the "=proc:" sections       - per-process heap / stack / msg-queue size
  * the "=ets:" sections        - per-table size

This tool parses those sections and prints:
  * the crash reason and whether it looks like an OOM
  * the global memory breakdown
  * the top memory-consuming processes (heap + old-heap + msg queue)
  * the top memory-consuming ETS tables
  * a plain-language diagnosis

It can also inspect a single process - dumping its mailbox (last N messages)
and/or its stacktrace - which is handy when a runaway mailbox or a stuck
process is the OOM cause. Both are pulled from one fast, targeted pass: only
the last N message lines are held in memory (a bounded deque), the heap is
loaded lazily for term decoding, stack frames are parsed on the fly, and the
scan stops the moment the requested sections are complete - so it stays fast
and flat-memory even on multi-GB dumps with multi-million-entry mailboxes.

Usage:
    # OOM report (default)
    analyze_crash_dump.py [erl_crash.dump] [--top N] [--json] [-v]

    # inspect a process: mailbox + stacktrace (default when neither named)
    analyze_crash_dump.py [erl_crash.dump] -p <0.42.0> [-n N] [--json]

    # just one of them (last N messages, or the first N with --first)
    analyze_crash_dump.py [erl_crash.dump] -p <0.42.0> --messages [-n N] [--first]
    analyze_crash_dump.py [erl_crash.dump] -p <0.42.0> --stack

    # huge process heap? index it once, then decode via DB lookups
    analyze_crash_dump.py [erl_crash.dump] -p <0.42.0> --heap-index

Results are cached in ./.analyze_crash_dump so later runs seek instead of
re-parsing. Running the report first builds the section index; --heap-index
additionally builds a per-process addr->offset index of =proc_heap so message
decoding uses random DB lookups instead of scanning a gigantic heap.

If no path is given, "erl_crash.dump" in the current directory is used.
Pass -v/--verbose to print parsing progress to stderr (useful for the
multi-GB dumps a real OOM produces).
"""

import argparse
import hashlib
import json
import os
import re
import sqlite3
import sys
import time
import urllib.parse


# Set by main() from the --verbose flag. When true, dbg() emits timestamped
# progress to stderr so the (data) output on stdout stays clean/pipeable.
VERBOSE = False
_T0 = None

# Bumped whenever the on-disk index schema or the logic that fills it changes,
# so a stale-format cache from an older script is transparently rebuilt.
FORMAT_VERSION = 1


def dbg(msg):
    """Print a debug line to stderr, prefixed with elapsed wall-clock time."""
    if not VERBOSE:
        return
    elapsed = (time.monotonic() - _T0) if _T0 is not None else 0.0
    print(f"[+{elapsed:7.2f}s] {msg}", file=sys.stderr, flush=True)


def human(nbytes):
    """Format a byte count as a human-readable string."""
    if nbytes is None:
        return "?"
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    v = float(nbytes)
    for u in units:
        if abs(v) < 1024.0 or u == units[-1]:
            return f"{v:.2f} {u}" if u != "B" else f"{int(v)} B"
        v /= 1024.0


def parse_crash_dump(path):
    """Parse a crash dump into a structured dict.

    The dump is a flat text file made of sections that each start with a
    line like "=proc:<0.42.0>". We do a single pass, switching parser state
    on each "=..." header.
    """
    header = None          # slogan / date / system version
    slogan = None
    date = None
    system_version = None
    word_size = 8          # bytes per word; corrected from the version line

    memory = {}            # name -> bytes, from the =memory section
    procs = []             # list of process dicts
    ets = []               # list of ets table dicts

    section = None         # current "=..." section kind
    cur = None             # dict being filled for =proc / =ets

    section_counts = {}    # "=..." kind -> how many seen (for --verbose)

    def flush():
        nonlocal cur, section
        if cur is None:
            return
        if section == "proc":
            procs.append(cur)
        elif section == "ets":
            ets.append(cur)
        cur = None

    try:
        file_size = os.path.getsize(path)
    except OSError:
        file_size = None
    dbg(f"opening {path} ({human(file_size)})")
    # Progress cadence: every 2M lines. Large real dumps run to tens of
    # millions of lines, so a per-line report would itself be the bottleneck.
    PROGRESS_EVERY = 2_000_000
    parse_start = time.monotonic()

    bytes_read = 0         # approximate; f.tell() is illegal mid-iteration
    with open(path, "r", errors="replace") as f:
        lineno = 0
        for line in f:
            lineno += 1
            bytes_read += len(line)
            if VERBOSE and lineno % PROGRESS_EVERY == 0:
                pct = (f"{100.0 * bytes_read / file_size:4.1f}%"
                       if file_size else "  ?  ")
                dbg(f"  parsed {lineno:>12,} lines ({pct}) "
                    f"procs={len(procs):,} ets={len(ets):,}")
            line = line.rstrip("\n")

            # First non-empty content lines carry the header/slogan/date.
            if lineno == 1 and line.startswith("=erl_crash_dump"):
                header = line
                continue

            if line.startswith("="):
                flush()
                if ":" in line:
                    kind, _, ident = line[1:].partition(":")
                else:
                    kind, ident = line[1:], None
                section = kind
                section_counts[kind] = section_counts.get(kind, 0) + 1
                if kind == "proc":
                    cur = {"pid": ident}
                elif kind == "ets":
                    cur = {"id": ident}
                elif kind == "memory":
                    cur = None
                else:
                    cur = None
                continue

            # Pre-section header lines (before the first "=..." after line 1).
            if section is None:
                if line.startswith("Slogan:"):
                    slogan = line.split(":", 1)[1].strip()
                elif re.match(r"^[A-Z][a-z]{2} [A-Z][a-z]{2} ", line):
                    # e.g. "Wed Jul 23 10:11:12 2026"
                    date = date or line.strip()
                elif "Erlang" in line and "version" in line.lower():
                    system_version = re.sub(r"^System version:\s*", "",
                                             line.strip())
                    if "[64-bit]" in line:
                        word_size = 8
                    elif "[32-bit]" in line:
                        word_size = 4
                    dbg(f"  system version: {system_version} "
                        f"(word size {word_size} bytes)")
                if slogan and "_slogan_logged" not in section_counts:
                    section_counts["_slogan_logged"] = 1
                    dbg(f"  slogan: {slogan}")
                continue

            if section == "memory":
                m = re.match(r"^(\S+):\s*(\d+)", line)
                if m:
                    memory[m.group(1)] = int(m.group(2))
                continue

            if section in ("proc", "ets") and cur is not None:
                if ":" in line:
                    key, _, val = line.partition(":")
                    cur[key.strip()] = val.strip()
                continue

        flush()

    parse_secs = time.monotonic() - parse_start
    dbg(f"parsed {lineno:,} lines in {parse_secs:.2f}s "
        f"({lineno / parse_secs:,.0f} lines/s)" if parse_secs > 0 else
        f"parsed {lineno:,} lines")
    if VERBOSE:
        interesting = {k: v for k, v in section_counts.items()
                       if not k.startswith("_")}
        summary = ", ".join(f"{k}={v:,}" for k, v in
                            sorted(interesting.items(),
                                   key=lambda kv: kv[1], reverse=True))
        dbg(f"  sections: {summary}")
        dbg(f"  extracted procs={len(procs):,} ets={len(ets):,} "
            f"memory_keys={len(memory)}")

    return {
        "path": path,
        "header": header,
        "slogan": slogan,
        "date": date,
        "system_version": system_version,
        "word_size": word_size,
        "memory": memory,
        "procs": procs,
        "ets": ets,
    }


def _int(val):
    if val is None:
        return None
    m = re.match(r"\s*(\d+)", str(val))
    return int(m.group(1)) if m else None


def proc_memory(p, word_size):
    """Best estimate of a process's memory footprint in bytes.

    Newer dumps have a direct "Memory:" field in bytes. Older dumps only
    give word counts for Stack+heap / OldHeap, so we convert those.
    """
    mem = _int(p.get("Memory"))
    if mem is not None:
        return mem
    words = 0
    for field in ("Stack+heap", "OldHeap", "Heap unused", "OldHeap unused"):
        w = _int(p.get(field))
        if w and field in ("Stack+heap", "OldHeap"):
            words += w
    return words * word_size


def ets_memory(t, word_size):
    words = _int(t.get("Words"))
    return words * word_size if words is not None else None


# ---------------------------------------------------------------------------
# Mailbox extraction
#
# A process's message queue lives in the "=proc_messages:<pid>" section. Each
# line is one message, encoded in the crash-dump term format, optionally
# followed by ":<seq-trace-token>". Terms reference the process heap, which is
# dumped separately in "=proc_heap:<pid>" as "<hexaddr>:<encoding>" lines.
#
# For very large dumps two things matter:
#   * bounded memory - we keep only the last N message lines (a deque with
#     maxlen), never the whole (possibly multi-million-entry) mailbox;
#   * bounded time    - a single pass over the file with per-line work kept
#     trivial, plus early-exit as soon as the target sections are complete.
# ---------------------------------------------------------------------------

NIL = ("nil",)
_HEXCHARS = set("0123456789abcdefABCDEF")


def normalize_pid(s):
    """Accept <0.42.0>, 0.42.0, or "0.42.0" and return "<0.42.0>"."""
    s = s.strip()
    if not s:
        return s
    if not s.startswith("<"):
        s = "<" + s
    if not s.endswith(">"):
        s = s + ">"
    return s


class TermDecoder:
    """Decoder for the crash-dump term encoding, following the grammar in
    OTP's observer/crashdump_viewer.erl (parse_term / parse_heap_term).

    Key points of that grammar (getting these wrong garbles output):
      * lengths and arities are HEX ("A<hexlen>:...", "t<hexarity>:...");
      * small integers are tagged: "I<decimal>";
      * INLINE positions (tuple elements, list head/tail, message body) only
        ever hold: H pointer, N nil, I int, A atom, P pid, p port, S string,
        D dist-external. Composite terms (tuples, lists, floats, bignums,
        binaries, maps, funs) live on their OWN heap line, reached by an H
        pointer, and are parsed by _boxed().

    The same instance doubles as a pointer collector for reachability: with a
    `collect` set installed, pointers are recorded (not dereferenced), so the
    exact grammar is shared and can't drift between the two uses.
    """

    def __init__(self, heap, max_depth=400, node_budget=2_000_000):
        self.heap = heap                 # lowercased hexaddr -> encoding
        self.max_depth = max_depth
        self.node_budget = node_budget
        self._budget = node_budget
        self._collect = None             # set → record pointers, don't deref

    def decode_message(self, line):
        """Decode one =proc_messages line into (term_string, token_string)."""
        self._budget = self.node_budget
        self._collect = None
        try:
            obj, rest = self._term(line, 0, frozenset())
            token = rest[1:].strip() if rest.startswith(":") else None
            return self._fmt(obj), (token if token and token != "N" else None)
        except Exception:
            # Never let a decode bug hide the raw evidence.
            return None, None

    def collect_term(self, s, out):
        """Record the pointers reachable from an inline term (e.g. a message
        line) into `out`, without dereferencing."""
        self._budget = self.node_budget
        self._collect = out
        try:
            self._term(s, 0, frozenset())
        except Exception:
            pass
        finally:
            self._collect = None

    def collect_boxed(self, enc, out):
        """Record the immediate child pointers of a heap-line encoding."""
        self._budget = self.node_budget
        self._collect = out
        try:
            self._boxed(enc, 0, frozenset())
        except Exception:
            pass
        finally:
            self._collect = None

    # -- helpers -----------------------------------------------------------

    @staticmethod
    def _hex(s):
        """Read a run of hex digits: return (value, hexstr, rest)."""
        j = 0
        while j < len(s) and s[j] in _HEXCHARS:
            j += 1
        h = s[:j]
        return (int(h, 16) if h else 0), h, s[j:]

    @staticmethod
    def _int(s):
        """Read a signed decimal integer: return (int, rest)."""
        j = 1 if s[:1] in ("-", "+") else 0
        while j < len(s) and s[j].isdigit():
            j += 1
        if j == 0 or (j == 1 and s[:1] in ("-", "+")):
            return 0, s
        return int(s[:j]), s[j:]

    @staticmethod
    def _id(s):
        """Parse an id of the form '...<a.b.c>' → ([a,b,c], rest-after-'>')."""
        lt = s.find("<")
        if lt < 0:
            return [], s
        gt = s.find(">", lt + 1)
        if gt < 0:
            return [], s[lt + 1:]
        parts = []
        for p in s[lt + 1:gt].split("."):
            parts.append(int(p) if p.isdigit() else p)
        return parts, s[gt + 1:]

    @staticmethod
    def _token(s):
        j = 0
        while j < len(s) and s[j] not in ",|:":
            j += 1
        return s[:j], s[j:]

    def _deref(self, hexaddr, depth, seen):
        if self._collect is not None:
            self._collect.add(hexaddr.lower())
            return ("ptr", hexaddr)                # collect mode: leaf, no walk
        enc = self.heap.get(hexaddr.lower())
        if enc is None:
            return ("ptr", hexaddr)
        if hexaddr in seen:
            return ("cycle", hexaddr)
        obj, _ = self._boxed(enc, depth + 1, seen | {hexaddr})
        return obj

    # -- parsing (parse_term: inline positions) ----------------------------

    def _term(self, s, depth, seen):
        self._budget -= 1
        if self._budget <= 0 or depth > self.max_depth:
            return ("truncated",), ""
        if not s:
            return ("raw", ""), ""
        c = s[0]
        if c == "H":                              # pointer to a heap term
            _v, h, rest = self._hex(s[1:])
            return self._deref(h, depth, seen), rest
        if c == "N":                              # []
            return NIL, s[1:]
        if c == "I":                              # small integer (decimal)
            val, rest = self._int(s[1:])
            return val, rest
        if c == "A":                              # atom: A<hexlen>:<chars>
            n, _h, rest = self._hex(s[1:])
            if rest.startswith(":"):
                rest = rest[1:]
                return ("atom", rest[:n]), rest[n:]
            return ("atom", ""), rest
        if c == "P":                              # pid: P<a.b.c>
            pid, rest = self._id(s[1:])
            return ("pid", pid), rest
        if c == "p":                              # port: p<a.b>
            port, rest = self._id(s[1:])
            return ("port", port), rest
        if c == "S":                              # information string (to EOL)
            return ("str", s[1:]), ""
        if c == "D":                              # dist-external (opaque)
            return ("ext",), ""
        tok, rest = self._token(s)                # unexpected → opaque token
        return ("raw", tok), rest

    # -- parsing (parse_heap_term: one whole heap line) --------------------

    def _boxed(self, enc, depth, seen):
        self._budget -= 1
        if self._budget <= 0 or depth > self.max_depth:
            return ("truncated",), ""
        if not enc:
            return ("raw", ""), ""
        two = enc[:2]
        c = enc[0]
        if c == "l":                              # cons cell
            if self._collect is not None:
                head, rest = self._term(enc[1:], depth + 1, seen)
                if rest.startswith("|"):
                    rest = rest[1:]
                self._term(rest, depth + 1, seen)
                return ("cons", head, None), ""
            return self._decode_list(enc, depth, seen), ""
        if c == "t":                              # tuple: t<hexarity>:e,e,...
            n, _h, rest = self._hex(enc[1:])
            if rest.startswith(":"):
                rest = rest[1:]
            elems = []
            for _ in range(n):
                obj, rest = self._term(rest, depth + 1, seen)
                elems.append(obj)
                if rest.startswith(","):
                    rest = rest[1:]
            return ("tuple", elems), rest
        if c == "F":                              # float: F<hexlen>:<chars>
            n, _h, rest = self._hex(enc[1:])
            if rest.startswith(":"):
                rest = rest[1:]
            chars = rest[:n]
            try:
                return float(chars), rest[n:]
            except ValueError:
                return ("raw", chars), rest[n:]
        if enc.startswith("B16#"):                # positive bignum (hex)
            v, _h, rest = self._hex(enc[4:])
            return v, rest
        if enc.startswith("B-16#"):               # negative bignum (hex)
            v, _h, rest = self._hex(enc[5:])
            return -v, rest
        if c == "B":                              # decimal bignum
            val, rest = self._int(enc[1:])
            return val, rest
        if c == "P":                              # external pid
            pid, rest = self._id(enc[1:])
            return ("pid", pid), rest
        if c == "p":                              # external port
            port, rest = self._id(enc[1:])
            return ("port", port), rest
        if c == "E":                              # external-format term (opaque)
            return ("ext",), ""
        if two in ("Yh", "Yc", "Ys"):             # binaries (contents opaque)
            return ("bin",), ""
        if two == "Mf":                           # flatmap: Mf<hexN>:<keys>:<vals>
            n, _h, rest = self._hex(enc[2:])
            if rest.startswith(":"):
                rest = rest[1:]
            keys, rest = self._term(rest, depth + 1, seen)
            if rest.startswith(":"):
                rest = rest[1:]
            vals = []
            for _ in range(n):
                v, rest = self._term(rest, depth + 1, seen)
                vals.append(v)
                if rest.startswith(","):
                    rest = rest[1:]
            return ("map", keys, vals), rest
        if two in ("Mh", "Mn"):                   # hashmap nodes (opaque)
            return ("map",), ""
        if two == "Rf":                           # fun reference
            return ("fun",), ""
        tok, rest = self._token(enc)
        return ("raw", tok), rest

    def _decode_list(self, enc, depth, seen):
        """Decode a cons chain iteratively (a proper list may be very long, so
        following the tail by recursion would blow the Python stack)."""
        items = []
        tail = NIL
        while True:
            self._budget -= 1
            if self._budget <= 0 or len(items) >= 1_000_000:
                tail = ("truncated",)
                break
            head, r = self._term(enc[1:], depth + 1, seen)
            items.append(head)
            if r.startswith("|"):
                r = r[1:]
            if r.startswith("H"):                 # tail is a pointer
                _v, h, _r2 = self._hex(r[1:])
                nxt = self.heap.get(h.lower())
                if nxt is not None and nxt[:1] == "l" and h not in seen:
                    seen = seen | {h}
                    enc = nxt
                    continue                      # walk to next cons cell
                tail = self._deref(h, depth + 1, seen)
                break
            if r.startswith("N") or r == "":      # proper list end
                tail = NIL
                break
            tail, _r = self._term(r, depth + 1, seen)   # improper tail
            break
        return ("list", items, tail)

    # -- formatting --------------------------------------------------------

    def _fmt(self, obj):
        if obj is NIL or obj == NIL:
            return "[]"
        if isinstance(obj, bool):
            return "true" if obj else "false"
        if isinstance(obj, int):
            return str(obj)
        if isinstance(obj, float):
            return repr(obj)
        tag = obj[0]
        if tag == "atom":
            return self._fmt_atom(obj[1])
        if tag == "pid":
            return "<" + ".".join(str(x) for x in obj[1]) + ">"
        if tag == "port":
            return "#Port<" + ".".join(str(x) for x in obj[1]) + ">"
        if tag == "tuple":
            return "{" + ",".join(self._fmt(e) for e in obj[1]) + "}"
        if tag == "list":
            return self._fmt_list(obj)
        if tag == "cons":
            return "[" + self._fmt(obj[1]) + "|...]"
        if tag == "str":
            return '"' + obj[1] + '"'
        if tag == "bin":
            return "<<...>>"
        if tag == "map":
            if len(obj) == 3 and isinstance(obj[1], tuple) \
                    and obj[1][0] == "tuple" and len(obj[1][1]) == len(obj[2]):
                pairs = [self._fmt(k) + " => " + self._fmt(v)
                         for k, v in zip(obj[1][1], obj[2])]
                return "#{" + ",".join(pairs) + "}"
            return "#{...}"
        if tag == "ext":
            return "#Encoded"
        if tag == "fun":
            return "#Fun<...>"
        if tag == "ptr":
            return "#ref@" + obj[1]
        if tag == "cycle":
            return "#cycle@" + obj[1]
        if tag == "truncated":
            return "..."
        return obj[1] if len(obj) > 1 and obj[1] else "?"

    def _fmt_list(self, obj):
        elems, tail = obj[1], obj[2]
        # Render a proper list of printable byte values as a string, matching
        # how the Erlang shell displays such lists.
        if (tail is NIL or tail == NIL) and elems and \
                all(isinstance(e, int) and (32 <= e <= 126 or e in (9, 10, 13))
                    for e in elems):
            s = "".join(chr(e) for e in elems)
            return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'
        items = [self._fmt(e) for e in elems]
        if tail is NIL or tail == NIL:
            return "[" + ",".join(items) + "]"
        return "[" + ",".join(items) + "|" + self._fmt(tail) + "]"

    @staticmethod
    def _fmt_atom(name):
        if re.match(r"^[a-z][a-zA-Z0-9_@]*$", name):
            return name
        return "'" + name.replace("\\", "\\\\").replace("'", "\\'") + "'"


# A stack line carries a frame when it names a "Module:Function/Arity + Offset"
# (return addresses, catch frames, the program counter). Matched permissively
# so it survives cosmetic format differences between OTP versions.
_FRAME_RE = re.compile(r"\(([^()]*?:[^()]*?/\d+)\s*\+\s*(\d+)\)")

# Guard: a pathological stack could in theory be enormous; cap what we retain.
_STACK_LINE_CAP = 1_000_000


def _frame_kind(line):
    low = line.lower()
    if "catch" in low:
        return "catch"
    if "return" in low:
        return "return"
    return "frame"


def parse_stack_line(line):
    """Extract any call frames named on a =proc_stack line."""
    out = []
    kind = _frame_kind(line)
    for m in _FRAME_RE.finditer(line):
        out.append({"func": m.group(1).strip(),
                    "offset": int(m.group(2)),
                    "kind": kind})
    return out


# A shared decoder instance used only in pointer-collect mode (heap unused),
# so reachability and decoding walk the exact same grammar.
_COLLECTOR = TermDecoder({})


def collect_pointers_term(s, out):
    """Collect heap pointers referenced by an inline term (e.g. a message
    line), following crashdump_viewer's parse_term grammar."""
    _COLLECTOR.collect_term(s, out)


def collect_pointers_boxed(enc, out):
    """Collect the immediate child pointers of a heap-line encoding
    (parse_heap_term grammar)."""
    _COLLECTOR.collect_boxed(enc, out)


def resolve_reachable_heap(path, ranges, seed, want_max, max_passes=200):
    """Resolve only the heap subgraph reachable from `seed` addresses.

    `ranges` is a list of [start, end) byte ranges to search - typically the
    process's =proc_heap plus the global =literals pool, since message terms
    can point into either. Each pass re-reads those ranges (in binary, so
    offsets are exact), expanding the frontier of wanted addresses until it
    closes or a bound is hit. Because we follow only what the messages
    reference, the resolved map stays small no matter how large the heap is.

    Returns (resolved: {addr: enc}, truncated: bool, passes: int).
    """
    resolved = {}
    pending = set(a for a in seed if a)
    truncated = False
    passes = 0
    ranges = [(s, e) for (s, e) in ranges if s is not None and e is not None]

    dbg(f"  reachability: seeding {len(pending)} address(es) over "
        f"{len(ranges)} range(s)")

    with open(path, "rb") as g:
        while pending and passes < max_passes and len(resolved) < want_max:
            passes += 1
            found_this_pass = 0
            # Live frontier: addresses discovered mid-pass are resolved too if
            # they appear later, so monotonic layouts close in a single pass.
            for start_off, end_off in ranges:
                if not pending:
                    break
                g.seek(start_off)
                pos = start_off
                for raw in g:
                    if pos >= end_off:
                        break
                    pos += len(raw)
                    if not pending:
                        break
                    ci = raw.find(b":")
                    if ci <= 0:
                        continue
                    addr = raw[:ci].strip().lower().decode("latin-1")
                    if addr not in pending or addr in resolved:
                        continue
                    enc = raw[ci + 1:].rstrip(b"\r\n").decode("latin-1")
                    resolved[addr] = enc
                    pending.discard(addr)
                    found_this_pass += 1
                    refs = set()
                    collect_pointers_boxed(enc, refs)
                    for r in refs:
                        if r and r not in resolved:
                            pending.add(r)
                    if len(resolved) >= want_max:
                        break
            dbg(f"    pass {passes}: resolved {found_this_pass} "
                f"(total {len(resolved):,}, pending {len(pending):,})")
            if found_this_pass == 0:
                break                                  # nothing more to find

    if pending or len(resolved) >= want_max:
        truncated = True
    return resolved, truncated, passes


def resolve_reachable_heap_db(conn, path, seed, want_max):
    """Resolve the reachable heap subgraph using an addr->offset index.

    A breadth-first walk from the seed addresses: for each address look up its
    byte offset in the DB, seek to that line in the dump, read its encoding,
    and enqueue the pointers it references. Touches only the reachable
    subgraph - no scanning of the (possibly gigantic) heap section, so cost is
    O(reachable nodes) regardless of total heap size.

    Returns (resolved: {addr: enc}, truncated: bool).
    """
    resolved = {}
    queue = [a for a in seed if a]
    seen = set(queue)
    truncated = False
    cur = conn.cursor()

    with open(path, "rb") as f:
        i = 0
        while i < len(queue):
            if len(resolved) >= want_max:
                truncated = True
                break
            addr = queue[i]
            i += 1
            try:
                key = int(addr, 16)
            except ValueError:
                continue
            row = cur.execute("SELECT off FROM heap WHERE addr=?",
                              (key,)).fetchone()
            if row is None:
                continue                              # dangling ref → #ref@addr
            f.seek(row[0])
            line = f.readline().rstrip(b"\r\n").decode("latin-1")
            _, sep, enc = line.partition(":")
            if not sep:
                continue
            resolved[addr] = enc
            refs = set()
            collect_pointers_boxed(enc, refs)
            for r in refs:
                if r and r not in seen:
                    seen.add(r)
                    queue.append(r)
    return resolved, truncated


def heap_index_path(cache_dir, path, pid):
    ph = hashlib.sha1(pid.encode("utf-8", "surrogatepass")).hexdigest()[:8]
    return os.path.join(cache_dir, cache_key(path) + f".heap-{ph}.sqlite")


def _ranges_sig(ranges):
    return ",".join(f"{s}-{e}" for s, e in ranges)


def build_heap_index(path, ranges, db_path, max_entries=0):
    """Scan the given [start,end) byte ranges (=proc_heap + =literals) once,
    writing an addr->offset SQLite index (atomic temp + rename). Returns
    (n_entries, capped)."""
    st = os.stat(path)
    tmp = os.path.join(os.path.dirname(db_path) or ".",
                       f".{os.path.basename(db_path)}.{os.getpid()}.tmp")
    total = sum(e - s for s, e in ranges)
    dbg(f"  building heap-index → {tmp} "
        f"({len(ranges)} range(s), {human(total)})")
    build_start = time.monotonic()

    conn = sqlite3.connect(tmp)
    ok = False
    n = 0
    capped = False
    try:
        conn.execute("PRAGMA synchronous=OFF")
        conn.execute("PRAGMA journal_mode=OFF")
        conn.execute("CREATE TABLE heap (addr INTEGER PRIMARY KEY, "
                     "off INTEGER) WITHOUT ROWID")
        conn.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT)")
        rows = []
        with open(path, "rb") as f:
            for start, end in ranges:
                if capped:
                    break
                f.seek(start)
                pos = start
                for raw in f:
                    if pos >= end:
                        break
                    line_start = pos
                    pos += len(raw)
                    ci = raw.find(b":")
                    if ci <= 0:
                        continue
                    try:
                        addr = int(raw[:ci].strip(), 16)
                    except ValueError:
                        continue
                    rows.append((addr, line_start))
                    n += 1
                    if len(rows) >= 50000:
                        conn.executemany(
                            "INSERT OR IGNORE INTO heap VALUES (?,?)", rows)
                        rows.clear()
                        if VERBOSE and n % 2_000_000 == 0:
                            dbg(f"    heap-indexed {n:,} entries")
                    if max_entries and n >= max_entries:
                        capped = True
                        break
        if rows:
            conn.executemany("INSERT OR IGNORE INTO heap VALUES (?,?)", rows)
        conn.executemany("INSERT INTO meta VALUES (?,?)", [
            ("src_size", str(st.st_size)),
            ("src_mtime_ns", str(st.st_mtime_ns)),
            ("format_version", str(FORMAT_VERSION)),
            ("ranges", _ranges_sig(ranges)),
            ("entries", str(n)),
            ("capped", "1" if capped else "0"),
        ])
        conn.commit()
        conn.close()
        os.replace(tmp, db_path)
        ok = True
    finally:
        if not ok:
            try:
                conn.close()
            except Exception:
                pass
            try:
                os.unlink(tmp)
            except OSError:
                pass

    dbg(f"  heap-index built: {n:,} entries"
        f"{' (capped)' if capped else ''} in "
        f"{time.monotonic() - build_start:.2f}s")
    return n, capped


def open_heap_index_ro(db_path, src_path, ranges):
    """Open a heap index read-only and validate it against the source file and
    the expected heap ranges. Returns a connection or None."""
    if not os.path.exists(db_path):
        return None
    conn = None
    try:
        uri = ("file:" + urllib.parse.quote(os.path.abspath(db_path))
               + "?mode=ro&immutable=1")
        conn = sqlite3.connect(uri, uri=True)
        meta = dict(conn.execute("SELECT key, value FROM meta").fetchall())
    except sqlite3.Error as e:
        dbg(f"  heap-index unreadable ({e}); treating as miss")
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
        return None
    try:
        st = os.stat(src_path)
    except OSError:
        conn.close()
        return None
    if (meta.get("format_version") != str(FORMAT_VERSION)
            or meta.get("src_size") != str(st.st_size)
            or meta.get("src_mtime_ns") != str(st.st_mtime_ns)
            or meta.get("ranges") != _ranges_sig(ranges)):
        dbg("  heap-index stale")
        conn.close()
        return None
    if meta.get("capped") == "1":
        dbg("  heap-index is capped (--max-heap-index-entries); some addresses "
            "may be unresolved")
    return conn


def get_or_build_heap_index(path, cache_dir, pid, ranges,
                            reindex=False, max_entries=0):
    """Return a read-only conn to a fresh per-process heap index, building it
    on first use. Returns None if caching is unavailable."""
    if not ensure_cache_dir(cache_dir):
        return None
    db_path = heap_index_path(cache_dir, path, pid)
    if not reindex:
        conn = open_heap_index_ro(db_path, path, ranges)
        if conn is not None:
            dbg(f"  heap-index hit: {db_path}")
            return conn
        dbg("  heap-index miss: building")
    else:
        dbg("  --reindex: rebuilding heap-index")
    try:
        build_heap_index(path, ranges, db_path, max_entries)
    except (OSError, sqlite3.Error) as e:
        dbg(f"  heap-index build failed ({e}); scanning instead")
        return None
    return open_heap_index_ro(db_path, path, ranges)


def extract_process(path, pid, want_messages=True, want_stack=True,
                    n=10, first=False, decode=True, max_heap_entries=5_000_000,
                    max_heap_passes=200, heap_index=False, cache_dir=None,
                    reindex=False, max_heap_index_entries=0):
    """Extract a process's mailbox and/or stacktrace in a single fast pass.

    Both are pulled from the same scan, so asking for messages + stack costs
    one traversal, not two. Everything stays targeted at `pid`:
      * only the last `n` message lines are retained (deque maxlen);
      * for decoding, we do NOT load the whole process heap - we record the
        heap section's byte range during the scan, then resolve only the
        subgraph reachable from those N messages. That subgraph is small even
        when the total heap has tens of millions of entries, so decoding the
        last N messages works regardless of process size;
      * stack frames are parsed on the fly (raw lines capped defensively);
      * the scan stops the moment every requested section is complete.
    """
    from collections import deque

    pid = normalize_pid(pid)
    want_proc = b"=proc:" + pid.encode()
    want_msgs = b"=proc_messages:" + pid.encode()
    want_heap = b"=proc_heap:" + pid.encode()
    want_stack_sec = b"=proc_stack:" + pid.encode()
    need_heap = want_messages and decode

    # first N → keep the head (a plain list, filled once); last N → a bounded
    # deque that always holds the most recent n lines.
    msgs = [] if first else deque(maxlen=n)
    proc_info = {}
    stack_frames = []
    stack_raw = []
    heap_start_off = None       # byte range of this process's =proc_heap body
    heap_end_off = None
    lit_start_off = None        # byte range of the global =literals pool
    lit_end_off = None

    in_proc = in_msgs = in_heap = in_stack = in_lit = False
    proc_seen = msgs_exited = heap_exited = stack_exited = lit_exited = False
    stack_overflow = False
    qlen = None

    try:
        file_size = os.path.getsize(path)
    except OSError:
        file_size = None
    parts = ([f"messages(last {n})"] if want_messages else []) + \
            (["stacktrace"] if want_stack else [])
    dbg(f"process: scanning {path} ({human(file_size)}) for {pid}")
    dbg(f"  extracting: {', '.join(parts)}")
    scan_start = time.monotonic()

    def can_stop():
        # Every requested section has been fully read (or provably skippable).
        if want_messages:
            m_ok = msgs_exited or qlen == 0
            # For decode we only need byte ranges (not contents) of =proc_heap
            # and the global =literals pool, since message terms point into
            # either. So we must have passed both before stopping.
            h_ok = (not need_heap) or heap_exited or qlen == 0
            lit_ok = (not need_heap) or lit_exited or qlen == 0
            if not (m_ok and h_ok and lit_ok):
                return False
        if want_stack and not stack_exited:
            return False
        return True

    offset = 0
    lineno = 0
    with open(path, "rb") as f:
        for raw in f:
            lineno += 1
            line_start = offset
            offset += len(raw)
            if VERBOSE and lineno % 2_000_000 == 0:
                pct = (f"{100.0 * offset / file_size:4.1f}%"
                       if file_size else "  ?  ")
                dbg(f"  scanned {lineno:>12,} lines ({pct}) "
                    f"msgs={len(msgs)} frames={len(stack_frames)}")

            if raw.startswith(b"="):
                # Leaving a section: record completion, then maybe early-exit.
                if in_msgs:
                    msgs_exited = True
                if in_heap:
                    heap_exited = True
                    heap_end_off = line_start
                if in_stack:
                    stack_exited = True
                if in_lit:
                    lit_exited = True
                    lit_end_off = line_start
                if in_proc:
                    in_proc = False
                if can_stop():
                    dbg(f"  early exit after line {lineno:,}")
                    break

                body = raw.rstrip(b"\r\n")
                in_proc = body == want_proc
                in_msgs = want_messages and body.startswith(want_msgs)
                in_heap = need_heap and body.startswith(want_heap)
                in_stack = want_stack and body.startswith(want_stack_sec)
                in_lit = need_heap and body == b"=literals"
                if in_proc:
                    proc_seen = True
                if in_heap:
                    heap_start_off = offset      # first heap body byte
                if in_lit:
                    lit_start_off = offset
                continue

            if in_msgs:
                if not first or len(msgs) < n:
                    msgs.append(raw.rstrip(b"\r\n").decode("latin-1"))
            elif in_stack:
                sline = raw.rstrip(b"\r\n").decode("latin-1")
                if len(stack_raw) < _STACK_LINE_CAP:
                    stack_raw.append(sline)
                elif not stack_overflow:
                    stack_overflow = True
                stack_frames.extend(parse_stack_line(sline))
            elif in_proc:
                key, sep, val = raw.decode("latin-1").partition(":")
                if sep:
                    key = key.strip()
                    val = val.strip()
                    if key == "Message queue length":
                        qlen = _int(val)
                        proc_info["msg_queue_length"] = qlen
                    elif key in ("Name", "State", "Spawned as",
                                 "Program counter", "CP", "arity"):
                        proc_info[key] = val
            # =proc_heap / =literals body lines are intentionally skipped
            # here; we only recorded the byte ranges and resolve them below.

        # Close ranges left open at EOF (truncated dump / last section).
        if in_heap and heap_end_off is None:
            heap_end_off = offset
        if in_lit and lit_end_off is None:
            lit_end_off = offset

    scan_secs = time.monotonic() - scan_start
    dbg(f"  scan done: {lineno:,} lines in {scan_secs:.2f}s, "
        f"msgs={len(msgs)} frames={len(stack_frames)}")

    heap_ranges = []
    if want_messages and decode:
        if heap_start_off is not None and heap_end_off is not None:
            heap_ranges.append((heap_start_off, heap_end_off))
        if lit_start_off is not None and lit_end_off is not None:
            heap_ranges.append((lit_start_off, lit_end_off))

    heap_db = None
    if heap_index and cache_dir and heap_ranges:
        heap_db = get_or_build_heap_index(
            path, cache_dir, normalize_pid(pid), heap_ranges,
            reindex=reindex, max_entries=max_heap_index_entries)
    try:
        return assemble_process_result(
            path, pid, proc_seen, qlen, proc_info, msgs, stack_frames,
            stack_raw, stack_overflow, heap_ranges,
            want_messages=want_messages, want_stack=want_stack, decode=decode,
            max_heap_entries=max_heap_entries, max_heap_passes=max_heap_passes,
            heap_db=heap_db, first=first)
    finally:
        if heap_db is not None:
            heap_db.close()


def assemble_process_result(path, pid, proc_seen, qlen, proc_info, msgs,
                            stack_frames, stack_raw, stack_overflow,
                            heap_ranges, want_messages,
                            want_stack, decode, max_heap_entries,
                            max_heap_passes, heap_db=None, first=False):
    """Build the process-inspection result dict from gathered raw materials.

    Shared by the streaming scanner (`extract_process`) and the index-backed
    path (`extract_process_from_index`) so both produce byte-identical output.
    Message decoding resolves only the heap subgraph reachable from the last N
    messages, searching `heap_ranges` (the process =proc_heap plus the global
    =literals pool). If `heap_db` (an addr->offset index over those ranges) is
    supplied, resolution uses random-access DB lookups instead of scanning.
    """
    result = {
        "path": path,
        "pid": pid,
        "found": proc_seen or (qlen is not None) or bool(msgs)
                 or bool(stack_frames),
        "queue_length": qlen,
        "proc": proc_info,
    }

    if want_messages:
        warnings = []
        resolved = {}
        truncated = False
        heap_ranges = [r for r in (heap_ranges or [])
                       if r[0] is not None and r[1] is not None]
        # Seed the reachable set from the addresses the messages point at.
        seed = set()
        for raw in msgs:
            collect_pointers_term(raw, seed)
        if decode and msgs:
            if heap_db is not None:
                resolved, truncated = resolve_reachable_heap_db(
                    heap_db, path, seed, want_max=max_heap_entries)
                dbg(f"  reachable heap (via index): {len(resolved):,} entries, "
                    f"truncated={truncated}")
                if truncated:
                    warnings.append(
                        f"message term graph exceeded --max-heap-entries "
                        f"({max_heap_entries:,}); decoded what fits (some "
                        f"values shown as #ref@addr). Raise it for more.")
            elif heap_ranges:
                resolved, truncated, passes = resolve_reachable_heap(
                    path, heap_ranges, seed,
                    want_max=max_heap_entries, max_passes=max_heap_passes)
                dbg(f"  reachable heap: {len(resolved):,} entries, "
                    f"{passes} pass(es), truncated={truncated}")
                if truncated:
                    warnings.append(
                        f"message term graph too large/deep; decoded what fits "
                        f"(some values shown as #ref@addr or truncated). Raise "
                        f"--max-heap-entries ({max_heap_entries:,}) or "
                        f"--max-heap-passes ({max_heap_passes}) for more.")
            elif seed:
                warnings.append("no heap sections found for this process; "
                                "messages with heap references shown partially")
        can_decode = decode
        items = []
        decoder = TermDecoder(resolved) if can_decode else None
        for raw in msgs:
            entry = {"raw": raw, "decoded": None, "token": None}
            if decoder is not None:
                entry["decoded"], entry["token"] = decoder.decode_message(raw)
            items.append(entry)
        result["messages"] = {
            "returned": len(items),
            "from_start": first,
            "items": items,
            "decoded": can_decode,
            "reachable_heap_entries": len(resolved),
            "warnings": warnings,
        }

    if want_stack:
        result["stack"] = {
            "program_counter": proc_info.get("Program counter"),
            "cp": proc_info.get("CP"),
            "frames": stack_frames,
            "raw": stack_raw,
            "truncated": stack_overflow,
        }

    return result


def print_process(r):
    print("=" * 72)
    print(f"PROCESS {r['pid']}")
    print("=" * 72)
    if r["proc"].get("Name"):
        print(f"Name:           {r['proc']['Name']}")
    if r["proc"].get("State"):
        print(f"State:          {r['proc']['State']}")
    if r["proc"].get("Spawned as"):
        print(f"Spawned as:     {r['proc']['Spawned as']}")
    if r["queue_length"] is not None:
        print(f"Queue length:   {r['queue_length']}")

    if not r["found"]:
        print("\nNo such process in this dump.")
        return

    if "stack" in r:
        print_stack(r["stack"])
    if "messages" in r:
        print_messages(r["pid"], r["queue_length"], r["messages"])
    print()


def print_stack(s):
    print("\n" + "-" * 72)
    print("STACKTRACE")
    print("-" * 72)
    if s["program_counter"]:
        print(f"Program counter: {s['program_counter']}")
    if s["cp"]:
        print(f"CP:              {s['cp']}")

    frames = s["frames"]
    if not frames:
        print("(no call frames found in =proc_stack; the process may have "
              "been idle in a receive)")
        return
    print(f"\nCall stack ({len(frames)} frame(s), top of stack first):")
    for i, fr in enumerate(frames):
        tag = "" if fr["kind"] == "return" else f"  [{fr['kind']}]"
        print(f"  {i:>4}  {fr['func']} + {fr['offset']}{tag}")
    if s["truncated"]:
        print(f"  ... (stack exceeded {_STACK_LINE_CAP:,} lines; truncated)")


def print_messages(pid, queue_length, m):
    from_start = m.get("from_start", False)
    print("\n" + "-" * 72)
    print("MAILBOX")
    print("-" * 72)
    which = "first" if from_start else "last"
    print(f"Showing:        {which} {m['returned']} message(s)"
          + ("  [decoded]" if m["decoded"] else "  [raw]"))
    for w in m["warnings"]:
        print(f"WARNING:        {w}")

    if m["returned"] == 0:
        print("Mailbox is empty (or no =proc_messages section).")
        return

    print()
    # Number each message by its position in the full queue (front = #1).
    # For the head we know positions directly; for the tail we offset by the
    # queue length so the most recent message keeps its true index.
    total = queue_length
    for i, msg in enumerate(m["items"]):
        if from_start:
            label = f"#{i + 1}"
        elif total is not None and total >= m["returned"]:
            label = f"#{total - m['returned'] + i + 1}"
        else:
            label = f"#{i + 1}"
        text = msg["decoded"] if msg["decoded"] is not None else msg["raw"]
        tok = f"   (token: {msg['token']})" if msg["token"] else ""
        print(f"{label}: {text}{tok}")


def diagnose(dump):
    slogan = dump["slogan"] or ""
    lc = slogan.lower()
    reasons = []
    is_oom = False

    if "cannot allocate" in lc or "eheap_alloc" in lc or "maximum" in lc \
            and "reached" in lc:
        is_oom = True

    m = re.search(r"cannot allocate (\d+) bytes of memory"
                  r"(?: \(of type \"([^\"]+)\"\))?", slogan, re.I)
    alloc = None
    if m:
        is_oom = True
        alloc = {"bytes": int(m.group(1)), "type": m.group(2)}
        reasons.append(
            f"The VM failed to allocate {human(alloc['bytes'])}"
            + (f' of type "{alloc["type"]}"' if alloc["type"] else "")
            + " and aborted. This is a classic in-VM OOM.")

    if "killed" in lc:
        reasons.append("Slogan mentions 'killed' - the process may have been "
                       "terminated by the OS OOM-killer (check dmesg / "
                       "/var/log/messages).")

    return {"is_oom": is_oom, "alloc": alloc, "reasons": reasons}


def build_report(dump, top):
    word_size = dump["word_size"]

    dbg(f"computing memory for {len(dump['procs']):,} processes")
    procs = []
    for p in dump["procs"]:
        mem = proc_memory(p, word_size)
        procs.append({
            "pid": p.get("pid"),
            "name": p.get("Name") or p.get("Spawned as"),
            "memory": mem,
            "msg_queue_len": _int(p.get("Message queue length")) or 0,
            "reductions": _int(p.get("Reductions")),
            "state": p.get("State"),
        })
    dbg("sorting processes by memory")
    procs.sort(key=lambda x: (x["memory"] or 0), reverse=True)
    if procs:
        proc_total = sum(x["memory"] or 0 for x in procs)
        dbg(f"  process heaps total {human(proc_total)}; "
            f"largest {human(procs[0]['memory'])} ({procs[0]['pid']})")

    dbg(f"computing memory for {len(dump['ets']):,} ETS tables")
    tables = []
    for t in dump["ets"]:
        tables.append({
            "id": t.get("id"),
            "name": t.get("Name"),
            "owner": t.get("Owner"),
            "objects": _int(t.get("Objects")),
            "memory": ets_memory(t, word_size),
        })
    tables.sort(key=lambda x: (x["memory"] or 0), reverse=True)

    dbg("running diagnosis")
    diag = diagnose(dump)
    dbg(f"  is_oom={diag['is_oom']}")

    return {
        "path": dump["path"],
        "date": dump["date"],
        "system_version": dump["system_version"],
        "slogan": dump["slogan"],
        "word_size": word_size,
        "diagnosis": diag,
        "memory": dump["memory"],
        "top_processes": procs[:top],
        "top_ets": tables[:top],
        "proc_count": len(dump["procs"]),
        "ets_count": len(dump["ets"]),
    }


def print_report(r):
    def rule(title):
        print("\n" + "=" * 72)
        print(title)
        print("=" * 72)

    rule("CRASH DUMP SUMMARY")
    print(f"File:           {r['path']}")
    print(f"Date:           {r['date'] or '?'}")
    print(f"System:         {r['system_version'] or '?'}")
    print(f"Word size:      {r['word_size']} bytes")
    print(f"Processes:      {r['proc_count']}")
    print(f"ETS tables:     {r['ets_count']}")
    print(f"\nSlogan:         {r['slogan'] or '(none)'}")

    diag = r["diagnosis"]
    rule("DIAGNOSIS")
    if diag["is_oom"]:
        print("VERDICT: This looks like an OUT-OF-MEMORY crash.")
    else:
        print("VERDICT: No clear OOM signature in the slogan. See details below.")
    for reason in diag["reasons"]:
        print(f"  - {reason}")
    if not diag["reasons"]:
        print("  (no specific reason lines extracted from the slogan)")

    if r["memory"]:
        rule("GLOBAL MEMORY BREAKDOWN (=memory)")
        total = r["memory"].get("total")
        order = sorted(r["memory"].items(), key=lambda kv: kv[1], reverse=True)
        for name, val in order:
            pct = f"{100.0 * val / total:5.1f}%" if total else "     "
            print(f"  {name:<22} {human(val):>14}  {pct}")

    rule(f"TOP {len(r['top_processes'])} PROCESSES BY MEMORY")
    print(f"  {'Memory':>12}  {'MsgQ':>8}  {'State':<12} PID / Name")
    for p in r["top_processes"]:
        name = p["name"] or ""
        print(f"  {human(p['memory']):>12}  {p['msg_queue_len']:>8}  "
              f"{(p['state'] or ''):<12} {p['pid']} {name}")

    if r["top_ets"]:
        rule(f"TOP {len(r['top_ets'])} ETS TABLES BY MEMORY")
        print(f"  {'Memory':>12}  {'Objects':>10}  Name (owner)")
        for t in r["top_ets"]:
            owner = f" ({t['owner']})" if t["owner"] else ""
            print(f"  {human(t['memory']):>12}  "
                  f"{(t['objects'] if t['objects'] is not None else '?'):>10}  "
                  f"{t['name'] or t['id']}{owner}")

    # Highlight suspicious message queues even if memory field is small.
    big_q = [p for p in r["top_processes"] if p["msg_queue_len"] >= 10000]
    if big_q:
        rule("WARNING: LARGE MESSAGE QUEUES")
        print("  A process buried under a huge mailbox is a common OOM cause")
        print("  (producer outpacing consumer). Suspects:")
        for p in big_q:
            print(f"    {p['pid']} {p['name'] or ''}: "
                  f"{p['msg_queue_len']} messages")

    print()


# ---------------------------------------------------------------------------
# On-disk index cache
#
# A single binary pass builds a SQLite index next to the dump (default
# ./.analyze_crash_dump/<key>.sqlite). It stores the report summaries (one row
# per process / ETS table) and the byte range of every proc/proc_heap/
# proc_messages/proc_stack section. Later runs answer the report from SQL
# (memory-bounded ORDER BY ... LIMIT) and jump straight to a process's sections
# by seeking - so the file is parsed only once until it changes.
# ---------------------------------------------------------------------------

# Sections whose byte ranges we record for seeking. "literals" is the global
# shared constant pool that message/stack terms can point into, so we need its
# range too when resolving heap references.
_INDEXED_SECTIONS = ("proc", "proc_heap", "proc_messages", "proc_stack",
                     "literals")

_SCHEMA = """
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE procs (pid TEXT, memory INTEGER, msgq INTEGER,
                    name TEXT, state TEXT, reductions INTEGER);
CREATE TABLE ets (id TEXT, name TEXT, owner TEXT,
                  objects INTEGER, memory INTEGER);
CREATE TABLE sections (kind TEXT, ident TEXT, start INTEGER, end INTEGER);
"""


def cache_key(path):
    real = os.path.realpath(path)
    return hashlib.sha1(real.encode("utf-8", "surrogatepass")).hexdigest()[:16]


def cache_path(cache_dir, path):
    return os.path.join(cache_dir, cache_key(path) + ".sqlite")


def ensure_cache_dir(cache_dir):
    """Create the cache dir if needed; return False (with a note) if we can't."""
    try:
        os.makedirs(cache_dir, exist_ok=True)
        return True
    except OSError as e:
        dbg(f"  cache dir unusable ({e}); running without cache")
        return False


def build_index(path, db_path):
    """One binary pass over the dump → SQLite index at db_path.

    Built into a temp file and atomically renamed, so readers never observe a
    partial DB and concurrent builders don't corrupt each other. Reuses the
    exact report helpers (proc_memory, ets_memory, _int) so index-backed output
    matches the in-memory path byte-for-byte.
    """
    st = os.stat(path)                       # raises if missing → caller falls back
    file_size = st.st_size
    tmp = os.path.join(os.path.dirname(db_path) or ".",
                       f".{os.path.basename(db_path)}.{os.getpid()}.tmp")
    dbg(f"  building index → {tmp} ({human(file_size)})")
    build_start = time.monotonic()

    slogan = date = system_version = None
    word_size = 8
    memory_pairs = []
    proc_rows = []
    ets_rows = []
    section_rows = []
    n_proc = n_ets = n_sec = 0

    section = None
    cur = None
    open_kind = open_ident = open_start = None

    conn = sqlite3.connect(tmp)
    ok = False
    try:
        conn.execute("PRAGMA synchronous=OFF")
        conn.execute("PRAGMA journal_mode=OFF")
        conn.executescript(_SCHEMA)

        def flush_row():
            nonlocal cur, n_proc, n_ets
            if cur is None:
                return
            if section == "proc":
                proc_rows.append((
                    cur.get("pid"),
                    proc_memory(cur, word_size),
                    _int(cur.get("Message queue length")) or 0,
                    cur.get("Name") or cur.get("Spawned as"),
                    cur.get("State"),
                    _int(cur.get("Reductions")),
                ))
                n_proc += 1
                if len(proc_rows) >= 10000:
                    conn.executemany("INSERT INTO procs VALUES (?,?,?,?,?,?)",
                                     proc_rows)
                    proc_rows.clear()
            elif section == "ets":
                ets_rows.append((
                    cur.get("id"),
                    cur.get("Name"),
                    cur.get("Owner"),
                    _int(cur.get("Objects")),
                    ets_memory(cur, word_size),
                ))
                n_ets += 1
                if len(ets_rows) >= 10000:
                    conn.executemany("INSERT INTO ets VALUES (?,?,?,?,?)",
                                     ets_rows)
                    ets_rows.clear()
            cur = None

        def close_section(end_off):
            nonlocal open_kind, open_ident, open_start, n_sec
            if open_kind is not None:
                section_rows.append((open_kind, open_ident, open_start, end_off))
                n_sec += 1
                if len(section_rows) >= 10000:
                    conn.executemany("INSERT INTO sections VALUES (?,?,?,?)",
                                     section_rows)
                    section_rows.clear()
            open_kind = open_ident = open_start = None

        offset = 0
        lineno = 0
        with open(path, "rb") as f:
            for raw in f:
                lineno += 1
                line_start = offset
                offset += len(raw)
                if VERBOSE and lineno % 2_000_000 == 0:
                    pct = (f"{100.0 * offset / file_size:4.1f}%"
                           if file_size else "  ?  ")
                    dbg(f"    indexed {lineno:>12,} lines ({pct}) "
                        f"procs={n_proc:,} ets={n_ets:,}")

                if raw.startswith(b"="):
                    body = raw.rstrip(b"\r\n")[1:].decode("latin-1")
                    # Line-1 =erl_crash_dump header: keep section None so the
                    # slogan/date/version lines that follow are still parsed.
                    if lineno == 1 and body.startswith("erl_crash_dump"):
                        continue
                    flush_row()
                    close_section(line_start)
                    if ":" in body:
                        kind, _, ident = body.partition(":")
                    else:
                        kind, ident = body, None
                    section = kind
                    if kind == "proc":
                        cur = {"pid": ident}
                    elif kind == "ets":
                        cur = {"id": ident}
                    else:
                        cur = None
                    if kind in _INDEXED_SECTIONS:
                        open_kind, open_ident, open_start = kind, ident, offset
                    continue

                line = raw.rstrip(b"\r\n").decode("latin-1")
                if section is None:
                    if line.startswith("Slogan:"):
                        slogan = line.split(":", 1)[1].strip()
                    elif re.match(r"^[A-Z][a-z]{2} [A-Z][a-z]{2} ", line):
                        date = date or line.strip()
                    elif "Erlang" in line and "version" in line.lower():
                        system_version = re.sub(r"^System version:\s*", "",
                                                 line.strip())
                        if "[64-bit]" in line:
                            word_size = 8
                        elif "[32-bit]" in line:
                            word_size = 4
                    continue
                if section == "memory":
                    m = re.match(r"^(\S+):\s*(\d+)", line)
                    if m:
                        memory_pairs.append((m.group(1), int(m.group(2))))
                    continue
                if section in ("proc", "ets") and cur is not None:
                    if ":" in line:
                        key, _, val = line.partition(":")
                        cur[key.strip()] = val.strip()
                    continue

            # EOF: flush the final open row and close the final section to
            # end-of-file (covers truncated dumps with no trailing header).
            flush_row()
            close_section(offset)

        if proc_rows:
            conn.executemany("INSERT INTO procs VALUES (?,?,?,?,?,?)", proc_rows)
        if ets_rows:
            conn.executemany("INSERT INTO ets VALUES (?,?,?,?,?)", ets_rows)
        if section_rows:
            conn.executemany("INSERT INTO sections VALUES (?,?,?,?)", section_rows)

        conn.executemany("INSERT INTO meta VALUES (?,?)", [
            ("slogan", slogan or ""),
            ("date", date or ""),
            ("system_version", system_version or ""),
            ("word_size", str(word_size)),
            ("memory", json.dumps(memory_pairs)),
            ("src_size", str(st.st_size)),
            ("src_mtime_ns", str(st.st_mtime_ns)),
            ("src_abspath", os.path.realpath(path)),
            ("format_version", str(FORMAT_VERSION)),
        ])
        # Indexes are built after bulk insert (much faster than incremental).
        conn.execute("CREATE INDEX idx_procs_mem ON procs(memory DESC)")
        conn.execute("CREATE INDEX idx_sections ON sections(ident, kind)")
        conn.commit()
        conn.close()
        os.replace(tmp, db_path)
        ok = True
    finally:
        if not ok:
            try:
                conn.close()
            except Exception:
                pass
            try:
                os.unlink(tmp)
            except OSError:
                pass

    dbg(f"  indexed procs={n_proc:,} ets={n_ets:,} sections={n_sec:,} "
        f"in {time.monotonic() - build_start:.2f}s")
    return True


def open_cache_ro(db_path, src_path):
    """Open the index read-only and validate it against the source file.

    Returns a connection if the cache is present, readable, and fresh
    (matching size / mtime / format version); otherwise None. Never raises on
    a missing or corrupt DB - the caller treats None as "no usable cache".
    """
    if not os.path.exists(db_path):
        return None
    conn = None
    try:
        uri = ("file:" + urllib.parse.quote(os.path.abspath(db_path))
               + "?mode=ro&immutable=1")
        conn = sqlite3.connect(uri, uri=True)
        meta = dict(conn.execute("SELECT key, value FROM meta").fetchall())
    except sqlite3.Error as e:
        dbg(f"  cache unreadable ({e}); treating as miss")
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
        return None

    try:
        st = os.stat(src_path)
    except OSError:
        conn.close()
        return None
    if (meta.get("format_version") != str(FORMAT_VERSION)
            or meta.get("src_size") != str(st.st_size)
            or meta.get("src_mtime_ns") != str(st.st_mtime_ns)):
        dbg("  cache stale (size/mtime/format changed)")
        conn.close()
        return None
    return conn


def get_or_build_index(path, cache_dir, reindex=False):
    """Return a read-only conn to a fresh index, building it if needed.

    Returns None when caching is unavailable (unwritable dir, build error),
    signalling the caller to fall back to the in-memory parse.
    """
    if not ensure_cache_dir(cache_dir):
        return None
    db_path = cache_path(cache_dir, path)
    if not reindex:
        conn = open_cache_ro(db_path, path)
        if conn is not None:
            dbg(f"  cache hit: {db_path}")
            return conn
        dbg("  cache miss: building index")
    else:
        dbg("  --reindex: rebuilding index")
    try:
        build_index(path, db_path)
    except (OSError, sqlite3.Error) as e:
        dbg(f"  index build failed ({e}); running without cache")
        return None
    return open_cache_ro(db_path, path)


def report_from_index(conn, top, path):
    """Reconstruct the exact build_report() dict shape from the index."""
    meta = dict(conn.execute("SELECT key, value FROM meta").fetchall())
    word_size = int(meta.get("word_size", "8"))
    slogan = meta.get("slogan") or None
    memory = {name: val for name, val in json.loads(meta.get("memory", "[]"))}

    procs = [
        {"pid": pid, "name": name, "memory": mem,
         "msg_queue_len": msgq, "reductions": red, "state": state}
        for pid, name, mem, msgq, red, state in conn.execute(
            "SELECT pid, name, memory, msgq, reductions, state FROM procs "
            "ORDER BY COALESCE(memory, 0) DESC, rowid ASC LIMIT ?", (top,))
    ]
    tables = [
        {"id": id_, "name": name, "owner": owner,
         "objects": objects, "memory": mem}
        for id_, name, owner, objects, mem in conn.execute(
            "SELECT id, name, owner, objects, memory FROM ets "
            "ORDER BY COALESCE(memory, 0) DESC, rowid ASC LIMIT ?", (top,))
    ]
    proc_count = conn.execute("SELECT COUNT(*) FROM procs").fetchone()[0]
    ets_count = conn.execute("SELECT COUNT(*) FROM ets").fetchone()[0]

    return {
        "path": path,
        "date": meta.get("date") or None,
        "system_version": meta.get("system_version") or None,
        "slogan": slogan,
        "word_size": word_size,
        "diagnosis": diagnose({"slogan": slogan}),
        "memory": memory,
        "top_processes": procs,
        "top_ets": tables,
        "proc_count": proc_count,
        "ets_count": ets_count,
    }


def _read_range(f, start, end):
    """Yield decoded body lines of a section given its [start, end) byte range."""
    f.seek(start)
    pos = start
    for raw in f:
        if pos >= end:
            break
        pos += len(raw)
        yield raw.rstrip(b"\r\n").decode("latin-1")


def extract_process_from_index(conn, path, pid, want_messages=True,
                               want_stack=True, n=10, first=False, decode=True,
                               max_heap_entries=5_000_000, max_heap_passes=200,
                               heap_index=False, cache_dir=None, reindex=False,
                               max_heap_index_entries=0):
    """Index-backed process inspection: seek to the process's sections using
    the stored byte offsets instead of scanning the file."""
    from collections import deque

    pid = normalize_pid(pid)
    sec = {}
    for kind, start, end in conn.execute(
            "SELECT kind, start, end FROM sections WHERE ident=? ORDER BY rowid",
            (pid,)):
        if kind not in sec:                  # first match wins (parity)
            sec[kind] = (start, end)
    # The global =literals pool (ident is NULL) is shared by all processes.
    lit = conn.execute(
        "SELECT start, end FROM sections WHERE kind='literals' "
        "ORDER BY rowid LIMIT 1").fetchone()
    dbg(f"  index seek for {pid}: sections={sorted(sec)}"
        + (" +literals" if lit else ""))

    proc_info = {}
    qlen = None
    # first N → head (plain list); last N → bounded deque of the most recent n.
    msgs = [] if first else deque(maxlen=n)
    stack_frames = []
    stack_raw = []
    stack_overflow = False
    proc_seen = "proc" in sec

    with open(path, "rb") as f:
        if "proc" in sec:
            for line in _read_range(f, *sec["proc"]):
                key, colon, val = line.partition(":")
                if colon:
                    key, val = key.strip(), val.strip()
                    if key == "Message queue length":
                        qlen = _int(val)
                        proc_info["msg_queue_length"] = qlen
                    elif key in ("Name", "State", "Spawned as",
                                 "Program counter", "CP", "arity"):
                        proc_info[key] = val
        if want_messages and "proc_messages" in sec:
            for line in _read_range(f, *sec["proc_messages"]):
                msgs.append(line)
                if first and len(msgs) >= n:     # head: stop once we have n
                    break
        if want_stack and "proc_stack" in sec:
            for line in _read_range(f, *sec["proc_stack"]):
                if len(stack_raw) < _STACK_LINE_CAP:
                    stack_raw.append(line)
                elif not stack_overflow:
                    stack_overflow = True
                stack_frames.extend(parse_stack_line(line))

    heap_ranges = []
    if want_messages and decode:
        if "proc_heap" in sec:
            heap_ranges.append(sec["proc_heap"])
        if lit:
            heap_ranges.append((lit[0], lit[1]))

    heap_db = None
    if heap_index and cache_dir and heap_ranges:
        heap_db = get_or_build_heap_index(
            path, cache_dir, pid, heap_ranges,
            reindex=reindex, max_entries=max_heap_index_entries)
    try:
        return assemble_process_result(
            path, pid, proc_seen, qlen, proc_info, msgs, stack_frames,
            stack_raw, stack_overflow, heap_ranges,
            want_messages=want_messages, want_stack=want_stack, decode=decode,
            max_heap_entries=max_heap_entries, max_heap_passes=max_heap_passes,
            heap_db=heap_db, first=first)
    finally:
        if heap_db is not None:
            heap_db.close()


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dump", nargs="?", default="erl_crash.dump",
                    help="path to the crash dump (default: erl_crash.dump)")
    ap.add_argument("--top", type=int, default=15,
                    help="how many processes / tables to show (default: 15)")
    ap.add_argument("--json", action="store_true",
                    help="emit the report as JSON instead of text")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="print parsing progress and timing to stderr")

    pg = ap.add_argument_group("process inspection")
    pg.add_argument("-p", "--pid", metavar="PID",
                    help="inspect process PID (e.g. '<0.42.0>' or '0.42.0') "
                         "instead of producing the OOM report")
    pg.add_argument("--messages", action="store_true",
                    help="include the mailbox (last -n messages by default)")
    pg.add_argument("--stack", action="store_true",
                    help="include the stacktrace")
    pg.add_argument("-n", "--num", type=int, default=10,
                    help="how many messages to show (default: 10)")
    pg.add_argument("--first", action="store_true",
                    help="show the FIRST -n messages (head of the mailbox) "
                         "instead of the last -n")
    pg.add_argument("--raw", action="store_true",
                    help="do not decode message terms; print raw dump "
                         "encoding (fastest, smallest memory)")
    pg.add_argument("--max-heap-entries", type=int, default=5_000_000,
                    help="cap on reachable heap entries resolved for decoding "
                         "(default: 5,000,000); beyond it, values render as "
                         "#ref@addr")
    pg.add_argument("--max-heap-passes", type=int, default=200,
                    help="max passes over the heap section when resolving "
                         "reachable terms (default: 200); bounds time on "
                         "deep/pathological term graphs")

    cg = ap.add_argument_group("caching")
    cg.add_argument("--cache-dir", metavar="DIR", default=".analyze_crash_dump",
                    help="directory for the on-disk index (default: "
                         "./.analyze_crash_dump)")
    cg.add_argument("--no-cache", action="store_true",
                    help="do not read or write any index; parse in memory")
    cg.add_argument("--reindex", action="store_true",
                    help="rebuild the index even if a fresh one exists")
    cg.add_argument("--heap-index", action="store_true",
                    help="build/reuse a per-process addr->offset index of the "
                         "=proc_heap section, so message decoding uses random "
                         "DB lookups instead of scanning a huge heap "
                         "(recommended when a process heap is very large)")
    cg.add_argument("--max-heap-index-entries", type=int, default=0,
                    help="cap on entries stored in the per-process heap index "
                         "(default: 0 = unlimited)")
    args = ap.parse_args()

    global VERBOSE, _T0
    VERBOSE = args.verbose
    _T0 = time.monotonic()

    # Process-inspection mode: pull the mailbox and/or the stacktrace. If
    # neither --messages nor --stack is named, extract both. Uses the index
    # opportunistically - a fresh one (typically built by a prior report run)
    # turns this into direct seeks - but never forces a full build for one PID.
    if args.pid:
        want_messages = args.messages or not args.stack
        want_stack = args.stack or not args.messages
        # The heap index needs a writable cache dir; disabled under --no-cache.
        hi_cache_dir = None if args.no_cache else args.cache_dir
        if args.heap_index and args.no_cache:
            dbg("  --heap-index ignored under --no-cache")
        try:
            result = None
            if not args.no_cache:
                db_path = cache_path(args.cache_dir, args.dump)
                # --reindex is the only path that WRITES here; a plain
                # inspection only READS an existing index and never creates
                # the cache dir (so it isn't left behind empty).
                if args.reindex and ensure_cache_dir(args.cache_dir):
                    try:
                        build_index(args.dump, db_path)
                    except (OSError, sqlite3.Error) as e:
                        dbg(f"  index build failed ({e})")
                conn = open_cache_ro(db_path, args.dump)
                if conn is not None:
                    dbg("  cache hit: inspecting via index")
                    result = extract_process_from_index(
                        conn, args.dump, args.pid,
                        want_messages=want_messages, want_stack=want_stack,
                        n=args.num, first=args.first, decode=not args.raw,
                        max_heap_entries=args.max_heap_entries,
                        max_heap_passes=args.max_heap_passes,
                        heap_index=args.heap_index, cache_dir=hi_cache_dir,
                        reindex=args.reindex,
                        max_heap_index_entries=args.max_heap_index_entries)
                    conn.close()
            if result is None:
                dbg("  no cached index yet (run the report once, or pass "
                    "--reindex, to build one); doing a targeted scan")
                result = extract_process(
                    args.dump, args.pid,
                    want_messages=want_messages, want_stack=want_stack,
                    n=args.num, first=args.first, decode=not args.raw,
                    max_heap_entries=args.max_heap_entries,
                    max_heap_passes=args.max_heap_passes,
                    heap_index=args.heap_index, cache_dir=hi_cache_dir,
                    reindex=args.reindex,
                    max_heap_index_entries=args.max_heap_index_entries)
        except FileNotFoundError:
            sys.exit(f"error: no such file: {args.dump}")
        except IsADirectoryError:
            sys.exit(f"error: {args.dump} is a directory")

        dbg("rendering process")
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print_process(result)
        dbg("done")
        sys.exit(0 if result["found"] else 2)

    # OOM report mode: served from the index (built/refreshed here in one pass);
    # falls back to the in-memory parse if caching is unavailable.
    try:
        report = None
        if not args.no_cache:
            conn = get_or_build_index(args.dump, args.cache_dir,
                                      reindex=args.reindex)
            if conn is not None:
                report = report_from_index(conn, args.top, args.dump)
                conn.close()
        if report is None:
            dump = parse_crash_dump(args.dump)
            report = build_report(dump, args.top)
    except FileNotFoundError:
        sys.exit(f"error: no such file: {args.dump}")
    except IsADirectoryError:
        sys.exit(f"error: {args.dump} is a directory")

    dbg("rendering report")
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print_report(report)

    dbg("done")
    sys.exit(0 if report["diagnosis"]["is_oom"] else 2)


if __name__ == "__main__":
    main()
