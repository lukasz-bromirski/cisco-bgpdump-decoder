"""Turn pasted Cisco syslog text into raw BGP message bytes.

Handles the shapes IOS/IOS-XE produce, e.g.

    022456: Jul  9 08:51:32.605: %BGP-6-MSGDUMP_LIMIT: unsupported or
    mal-formatted message received from 2A03:4620::A:
    FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF 02B1 0200 0002 9A40 0101 0050 ...

plus the variants you get when the same log is relayed to a syslog server
(leading PRI, host name, RFC3339 stamp) and the uptime form (*00:01:02.345).
"""

import datetime as _dt
import re

from . import constants as C

# %BGP-6-MSGDUMP_LIMIT: ...   /   %BGP-3-NOTIFICATION: ...
HEADER_RE = re.compile(
    r"%(?P<facility>[A-Z][A-Z0-9_]*)-(?P<sev>\d)-(?P<mnemonic>[A-Z0-9_]+)\s*:"
    r"\s*(?P<text>.*)$"
)

# A line (or line tail) that is nothing but hex groups.  Groups of a single
# nibble occur where IOS-XE split a chunk in the middle of a byte.
HEX_LINE_RE = re.compile(r"^(?:[0-9A-Fa-f]{1,8}[ \t]+)*[0-9A-Fa-f]{1,8}[ \t]*$")

PEER_RE = re.compile(
    r"\b(?:from|to|with|neighbor)\s+"
    r"(?P<peer>\[?[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{0,4}){2,7}\]?"
    r"|\d{1,3}(?:\.\d{1,3}){3})",
    re.I,
)

DIRECTION_RE = re.compile(r"\b(received|sent|receiving|sending)\b", re.I)

# Timestamp shapes seen in front of the %FACILITY tag.
TS_PATTERNS = [
    # Jul  9 08:51:32.605  /  Jul  9 2025 08:51:32.605
    (re.compile(r"(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})"
                r"(?:\s+(?P<year>\d{4}))?\s+"
                r"(?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2})"
                r"(?:\.(?P<frac>\d+))?"), "mon"),
    # 2025-07-09T08:51:32.605+02:00
    (re.compile(r"(?P<year>\d{4})-(?P<mon>\d{2})-(?P<day>\d{2})"
                r"[T ](?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2})"
                r"(?:\.(?P<frac>\d+))?"), "iso"),
    # *00:01:02.345 (uptime, no clock)
    (re.compile(r"^\W*(?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2})"
                r"\.(?P<frac>\d+)"), "uptime"),
]

MONTHS = {m: i + 1 for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"])}

SEQ_RE = re.compile(r"^\s*(?:<\d{1,3}>)?\s*(?P<seq>\d{1,10})\s*:")

# IOS-XE splits an over-long syslog message into chunks and marks the seam:
#   ... 32CC 00**MSG 21505 TRUNCATED**
#   **MSG 21505 CONTINUATION #01**00 32F6 ...
# The split can fall in the middle of a byte pair, so the chunks are joined
# with nothing in between.
TRUNC_RE = re.compile(r"\*\*\s*MSG\s+(?P<id>\d+)\s+TRUNCATED\s*\*\*")
CONT_RE = re.compile(
    r"\*\*\s*MSG\s+(?P<id>\d+)\s+CONTINUATION\s*#?(?P<idx>\d+)\s*\*\*")


class LogEvent:
    """One %BGP-... syslog line, with any hexdump that followed it."""

    def __init__(self, mnemonic, severity, text, line_no, raw_line,
                 facility="BGP"):
        self.facility = facility
        self.mnemonic = mnemonic
        self.severity = severity
        self.text = text
        self.line_no = line_no
        self.raw_line = raw_line
        self.seq = None
        self.timestamp = None        # datetime or None
        self.timestamp_text = None
        self.timestamp_kind = None   # 'mon' | 'iso' | 'uptime' | None
        self.peer = None
        self.direction = "received"
        self.data = b""              # reassembled BGP bytes
        self.hex_lines = 0
        self.chunks = 1              # syslog chunks stitched together
        self.odd_nibble = False      # dump ended on a half byte
        self.msg_id = None           # **MSG <id> TRUNCATED** identifier

    @property
    def has_dump(self):
        return bool(self.data)

    def __repr__(self):
        return "<LogEvent %s line %d peer=%s bytes=%d>" % (
            self.mnemonic, self.line_no, self.peer, len(self.data))


def _parse_timestamp(prefix, default_year, tz):
    for rx, kind in TS_PATTERNS:
        m = rx.search(prefix)
        if not m:
            continue
        g = m.groupdict()
        frac = g.get("frac") or "0"
        micro = int((frac + "000000")[:6])
        try:
            if kind == "uptime":
                return None, m.group(0), kind
            if kind == "mon":
                mon = MONTHS.get(g["mon"])
                if mon is None:
                    continue
                year = int(g["year"]) if g.get("year") else default_year
                dt = _dt.datetime(year, mon, int(g["day"]), int(g["h"]),
                                  int(g["m"]), int(g["s"]), micro, tzinfo=tz)
                if not g.get("year"):
                    now = _dt.datetime.now(tz)
                    if dt > now + _dt.timedelta(days=1):
                        dt = dt.replace(year=year - 1)
                return dt, m.group(0), kind
            dt = _dt.datetime(int(g["year"]), int(g["mon"]), int(g["day"]),
                              int(g["h"]), int(g["m"]), int(g["s"]), micro,
                              tzinfo=tz)
            return dt, m.group(0), kind
        except ValueError:
            continue
    return None, None, None


def _hex_payload(line, min_digits=4):
    """Return the hex-only tail of a line, or None.

    Chunked IOS-XE dumps can break inside a byte, so an odd number of nibbles
    is accepted here; the caller joins the nibble stream and only needs the
    total to be even.
    """
    s = line.strip()
    if not s:
        return None
    if HEX_LINE_RE.match(s):
        cand = s
    elif ":" in s:
        cand = s.rsplit(":", 1)[-1].strip()
        if not cand or not HEX_LINE_RE.match(cand):
            return None
    else:
        return None
    digits = cand.replace(" ", "").replace("\t", "")
    if len(digits) < min_digits:
        return None
    return digits


def parse_log(text, year=None, tz=None, max_gap_lines=1, facilities=("BGP",)):
    """Parse pasted syslog text into a list of LogEvent.

    Only lines whose facility is in ``facilities`` are returned (pass None to
    keep everything); other %FACILITY lines still terminate a hexdump block,
    so an interleaved %SYS or %LINEPROTO message cannot be absorbed into a
    BGP dump.  ``max_gap_lines`` blank lines are tolerated inside one block.
    """
    tz = tz or _dt.timezone.utc
    default_year = year or _dt.datetime.now(tz).year
    events = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        m = HEADER_RE.search(line)
        if not m:
            i += 1
            continue
        if facilities is not None and m.group("facility") not in facilities:
            i += 1
            continue
        prefix = line[:m.start()]
        ev = LogEvent(m.group("mnemonic"), int(m.group("sev")),
                      m.group("text").strip(), i + 1, line.rstrip(),
                      facility=m.group("facility"))
        sm = SEQ_RE.match(prefix)
        if sm:
            ev.seq = int(sm.group("seq"))
        ev.timestamp, ev.timestamp_text, ev.timestamp_kind = _parse_timestamp(
            prefix, default_year, tz)
        pm = PEER_RE.search(m.group("text"))
        if pm:
            ev.peer = pm.group("peer").strip("[]").rstrip(":")
        dm = DIRECTION_RE.search(m.group("text"))
        if dm:
            ev.direction = ("sent" if dm.group(1).lower().startswith("s")
                            else "received")

        digits = []
        j = i + 1
        gap = 0
        want = None
        pending_cont = None      # msg id we expect a CONTINUATION line for
        while j < len(lines):
            nxt = lines[j]
            if not nxt.strip():
                if digits and gap < max_gap_lines:
                    gap += 1
                    j += 1
                    continue
                break

            cont = CONT_RE.search(nxt)
            if pending_cont is not None:
                # Only a matching continuation may extend the dump.
                if not cont or cont.group("id") != pending_cont:
                    break
            if cont:
                nxt = nxt[cont.end():]
                ev.chunks += 1
                pending_cont = None
            elif HEADER_RE.search(nxt):
                break

            trunc = TRUNC_RE.search(nxt)
            if trunc:
                nxt = nxt[:trunc.start()]
                pending_cont = trunc.group("id")
                ev.msg_id = trunc.group("id")

            payload = _hex_payload(nxt, min_digits=1 if cont else 4)
            if payload is None:
                break
            digits.append(payload)
            ev.hex_lines += 1
            gap = 0
            j += 1
            # Stop as soon as the declared message length is satisfied; this
            # keeps unrelated hex-looking syslog lines out of the dump.
            joined = "".join(digits)
            if want is None and len(joined) >= 38:
                try:
                    want = int(joined[32:36], 16)
                except ValueError:
                    want = None
            if want and len(joined) >= want * 2:
                break

        if digits:
            joined = "".join(digits)
            if len(joined) % 2:
                # A dangling nibble means the dump really did end mid-byte.
                joined = joined[:-1]
                ev.odd_nibble = True
            try:
                ev.data = bytes.fromhex(joined)
            except ValueError:
                ev.data = b""
            i = j
        else:
            i += 1
        events.append(ev)
    return events


def dump_events(events):
    """Only the events that actually carried a hexdump."""
    return [e for e in events if e.has_dump]


def is_dump_mnemonic(mnemonic):
    return mnemonic in C.DUMP_MNEMONICS
