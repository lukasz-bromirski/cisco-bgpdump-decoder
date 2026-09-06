"""Small helpers: byte readers, prefix decoding, address formatting."""

import ipaddress


class ReadError(ValueError):
    """Raised when a decoder walks off the end of a buffer."""


class Reader:
    """Bounds-checked sequential reader over a bytes object."""

    __slots__ = ("buf", "off", "end")

    def __init__(self, buf, off=0, end=None):
        self.buf = buf
        self.off = off
        self.end = len(buf) if end is None else end

    @property
    def remaining(self):
        return self.end - self.off

    def _need(self, n):
        if self.off + n > self.end:
            raise ReadError(
                "need %d byte(s) at offset %d, only %d available"
                % (n, self.off, self.remaining)
            )

    def u8(self):
        self._need(1)
        v = self.buf[self.off]
        self.off += 1
        return v

    def u16(self):
        self._need(2)
        v = int.from_bytes(self.buf[self.off:self.off + 2], "big")
        self.off += 2
        return v

    def u32(self):
        self._need(4)
        v = int.from_bytes(self.buf[self.off:self.off + 4], "big")
        self.off += 4
        return v

    def u64(self):
        self._need(8)
        v = int.from_bytes(self.buf[self.off:self.off + 8], "big")
        self.off += 8
        return v

    def take(self, n):
        self._need(n)
        v = self.buf[self.off:self.off + n]
        self.off += n
        return v

    def rest(self):
        v = self.buf[self.off:self.end]
        self.off = self.end
        return v

    def sub(self, n):
        """Return a Reader over the next n bytes and skip past them."""
        self._need(n)
        r = Reader(self.buf, self.off, self.off + n)
        self.off += n
        return r


def hexs(data, group=1, sep=" "):
    """Hex string; group=n emits n-byte groups separated by sep."""
    h = data.hex().upper()
    if group <= 0:
        return h
    step = group * 2
    return sep.join(h[i:i + step] for i in range(0, len(h), step))


def hexdump(data, indent="", width=16):
    """Classic offset / hex / ASCII dump."""
    out = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hx = " ".join("%02X" % b for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append("%s%04X  %-*s  |%s|" % (indent, i, width * 3 - 1, hx, asc))
    return "\n".join(out)


def ip_from_bytes(raw, family):
    """family is 4 or 6; raw is padded/truncated as needed."""
    size = 4 if family == 4 else 16
    b = bytes(raw[:size]).ljust(size, b"\x00")
    return str(ipaddress.ip_address(b))


def read_prefix(r, family, add_path=False):
    """Read one NLRI entry (RFC 4271 4.3 / RFC 7911).

    Returns a dict with the textual prefix and, optionally, the ADD-PATH id.
    """
    entry = {}
    if add_path:
        entry["path_id"] = r.u32()
    plen = r.u8()
    maxbits = 32 if family == 4 else 128
    if plen > maxbits:
        raise ReadError("prefix length %d exceeds %d bits" % (plen, maxbits))
    nbytes = (plen + 7) // 8
    raw = r.take(nbytes)
    addr = ip_from_bytes(raw, family)
    entry["prefix"] = "%s/%d" % (addr, plen)
    entry["length"] = plen
    # Flag host bits that should have been zeroed.
    if nbytes and plen % 8:
        if raw[-1] & ((1 << (8 - plen % 8)) - 1):
            entry["nonzero_trailing_bits"] = True
    return entry


def read_labels(r):
    """MPLS label stack in NLRI (RFC 3107/8277). Returns (labels, bottom_seen)."""
    labels = []
    while True:
        b = r.take(3)
        val = (b[0] << 16 | b[1] << 8 | b[2])
        label = val >> 4
        bos = val & 0x01
        labels.append(label)
        # 0x800000 == withdraw placeholder, 0x000000 also terminates.
        if bos or label in (0x080000, 0x000000) or len(labels) > 10:
            return labels, bool(bos)


def format_rd(raw):
    """Route Distinguisher (RFC 4364 4.2)."""
    if len(raw) != 8:
        return hexs(raw)
    typ = int.from_bytes(raw[0:2], "big")
    if typ == 0:
        return "%d:%d" % (int.from_bytes(raw[2:4], "big"),
                          int.from_bytes(raw[4:8], "big"))
    if typ == 1:
        return "%s:%d" % (ip_from_bytes(raw[2:6], 4),
                          int.from_bytes(raw[6:8], "big"))
    if typ == 2:
        return "%d:%d" % (int.from_bytes(raw[2:6], "big"),
                          int.from_bytes(raw[6:8], "big"))
    return hexs(raw)


def asdot(asn):
    """AS number in asdot+ notation (only meaningful above 65535)."""
    if asn > 0xFFFF:
        return "%d.%d" % (asn >> 16, asn & 0xFFFF)
    return str(asn)


def runlength(items):
    """[a,a,a,b] -> [(a,3),(b,1)]"""
    out = []
    for it in items:
        if out and out[-1][0] == it:
            out[-1][1] += 1
        else:
            out.append([it, 1])
    return [(v, c) for v, c in out]


def collapse(items, joiner=" "):
    """Human-friendly collapsed run-length rendering of an AS path."""
    parts = []
    for val, count in runlength(items):
        parts.append("%s" % val if count == 1 else "%s x%d" % (val, count))
    return joiner.join(parts)
