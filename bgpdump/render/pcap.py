"""Rebuild a pcap from decoded dumps so Wireshark/tshark can dissect them.

A syslog hexdump has no L2/L3/L4 context, so the framing is synthesised:

  * the peer address comes from the syslog line ("... received from X");
  * the local address is a placeholder from RFC 5737 / RFC 3849
    documentation space unless --local-addr is given;
  * the BGP speaker side always uses TCP/179 and the local side an
    ephemeral port, so Wireshark's BGP dissector triggers;
  * TCP sequence numbers advance per flow so multi-message streams
    reassemble cleanly; no handshake is emitted unless --handshake is set.

None of that is real captured data - it exists only to give the dissector
something to chew on.  The BGP payload itself is byte-for-byte what the
router printed.
"""

import ipaddress
import struct
import time

LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LOOP = 108

DEFAULT_LOCAL_V4 = "192.0.2.1"      # RFC 5737 TEST-NET-1
DEFAULT_LOCAL_V6 = "2001:db8::1"    # RFC 3849
DEFAULT_PEER_V4 = "198.51.100.1"    # RFC 5737 TEST-NET-2
DEFAULT_PEER_V6 = "2001:db8:ffff::1"

MAC_LOCAL = bytes.fromhex("02000000CAFE")
MAC_PEER = bytes.fromhex("020000000179")


def _ones_complement(data):
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


class PcapWriter:
    def __init__(self, fh, linktype=LINKTYPE_ETHERNET, snaplen=262144):
        self.fh = fh
        self.linktype = linktype
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0,
                             snaplen, linktype))

    def packet(self, ts, data):
        sec = int(ts)
        usec = int(round((ts - sec) * 1_000_000))
        if usec >= 1_000_000:
            sec += 1
            usec -= 1_000_000
        self.fh.write(struct.pack("<IIII", sec, usec, len(data), len(data)))
        self.fh.write(data)


class Framer:
    """Builds Ethernet/IP/TCP frames around BGP payloads."""

    def __init__(self, local_addr=None, local_port_base=49152,
                 linktype=LINKTYPE_ETHERNET, handshake=False):
        self.local_addr = local_addr
        self.local_port_base = local_port_base
        self.linktype = linktype
        self.handshake = handshake
        self.flows = {}      # peer -> state dict
        self._port_next = local_port_base

    # ------------------------------------------------------------ addressing
    def _local_for(self, peer_ip):
        if self.local_addr:
            return ipaddress.ip_address(self.local_addr)
        return ipaddress.ip_address(
            DEFAULT_LOCAL_V6 if peer_ip.version == 6 else DEFAULT_LOCAL_V4)

    def _flow(self, peer):
        st = self.flows.get(peer)
        if st is None:
            try:
                pip = ipaddress.ip_address(peer)
            except ValueError:
                pip = ipaddress.ip_address(DEFAULT_PEER_V6 if ":" in str(peer)
                                           else DEFAULT_PEER_V4)
            lip = self._local_for(pip)
            if lip.version != pip.version:
                lip = ipaddress.ip_address(
                    DEFAULT_LOCAL_V6 if pip.version == 6 else DEFAULT_LOCAL_V4)
            st = {
                "peer_ip": pip,
                "local_ip": lip,
                "local_port": self._port_next,
                "seq_peer": 1,
                "seq_local": 1,
                "started": False,
            }
            self._port_next += 1
            self.flows[peer] = st
        return st

    # ---------------------------------------------------------------- frames
    def _tcp(self, src, dst, sport, dport, seq, ack, flags, payload):
        offset_flags = (5 << 12) | flags
        hdr = struct.pack("!HHIIHHHH", sport, dport, seq, ack,
                          offset_flags, 65535, 0, 0)
        if src.version == 4:
            pseudo = src.packed + dst.packed + struct.pack(
                "!BBH", 0, 6, len(hdr) + len(payload))
        else:
            pseudo = src.packed + dst.packed + struct.pack(
                "!IBBBB", len(hdr) + len(payload), 0, 0, 0, 6)
        csum = _ones_complement(pseudo + hdr + payload)
        hdr = hdr[:16] + struct.pack("!H", csum) + hdr[18:]
        return hdr + payload

    def _ip(self, src, dst, tcp, ident):
        if src.version == 6:
            return struct.pack("!IHBB", 0x60000000, len(tcp), 6, 64) \
                + src.packed + dst.packed
        hdr = struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(tcp), ident,
                          0x4000, 64, 6, 0) + src.packed + dst.packed
        csum = _ones_complement(hdr)
        return hdr[:10] + struct.pack("!H", csum) + hdr[12:]

    def _frame(self, src, dst, tcp, ident):
        ip = self._ip(src, dst, tcp, ident) + tcp
        if self.linktype == LINKTYPE_RAW:
            return ip
        if self.linktype == LINKTYPE_LOOP:
            return struct.pack("!I", 2 if src.version == 4 else 24) + ip
        ethertype = 0x86DD if src.version == 6 else 0x0800
        return MAC_LOCAL + MAC_PEER + struct.pack("!H", ethertype) + ip

    def build(self, peer, direction, payload, ident=0):
        """Return a list of frames for one BGP message."""
        st = self._flow(peer)
        pip, lip = st["peer_ip"], st["local_ip"]
        frames = []
        if self.handshake and not st["started"]:
            st["started"] = True
            frames.append(self._frame(pip, lip, self._tcp(
                pip, lip, 179, st["local_port"], 0, 0, 0x02, b""), ident))
            frames.append(self._frame(lip, pip, self._tcp(
                lip, pip, st["local_port"], 179, 0, 1, 0x12, b""), ident))
            frames.append(self._frame(pip, lip, self._tcp(
                pip, lip, 179, st["local_port"], 1, 1, 0x10, b""), ident))
        if direction == "sent":
            src, dst, sport, dport = lip, pip, st["local_port"], 179
            seq = st["seq_local"]
            ack = st["seq_peer"]
            st["seq_local"] += len(payload)
        else:
            src, dst, sport, dport = pip, lip, 179, st["local_port"]
            seq = st["seq_peer"]
            ack = st["seq_local"]
            st["seq_peer"] += len(payload)
        tcp = self._tcp(src, dst, sport, dport, seq, ack, 0x18, payload)
        frames.append(self._frame(src, dst, tcp, ident))
        return frames


def write_pcap(path, records, local_addr=None, linktype=LINKTYPE_ETHERNET,
               handshake=False, base_time=None, pad_truncated=True):
    """records: list of {'event':LogEvent|None, 'raw':bytes, 'peer':str}.

    ``pad_truncated`` zero-fills a message whose hexdump was cut short so the
    TCP stream stays byte-aligned; without it Wireshark's reassembly glues the
    next message onto the tail of the short one and both dissect as garbage.
    Padding bytes are invented - the text/JSON output always flags which
    messages were short.
    """
    framer = Framer(local_addr=local_addr, linktype=linktype,
                    handshake=handshake)
    fallback = base_time if base_time is not None else time.time()
    count = 0
    with open(path, "wb") as fh:
        w = PcapWriter(fh, linktype=linktype)
        for i, rec in enumerate(records):
            ev = rec.get("event")
            ts = None
            if ev is not None and ev.timestamp is not None:
                ts = ev.timestamp.timestamp()
            if ts is None:
                ts = fallback + i * 0.001
            peer = rec.get("peer") or (ev.peer if ev else None) or "unknown"
            direction = rec.get("direction") or (ev.direction if ev
                                                 else "received")
            payload = rec["raw"]
            declared = rec.get("declared_length") or 0
            if pad_truncated and declared > len(payload):
                payload = payload + b"\x00" * (declared - len(payload))
            for frame in framer.build(peer, direction, payload,
                                      ident=i & 0xFFFF):
                w.packet(ts, frame)
                count += 1
    return count
