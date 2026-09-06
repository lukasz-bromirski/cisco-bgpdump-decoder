"""Command line interface."""

import argparse
import datetime as _dt
import os
import sys

from . import __version__
from . import constants as C
from .bgp import decode_stream, summarize
from .logparse import parse_log
from .render import jsonout, pcap as pcapout, text as textout
from .utils import hexs

FORMATS = ("txt", "json", "pcap", "hex", "summary")

LINKTYPES = {
    "ethernet": pcapout.LINKTYPE_ETHERNET,
    "raw": pcapout.LINKTYPE_RAW,
    "loop": pcapout.LINKTYPE_LOOP,
}


def build_parser():
    p = argparse.ArgumentParser(
        prog="cisco-bgpdump",
        description="Decode Cisco IOS/IOS-XE %BGP-x-MSGDUMP syslog hexdumps "
                    "into readable text, JSON, or a replayable pcap.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  cisco-bgpdump dump.txt\n"
            "  cisco-bgpdump dump.txt -f json -o decode.json\n"
            "  cisco-bgpdump dump.txt -f pcap -o bgp.pcap --year 2025\n"
            "  cisco-bgpdump dump.txt -f txt -f json -f pcap -o out/bgp\n"
            "  cat buffer.log | cisco-bgpdump - -f summary\n"
        ),
    )
    p.add_argument("input", nargs="*", default=["-"],
                   help="syslog text file(s); '-' reads stdin")
    p.add_argument("-f", "--format", action="append", choices=FORMATS,
                   help="output format, repeatable (default: txt)")
    p.add_argument("-o", "--output",
                   help="output file, or base name when several formats are "
                        "requested; default is stdout for text formats")
    p.add_argument("-V", "--version", action="version",
                   version="cisco-bgpdump " + __version__)

    g = p.add_argument_group("decoding")
    g.add_argument("--asn-width", choices=("auto", "2", "4"), default="auto",
                   help="AS_PATH ASN width (default: auto-detect per UPDATE)")
    g.add_argument("--add-path", action="append", metavar="AFI:SAFI",
                   help="treat this AFI:SAFI as ADD-PATH encoded, e.g. 2:1; "
                        "repeatable. Use 'ipv4' as shorthand for the legacy "
                        "IPv4 unicast NLRI fields.")
    g.add_argument("--extended-message", action="store_true",
                   help="allow RFC 8654 messages longer than 4096 bytes")
    g.add_argument("--strict", action="store_true",
                   help="exit non-zero if any message decoded with errors")

    g = p.add_argument_group("timestamps")
    g.add_argument("--year", type=int,
                   help="year to assume for 'Mon DD hh:mm:ss' stamps "
                        "(default: current year, rolled back if in future)")
    g.add_argument("--tz-offset", type=float, default=0.0, metavar="HOURS",
                   help="UTC offset of the router clock (default: 0)")

    g = p.add_argument_group("pcap framing")
    g.add_argument("--local-addr",
                   help="local BGP speaker address (default: %s / %s)"
                        % (pcapout.DEFAULT_LOCAL_V4, pcapout.DEFAULT_LOCAL_V6))
    g.add_argument("--linktype", choices=sorted(LINKTYPES), default="ethernet",
                   help="pcap link layer (default: ethernet)")
    g.add_argument("--handshake", action="store_true",
                   help="emit a synthetic TCP three-way handshake per peer")
    g.add_argument("--skip-truncated", action="store_true",
                   help="leave messages whose dump is short out of the pcap "
                        "entirely; the remaining ones then dissect cleanly")
    g.add_argument("--no-pad", dest="pad", action="store_false", default=True,
                   help="do not zero-pad truncated messages to their declared "
                        "length (padding keeps Wireshark's TCP reassembly "
                        "aligned; the padding itself is synthetic)")

    g = p.add_argument_group("text output")
    g.add_argument("-x", "--hex", action="store_true",
                   help="append a hexdump of every message")
    g.add_argument("--wide", action="store_true",
                   help="do not truncate long AS paths")
    g.add_argument("--max-path", type=int, default=0, metavar="CHARS",
                   help="also print the expanded AS path, cut at CHARS")
    return p


def _parse_add_path(values):
    out = set()
    legacy_v4 = False
    for v in values or []:
        if v.lower() in ("ipv4", "v4", "1:1"):
            legacy_v4 = True
            out.add((1, 1))
            continue
        try:
            afi, safi = v.split(":")
            out.add((int(afi), int(safi)))
        except ValueError:
            raise SystemExit("bad --add-path value %r (expected AFI:SAFI)" % v)
    return out, legacy_v4


def _read_inputs(paths):
    chunks = []
    names = []
    for path in paths:
        if path == "-":
            chunks.append(sys.stdin.read())
            names.append("<stdin>")
        else:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                chunks.append(fh.read())
            names.append(path)
    return "\n".join(chunks), ", ".join(names)


def run(argv=None):
    args = build_parser().parse_args(argv)
    formats = args.format or ["txt"]
    tz = _dt.timezone(_dt.timedelta(hours=args.tz_offset))

    raw_text, source = _read_inputs(args.input)
    events = parse_log(raw_text, year=args.year, tz=tz)

    ap_set, legacy_v4 = _parse_add_path(args.add_path)
    options = {
        "asn_width": args.asn_width,
        "add_path_afi_safi": ap_set,
        "add_path_ipv4": legacy_v4,
        "extended_message": args.extended_message,
    }

    records = []
    for ev in events:
        if not ev.has_dump:
            continue
        msgs, _ = decode_stream(ev.data, options)
        for m in msgs:
            start = m["offset"]
            raw = ev.data[start:start + m["captured_length"]]
            records.append({"event": ev, "message": m, "raw": raw,
                            "declared_length": m["length"],
                            "peer": ev.peer, "direction": ev.direction})

    if not records:
        sys.stderr.write(
            "no BGP hexdumps found. Expected lines such as:\n"
            "  %BGP-6-MSGDUMP_LIMIT: ... received from <peer>:\n"
            "  FFFF FFFF FFFF FFFF ...\n")

    meta = {
        "source": source,
        "events_parsed": len(events),
        "dumps_found": sum(1 for e in events if e.has_dump),
        "asn_width": args.asn_width,
        "assumed_year": args.year or "current-year heuristic",
        "tz_offset_hours": args.tz_offset,
    }

    _emit(args, formats, records, events, source, meta)

    if args.strict:
        st = summarize([r["message"] for r in records])
        if st["errors"]:
            return 2
    return 0


def _target(args, fmt, multiple):
    if not args.output:
        return None if fmt != "pcap" else "bgp.pcap"
    if not multiple:
        return args.output
    ext = {"txt": ".txt", "json": ".json", "pcap": ".pcap",
           "hex": ".hex", "summary": ".summary.txt"}[fmt]
    base = args.output
    for known in (".txt", ".json", ".pcap", ".hex"):
        if base.endswith(known):
            base = base[:-len(known)]
            break
    return base + ext


def _write(path, data, binary=False):
    if path is None:
        if binary:
            sys.stdout.buffer.write(data)
        else:
            sys.stdout.write(data)
        return
    d = os.path.dirname(os.path.abspath(path))
    if d and not os.path.isdir(d):
        os.makedirs(d, exist_ok=True)
    with open(path, "wb" if binary else "w",
              **({} if binary else {"encoding": "utf-8"})) as fh:
        fh.write(data)
    sys.stderr.write("wrote %s (%d bytes)\n" % (path, os.path.getsize(path)))


def _emit(args, formats, records, events, source, meta):
    multiple = len(formats) > 1
    for fmt in formats:
        path = _target(args, fmt, multiple)
        if fmt == "txt":
            _write(path, textout.render_text(
                records, events, source, show_hex=args.hex, wide=args.wide,
                max_path=args.max_path))
        elif fmt == "json":
            _write(path, jsonout.render_json(records, events, source, meta))
        elif fmt == "hex":
            lines = []
            for i, rec in enumerate(records, 1):
                ev = rec["event"]
                lines.append("# message %d  peer=%s  seq=%s  %s"
                             % (i, rec.get("peer"),
                                ev.seq if ev else "-",
                                ev.timestamp_text if ev else "-"))
                lines.append(hexs(rec["raw"], 1))
            _write(path, "\n".join(lines) + "\n")
        elif fmt == "summary":
            _write(path, _summary_text(records, meta))
        elif fmt == "pcap":
            if path is None:
                path = "bgp.pcap"
            pcap_records = records
            if args.skip_truncated:
                pcap_records = [r for r in records
                                if not r["message"]["truncated"]]
                dropped = len(records) - len(pcap_records)
                if dropped:
                    sys.stderr.write("skipped %d truncated message(s)\n"
                                     % dropped)
            n = pcapout.write_pcap(
                path, pcap_records, local_addr=args.local_addr,
                linktype=LINKTYPES[args.linktype], handshake=args.handshake,
                pad_truncated=args.pad)
            sys.stderr.write("wrote %s (%d packet(s), %d bytes)\n"
                             % (path, n, os.path.getsize(path)))


def _summary_text(records, meta):
    msgs = [r["message"] for r in records]
    st = summarize(msgs)
    lines = ["source            : %s" % meta.get("source"),
             "syslog events      : %s" % meta.get("events_parsed"),
             "hexdumps found     : %s" % meta.get("dumps_found"),
             "messages decoded   : %d" % st["total"],
             "truncated          : %d" % st["truncated"],
             "errors / warnings  : %d / %d" % (st["errors"], st["warnings"]),
             ""]
    lines.append("%-6s %-22s %-14s %-8s %s"
                 % ("#", "time", "peer", "type", "detail"))
    lines.append("-" * 96)
    for i, rec in enumerate(records, 1):
        ev = rec["event"]
        m = rec["message"]
        detail = _one_line(m)
        lines.append("%-6d %-22s %-14s %-8s %s"
                     % (i, (ev.timestamp_text or "-") if ev else "-",
                        (rec.get("peer") or "-")[:14],
                        m["type_name"][:8], detail))
    return "\n".join(lines) + "\n"


def _one_line(m):
    b = m.get("body") or {}
    if m["type"] != 2:
        return "len=%d" % m["length"]
    bits = []
    for a in b.get("path_attributes", []):
        if a["type_code"] == C.ATTR_AS_PATH and a.get("value"):
            bits.append("as_path=%d ASNs" % a["value"].get("as_count", 0))
        if a["type_code"] == C.ATTR_MP_REACH_NLRI and a.get("value"):
            pfx = [p["prefix"] for p in a["value"].get("nlri", [])]
            if pfx:
                bits.append("nlri=" + ",".join(pfx[:3]))
    if b.get("nlri"):
        bits.append("v4nlri=" + ",".join(p["prefix"] for p in b["nlri"][:3]))
    if b.get("withdrawn_routes"):
        bits.append("withdraw=%d" % len(b["withdrawn_routes"]))
    bits.append("len=%d" % m["length"])
    return "  ".join(bits)


def main():
    try:
        sys.exit(run())
    except BrokenPipeError:
        sys.exit(0)
    except KeyboardInterrupt:
        sys.exit(130)
