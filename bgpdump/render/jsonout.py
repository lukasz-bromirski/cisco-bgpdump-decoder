"""JSON renderer: the full decode tree, machine readable."""

import json

from ..bgp import summarize


def build(records, events=None, source=None, meta=None):
    msgs = []
    for idx, rec in enumerate(records, 1):
        ev = rec.get("event")
        item = {"index": idx, "message": rec["message"]}
        if ev is not None:
            item["log"] = {
                "sequence": ev.seq,
                "line": ev.line_no,
                "timestamp": ev.timestamp.isoformat() if ev.timestamp else None,
                "timestamp_text": ev.timestamp_text,
                "timestamp_kind": ev.timestamp_kind,
                "mnemonic": ev.mnemonic,
                "severity": ev.severity,
                "text": ev.text,
                "peer": ev.peer,
                "direction": ev.direction,
                "hex_lines": ev.hex_lines,
                "syslog_chunks": ev.chunks,
                "syslog_msg_id": ev.msg_id,
                "ended_on_half_byte": ev.odd_nibble,
                "dump_bytes": len(ev.data),
            }
        msgs.append(item)

    doc = {
        "tool": "cisco-bgpdump",
        "source": source,
        "meta": meta or {},
        "summary": summarize([r["message"] for r in records]),
        "messages": msgs,
    }
    if events:
        doc["other_events"] = [
            {
                "sequence": e.seq,
                "line": e.line_no,
                "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                "timestamp_text": e.timestamp_text,
                "mnemonic": e.mnemonic,
                "severity": e.severity,
                "text": e.text,
                "peer": e.peer,
            }
            for e in events if not e.has_dump
        ]
    return doc


def render_json(records, events=None, source=None, meta=None, indent=2):
    return json.dumps(build(records, events, source, meta),
                      indent=indent, sort_keys=False) + "\n"
