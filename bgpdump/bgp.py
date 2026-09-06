"""BGP-4 wire format decoder (RFC 4271 + common extensions).

decode_stream() takes the raw bytes recovered from a Cisco hexdump and
returns a list of decoded message dicts.  Every decoder is defensive: a
malformed field produces an ``issue`` entry rather than an exception, since
the whole point of this tool is looking at messages Cisco already called
"unsupported or mal-formatted".
"""

import ipaddress

from . import constants as C
from .utils import (Reader, ReadError, asdot, collapse, format_rd, hexs,
                    ip_from_bytes, read_labels, read_prefix)

ERROR = "error"
WARNING = "warning"
INFO = "info"


def _issue(bag, severity, text):
    bag.append({"severity": severity, "text": text})


def flags_repr(flags):
    names = []
    names.append("Optional" if flags & 0x80 else "Well-known")
    names.append("Transitive" if flags & 0x40 else "Non-transitive")
    if flags & 0x20:
        names.append("Partial")
    if flags & 0x10:
        names.append("Extended-Length")
    if flags & 0x0F:
        names.append("Reserved-bits-set(0x%02X)" % (flags & 0x0F))
    return "0x%02X (%s)" % (flags, ", ".join(names))


def decode_flags(flags):
    return {
        "raw": flags,
        "optional": bool(flags & 0x80),
        "transitive": bool(flags & 0x40),
        "partial": bool(flags & 0x20),
        "extended_length": bool(flags & 0x10),
        "repr": flags_repr(flags),
    }


# --------------------------------------------------------------------------
# message framing
# --------------------------------------------------------------------------

def decode_stream(data, options=None):
    """Decode back-to-back BGP messages out of ``data``.

    Returns (messages, trailing_bytes).
    """
    options = options or {}
    messages = []
    off = 0
    n = len(data)
    while off < n:
        if n - off < C.BGP_HEADER_LEN:
            # Not even a header: keep it as a truncated remnant.
            messages.append(_truncated_header(data[off:], off))
            off = n
            break
        msg = decode_message(data[off:], options)
        msg["offset"] = off
        messages.append(msg)
        consumed = msg["captured_length"]
        if consumed <= 0:
            break
        off += consumed
    return messages, b""


def _truncated_header(chunk, off):
    return {
        "offset": off,
        "marker_ok": chunk.startswith(C.BGP_MARKER[:len(chunk)]),
        "length": None,
        "captured_length": len(chunk),
        "truncated": True,
        "type": None,
        "type_name": "<incomplete header>",
        "raw_hex": hexs(chunk, 1),
        "issues": [{"severity": ERROR,
                    "text": "only %d byte(s) of a 19-byte BGP header present"
                            % len(chunk)}],
        "body": {},
    }


def decode_message(data, options=None):
    options = options or {}
    issues = []
    marker = data[:16]
    marker_ok = marker == C.BGP_MARKER
    if not marker_ok:
        _issue(issues, ERROR,
               "BGP marker is not 16x0xFF (got %s)" % hexs(marker, 2))
    length = int.from_bytes(data[16:18], "big")
    mtype = data[18]

    limit = (C.BGP_MAX_EXTENDED_MESSAGE_LEN if options.get("extended_message")
             else C.BGP_MAX_MESSAGE_LEN)
    if length < C.BGP_HEADER_LEN:
        _issue(issues, ERROR, "header Length %d is below the 19-byte minimum"
               % length)
    elif length > limit:
        _issue(issues, ERROR,
               "header Length %d exceeds the %d-byte maximum "
               "(RFC 4271 / RFC 8654)" % (length, limit))

    available = len(data)
    captured = min(max(length, C.BGP_HEADER_LEN), available)
    truncated = length > available
    if truncated:
        _issue(issues, WARNING,
               "hexdump holds %d of %d byte(s) - the dump is short (router "
               "dump limit, or bytes lost copying out of the syslog buffer). "
               "Decoding past the cut is unreliable and the errors below are "
               "a consequence, not necessarily a real protocol fault."
               % (available, length))

    body_bytes = data[C.BGP_HEADER_LEN:captured]
    msg = {
        "marker_ok": marker_ok,
        "length": length,
        "captured_length": captured,
        "truncated": truncated,
        "type": mtype,
        "type_name": C.MSG_TYPES.get(mtype, "UNKNOWN(%d)" % mtype),
        "raw_hex": hexs(data[:captured], 1),
        "issues": issues,
        "body": {},
    }
    if mtype not in C.MSG_TYPES:
        _issue(issues, ERROR, "unknown message type %d" % mtype)
        msg["body"] = {"raw_hex": hexs(body_bytes, 1)}
        return msg

    try:
        if mtype == 1:
            msg["body"] = decode_open(body_bytes, issues)
        elif mtype == 2:
            msg["body"] = decode_update(body_bytes, issues, options)
        elif mtype == 3:
            msg["body"] = decode_notification(body_bytes, issues)
        elif mtype == 4:
            msg["body"] = {}
            if body_bytes:
                _issue(issues, WARNING,
                       "KEEPALIVE carries %d unexpected payload byte(s)"
                       % len(body_bytes))
        elif mtype == 5:
            msg["body"] = decode_route_refresh(body_bytes, issues)
    except ReadError as exc:
        _issue(issues, ERROR, "decode stopped: %s" % exc)
        msg["body"].setdefault("raw_hex", hexs(body_bytes, 1))
    return msg


# --------------------------------------------------------------------------
# OPEN
# --------------------------------------------------------------------------

def decode_open(body, issues):
    r = Reader(body)
    out = {
        "version": r.u8(),
        "my_as": r.u16(),
        "hold_time": r.u16(),
        "bgp_identifier": ip_from_bytes(r.take(4), 4),
    }
    optlen = r.u8()
    out["opt_param_len"] = optlen
    if optlen == 255 and r.remaining >= 3:
        # RFC 9072 extended optional parameters length
        if body[10] == 255:
            pass
    params = []
    pr = r.sub(min(optlen, r.remaining))
    while pr.remaining >= 2:
        ptype = pr.u8()
        plen = pr.u8()
        pdata = pr.take(min(plen, pr.remaining))
        if ptype == 2:
            params.append({"type": ptype, "type_name": "Capabilities",
                           "capabilities": decode_capabilities(pdata, issues)})
        else:
            params.append({"type": ptype, "type_name": "Unknown(%d)" % ptype,
                           "raw_hex": hexs(pdata, 1)})
    out["optional_parameters"] = params
    if out["version"] != 4:
        _issue(issues, WARNING, "BGP version %d (expected 4)" % out["version"])
    if out["my_as"] == 23456:
        _issue(issues, INFO,
               "My AS is AS_TRANS (23456); real ASN is in capability 65")
    return out


def decode_capabilities(data, issues):
    caps = []
    r = Reader(data)
    while r.remaining >= 2:
        code = r.u8()
        clen = r.u8()
        val = r.take(min(clen, r.remaining))
        cap = {"code": code,
               "name": C.CAPABILITIES.get(code, "Unknown(%d)" % code),
               "length": clen,
               "raw_hex": hexs(val, 1)}
        try:
            if code == 1 and len(val) >= 4:
                afi = int.from_bytes(val[0:2], "big")
                safi = val[3]
                cap["afi"] = afi
                cap["afi_name"] = C.AFI.get(afi, "Unknown(%d)" % afi)
                cap["safi"] = safi
                cap["safi_name"] = C.SAFI.get(safi, "Unknown(%d)" % safi)
            elif code == 65 and len(val) >= 4:
                cap["as4"] = int.from_bytes(val[0:4], "big")
            elif code == 69:
                items = []
                for i in range(0, len(val) - 3, 4):
                    afi = int.from_bytes(val[i:i + 2], "big")
                    items.append({
                        "afi": afi,
                        "afi_name": C.AFI.get(afi, "Unknown(%d)" % afi),
                        "safi": val[i + 2],
                        "safi_name": C.SAFI.get(val[i + 2],
                                                "Unknown(%d)" % val[i + 2]),
                        "mode": C.ADD_PATH_SEND_RECEIVE.get(
                            val[i + 3], "Unknown(%d)" % val[i + 3]),
                    })
                cap["add_path"] = items
            elif code == 64 and len(val) >= 2:
                flags_time = int.from_bytes(val[0:2], "big")
                cap["restart_flags"] = flags_time >> 12
                cap["restart_time"] = flags_time & 0x0FFF
            elif code == 73:
                if val:
                    hn = val[1:1 + val[0]]
                    rest = val[1 + val[0]:]
                    dom = rest[1:1 + rest[0]] if rest else b""
                    cap["hostname"] = hn.decode("ascii", "replace")
                    cap["domain"] = dom.decode("ascii", "replace")
            elif code == 9 and len(val) >= 1:
                cap["role"] = val[0]
        except Exception as exc:  # keep going on any odd capability
            _issue(issues, WARNING,
                   "capability %d could not be decoded: %s" % (code, exc))
        caps.append(cap)
    return caps


# --------------------------------------------------------------------------
# NOTIFICATION / ROUTE-REFRESH
# --------------------------------------------------------------------------

def decode_notification(body, issues):
    r = Reader(body)
    code = r.u8()
    sub = r.u8()
    data = r.rest()
    out = {
        "error_code": code,
        "error_name": C.NOTIFY_CODES.get(code, "Unknown(%d)" % code),
        "error_subcode": sub,
        "error_subname": C.NOTIFY_SUBCODES.get(code, {}).get(
            sub, "Unknown(%d)" % sub),
        "data_hex": hexs(data, 1),
    }
    if code == 6 and sub in (2, 4) and data:
        # RFC 9003 shutdown communication
        ln = data[0]
        out["shutdown_communication"] = data[1:1 + ln].decode("utf-8", "replace")
    return out


def decode_route_refresh(body, issues):
    r = Reader(body)
    afi = r.u16()
    subtype = r.u8()
    safi = r.u8()
    return {
        "afi": afi, "afi_name": C.AFI.get(afi, "Unknown(%d)" % afi),
        "safi": safi, "safi_name": C.SAFI.get(safi, "Unknown(%d)" % safi),
        "subtype": subtype,
        "subtype_name": C.ROUTE_REFRESH_SUBTYPE.get(subtype,
                                                    "Unknown(%d)" % subtype),
        "orf_hex": hexs(r.rest(), 1),
    }


# --------------------------------------------------------------------------
# UPDATE
# --------------------------------------------------------------------------

def decode_update(body, issues, options):
    r = Reader(body)
    out = {}
    wlen = r.u16()
    out["withdrawn_routes_length"] = wlen
    if wlen > r.remaining:
        _issue(issues, ERROR,
               "Withdrawn Routes Length %d exceeds the %d remaining byte(s)"
               % (wlen, r.remaining))
        wlen = r.remaining
    wr = r.sub(wlen)
    withdrawn = []
    add_path_v4 = options.get("add_path_ipv4", False)
    while wr.remaining:
        try:
            withdrawn.append(read_prefix(wr, 4, add_path_v4))
        except ReadError as exc:
            _issue(issues, ERROR, "withdrawn routes: %s" % exc)
            break
    out["withdrawn_routes"] = withdrawn

    if r.remaining < 2:
        _issue(issues, ERROR, "UPDATE ends before Total Path Attribute Length")
        out["path_attributes"] = []
        out["nlri"] = []
        return out

    plen = r.u16()
    out["total_path_attribute_length"] = plen
    if plen > r.remaining:
        _issue(issues, ERROR,
               "Total Path Attribute Length %d exceeds the %d remaining byte(s)"
               % (plen, r.remaining))
        plen = r.remaining
    attr_bytes = r.take(plen)

    raw_attrs = _split_attributes(attr_bytes, issues)
    present = {a["type_code"] for a in raw_attrs}
    ctx = dict(options)
    if options.get("asn_width", "auto") == "auto":
        # RFC 6793: an AS4_PATH is only ever sent by a NEW speaker to an OLD
        # one, so its presence means AS_PATH carries 2-octet ASNs.
        ctx["asn_width_hint"] = 2 if C.ATTR_AS4_PATH in present else None
    else:
        ctx["asn_width_hint"] = int(options["asn_width"])

    attrs = [_decode_attribute(a, issues, ctx) for a in raw_attrs]
    out["path_attributes"] = attrs

    nlri = []
    while r.remaining:
        try:
            nlri.append(read_prefix(r, 4, add_path_v4))
        except ReadError as exc:
            _issue(issues, ERROR, "NLRI: %s" % exc)
            break
    out["nlri"] = nlri

    _check_update_semantics(out, present, issues)
    return out


def _split_attributes(buf, issues):
    """First pass: carve the TLVs without interpreting the values."""
    r = Reader(buf)
    attrs = []
    while r.remaining:
        start = r.off
        if r.remaining < 2:
            _issue(issues, ERROR,
                   "%d stray byte(s) at end of path attributes"
                   % r.remaining)
            break
        flags = r.u8()
        tcode = r.u8()
        try:
            alen = r.u16() if flags & 0x10 else r.u8()
        except ReadError as exc:
            _issue(issues, ERROR, "attribute %d: %s" % (tcode, exc))
            break
        if alen > r.remaining:
            _issue(issues, ERROR,
                   "attribute %s length %d exceeds the %d remaining byte(s)"
                   % (C.ATTR_TYPES.get(tcode, tcode), alen, r.remaining))
            alen = r.remaining
        value = r.take(alen)
        attrs.append({
            "offset": start,
            "flags": flags,
            "type_code": tcode,
            "length": alen,
            "value": value,
        })
    return attrs


def _decode_attribute(raw, issues, ctx):
    tcode = raw["type_code"]
    flags = raw["flags"]
    value = raw["value"]
    a = {
        "offset": raw["offset"],
        "type_code": tcode,
        "type_name": C.ATTR_TYPES.get(tcode, "UNKNOWN(%d)" % tcode),
        "flags": decode_flags(flags),
        "length": raw["length"],
        "value_hex": hexs(value, 1),
        "issues": [],
    }
    _check_attr_flags(a, issues)

    try:
        _decode_attr_value(a, tcode, value, ctx)
    except (ReadError, ValueError) as exc:
        _issue(a["issues"], ERROR, "value decode failed: %s" % exc)
        _issue(issues, ERROR,
               "%s attribute: %s" % (a["type_name"], exc))
    return a


def _check_attr_flags(a, issues):
    tcode = a["type_code"]
    f = a["flags"]
    if tcode in C.ATTR_TYPES and tcode in C.WELL_KNOWN_ATTRS | {
            C.ATTR_AGGREGATOR, C.ATTR_AS_PATH}:
        pass
    known_wellknown = tcode in C.WELL_KNOWN_ATTRS
    if known_wellknown:
        if f["optional"]:
            _issue(a["issues"], ERROR,
                   "well-known attribute must have Optional bit clear")
        if not f["transitive"]:
            _issue(a["issues"], ERROR,
                   "well-known attribute must have Transitive bit set")
        if f["partial"]:
            _issue(a["issues"], ERROR,
                   "well-known attribute must have Partial bit clear")
    if f["raw"] & 0x0F:
        _issue(a["issues"], WARNING,
               "low-order flag bits are reserved and must be zero")
    if not f["optional"] and f["partial"]:
        _issue(a["issues"], ERROR, "Partial bit set on a well-known attribute")
    for it in a["issues"]:
        if it["severity"] == ERROR:
            _issue(issues, ERROR, "%s: %s" % (a["type_name"], it["text"]))


def _decode_attr_value(a, tcode, value, ctx):
    r = Reader(value)
    if tcode == C.ATTR_ORIGIN:
        v = r.u8()
        a["value"] = {"origin": v,
                      "origin_name": C.ORIGIN_TYPES.get(v, "INVALID(%d)" % v)}
        if v not in C.ORIGIN_TYPES:
            _issue(a["issues"], ERROR, "invalid ORIGIN value %d" % v)
        if len(value) != 1:
            _issue(a["issues"], ERROR,
                   "ORIGIN length must be 1, got %d" % len(value))

    elif tcode in (C.ATTR_AS_PATH, C.ATTR_AS4_PATH):
        width = 4 if tcode == C.ATTR_AS4_PATH else ctx.get("asn_width_hint")
        a["value"] = decode_as_path(value, width, a["issues"])

    elif tcode == C.ATTR_NEXT_HOP:
        a["value"] = {"next_hop": ip_from_bytes(r.take(4), 4)}
        if len(value) != 4:
            _issue(a["issues"], ERROR,
                   "NEXT_HOP length must be 4, got %d" % len(value))

    elif tcode in (C.ATTR_MED, C.ATTR_LOCAL_PREF):
        a["value"] = {"value": r.u32()}
        if len(value) != 4:
            _issue(a["issues"], ERROR,
                   "%s length must be 4, got %d" % (a["type_name"], len(value)))

    elif tcode == C.ATTR_ATOMIC_AGGREGATE:
        a["value"] = {}
        if len(value) != 0:
            _issue(a["issues"], ERROR,
                   "ATOMIC_AGGREGATE length must be 0, got %d" % len(value))

    elif tcode in (C.ATTR_AGGREGATOR, C.ATTR_AS4_AGGREGATOR):
        if len(value) == 8 or tcode == C.ATTR_AS4_AGGREGATOR:
            asn = r.u32()
        else:
            asn = r.u16()
        a["value"] = {"as": asn, "asdot": asdot(asn),
                      "address": ip_from_bytes(r.take(4), 4)}

    elif tcode == C.ATTR_COMMUNITIES:
        comms = []
        while r.remaining >= 4:
            v = r.u32()
            hi, lo = v >> 16, v & 0xFFFF
            item = {"value": v, "text": "%d:%d" % (hi, lo)}
            if v in C.WELL_KNOWN_COMMUNITIES:
                item["well_known"] = C.WELL_KNOWN_COMMUNITIES[v]
            comms.append(item)
        if r.remaining:
            _issue(a["issues"], ERROR,
                   "COMMUNITIES length %d is not a multiple of 4" % len(value))
        a["value"] = {"communities": comms}

    elif tcode == C.ATTR_LARGE_COMMUNITY:
        comms = []
        while r.remaining >= 12:
            ga, l1, l2 = r.u32(), r.u32(), r.u32()
            comms.append({"global": ga, "local1": l1, "local2": l2,
                          "text": "%d:%d:%d" % (ga, l1, l2)})
        if r.remaining:
            _issue(a["issues"], ERROR,
                   "LARGE_COMMUNITY length %d is not a multiple of 12"
                   % len(value))
        a["value"] = {"large_communities": comms}

    elif tcode == C.ATTR_EXT_COMMUNITIES:
        comms = []
        while r.remaining >= 8:
            comms.append(decode_ext_community(r.take(8)))
        if r.remaining:
            _issue(a["issues"], ERROR,
                   "EXTENDED_COMMUNITIES length %d is not a multiple of 8"
                   % len(value))
        a["value"] = {"extended_communities": comms}

    elif tcode == C.ATTR_IPV6_EXT_COMMUNITIES:
        comms = []
        while r.remaining >= 20:
            blob = r.take(20)
            comms.append({
                "type": blob[0], "subtype": blob[1],
                "global": ip_from_bytes(blob[2:18], 6),
                "local": int.from_bytes(blob[18:20], "big"),
                "text": "%s:%s:%d" % (
                    C.EXTCOMM_SUBTYPE_AS.get(blob[1], "0x%02X" % blob[1]),
                    ip_from_bytes(blob[2:18], 6),
                    int.from_bytes(blob[18:20], "big")),
            })
        a["value"] = {"ipv6_extended_communities": comms}

    elif tcode == C.ATTR_ORIGINATOR_ID:
        a["value"] = {"originator_id": ip_from_bytes(r.take(4), 4)}

    elif tcode == C.ATTR_CLUSTER_LIST:
        ids = []
        while r.remaining >= 4:
            ids.append(ip_from_bytes(r.take(4), 4))
        a["value"] = {"cluster_list": ids}

    elif tcode == C.ATTR_MP_REACH_NLRI:
        a["value"] = decode_mp_reach(value, a["issues"], ctx)

    elif tcode == C.ATTR_MP_UNREACH_NLRI:
        a["value"] = decode_mp_unreach(value, a["issues"], ctx)

    elif tcode == C.ATTR_AIGP:
        tlvs = []
        while r.remaining >= 3:
            t = r.u8()
            ln = r.u16()
            body = r.take(max(0, min(ln - 3, r.remaining)))
            tlvs.append({"type": t,
                         "metric": int.from_bytes(body, "big") if t == 1
                         else None,
                         "raw_hex": hexs(body, 1)})
        a["value"] = {"tlvs": tlvs}

    elif tcode == C.ATTR_OTC:
        a["value"] = {"only_to_customer_as": r.u32()}

    else:
        a["value"] = {"raw_hex": hexs(value, 1)}


def decode_as_path(value, width_hint, issues):
    """Decode AS_PATH, auto-detecting 2- vs 4-octet ASNs when needed."""
    candidates = [4, 2] if width_hint is None else [width_hint]
    best = None
    for width in candidates:
        try:
            segs, consumed = _parse_as_path(value, width)
        except ReadError:
            continue
        if consumed == len(value):
            best = (width, segs)
            break
    if best is None:
        # Nothing fits exactly; report the closest 4-octet attempt.
        width = width_hint or 4
        try:
            segs, consumed = _parse_as_path(value, width)
        except ReadError as exc:
            _issue(issues, ERROR, "AS_PATH is malformed: %s" % exc)
            return {"asn_width": width,
                    "asn_width_source": ("explicit" if width_hint
                                         else "auto-detected"),
                    "segments": [], "as_count": 0, "asn_list": [],
                    "path": "", "path_collapsed": "",
                    "raw_hex": hexs(value, 1)}
        _issue(issues, ERROR,
               "AS_PATH segments consume %d of %d byte(s) - malformed or an "
               "ASN width mismatch" % (consumed, len(value)))
        best = (width, segs)

    width, segs = best
    flat = []
    for s in segs:
        flat.extend(s["asns"])
    out = {
        "asn_width": width,
        "asn_width_source": "explicit" if width_hint else "auto-detected",
        "segments": segs,
        "as_count": sum(len(s["asns"]) if s["type"] != 1 else 1 for s in segs),
        "asn_list": flat,
        "path": " ".join(str(x) for x in flat),
        "path_collapsed": collapse(flat),
        "distinct_asns": sorted(set(flat)),
    }
    for s in segs:
        if s["type"] not in C.AS_PATH_SEGMENT_TYPES:
            _issue(issues, ERROR,
                   "invalid AS_PATH segment type %d" % s["type"])
        if s["count"] == 0:
            _issue(issues, ERROR, "AS_PATH segment with zero ASNs")
    if 0 in flat:
        _issue(issues, ERROR, "AS_PATH contains AS 0 (RFC 7607 forbids it)")
    return out


def _parse_as_path(value, width):
    r = Reader(value)
    segs = []
    while r.remaining:
        stype = r.u8()
        count = r.u8()
        need = count * width
        if need > r.remaining:
            raise ReadError("segment needs %d byte(s), %d left"
                            % (need, r.remaining))
        asns = []
        for _ in range(count):
            asns.append(r.u32() if width == 4 else r.u16())
        segs.append({
            "type": stype,
            "type_name": C.AS_PATH_SEGMENT_TYPES.get(stype,
                                                     "INVALID(%d)" % stype),
            "count": count,
            "asns": asns,
            "collapsed": collapse(asns),
        })
    return segs, r.off


def decode_ext_community(raw):
    hi, sub = raw[0], raw[1]
    out = {
        "type": hi,
        "subtype": sub,
        "type_name": C.EXTCOMM_TYPE_HIGH.get(hi, "Unknown(0x%02X)" % hi),
        "raw_hex": hexs(raw, 1),
    }
    base = hi & 0x3F  # strip transitivity bit for structure lookup
    sub_name = None
    if base in (0x00, 0x02):
        sub_name = C.EXTCOMM_SUBTYPE_AS.get(sub)
    elif base == 0x01:
        sub_name = C.EXTCOMM_SUBTYPE_AS.get(sub)
    elif base == 0x03:
        sub_name = C.EXTCOMM_SUBTYPE_OPAQUE.get(sub)
    out["subtype_name"] = sub_name or "Unknown(0x%02X)" % sub

    prefix = {0x02: "RT", 0x03: "SoO", 0x09: "SoAS"}.get(sub, "0x%02X" % sub)
    if base == 0x00:      # 2-octet AS : 4-octet local
        ga = int.from_bytes(raw[2:4], "big")
        la = int.from_bytes(raw[4:8], "big")
        out["global"] = ga
        out["local"] = la
        out["text"] = "%s:%d:%d" % (prefix, ga, la)
    elif base == 0x01:    # IPv4 : 2-octet local
        ga = ip_from_bytes(raw[2:6], 4)
        la = int.from_bytes(raw[6:8], "big")
        out["global"] = ga
        out["local"] = la
        out["text"] = "%s:%s:%d" % (prefix, ga, la)
    elif base == 0x02:    # 4-octet AS : 2-octet local
        ga = int.from_bytes(raw[2:6], "big")
        la = int.from_bytes(raw[6:8], "big")
        out["global"] = ga
        out["local"] = la
        out["text"] = "%s:%d:%d" % (prefix, ga, la)
    elif base == 0x03 and sub == 0x0B:
        out["color"] = int.from_bytes(raw[4:8], "big")
        out["text"] = "Color:%d" % out["color"]
    elif base == 0x03 and sub == 0x0C:
        out["tunnel_type"] = int.from_bytes(raw[6:8], "big")
        out["text"] = "Encapsulation:%d" % out["tunnel_type"]
    else:
        out["text"] = "%s/%s:%s" % (out["type_name"], out["subtype_name"],
                                    hexs(raw[2:], 1, ""))
    return out


# ---------------------------------------------------------------- MP-BGP

def _nexthop_family(afi, nhlen):
    if nhlen in (4, 12):
        return 4
    return 6


def decode_mp_nexthop(afi, raw, issues):
    """RFC 4760 / RFC 2545 next hop field."""
    n = len(raw)
    out = {"length": n, "raw_hex": hexs(raw, 1), "addresses": []}
    if n == 4:
        out["addresses"] = [ip_from_bytes(raw, 4)]
    elif n == 16:
        out["addresses"] = [ip_from_bytes(raw, 6)]
    elif n == 32:
        out["addresses"] = [ip_from_bytes(raw[0:16], 6),
                            ip_from_bytes(raw[16:32], 6)]
        out["link_local"] = out["addresses"][1]
    elif n == 12:
        out["rd"] = format_rd(raw[0:8])
        out["addresses"] = [ip_from_bytes(raw[8:12], 4)]
    elif n == 24:
        out["rd"] = format_rd(raw[0:8])
        out["addresses"] = [ip_from_bytes(raw[8:24], 6)]
    elif n == 48:
        out["rd"] = format_rd(raw[0:8])
        out["addresses"] = [ip_from_bytes(raw[8:24], 6),
                            ip_from_bytes(raw[32:48], 6)]
        out["link_local"] = out["addresses"][1]
    else:
        _issue(issues, WARNING,
               "unexpected MP next hop length %d" % n)
    out["text"] = ", ".join(out["addresses"]) if out["addresses"] else hexs(raw, 1)
    return out


def _mp_nlri_family(afi):
    return 4 if afi == 1 else 6


def _read_mp_nlri(r, afi, safi, add_path, issues):
    entries = []
    fam = _mp_nlri_family(afi)
    labeled = safi in (4, 128, 129)
    vpn = safi in (128, 129)
    while r.remaining:
        try:
            entry = {}
            if add_path:
                entry["path_id"] = r.u32()
            bits = r.u8()
            consumed_bits = 0
            if labeled:
                labels, _ = read_labels(r)
                entry["labels"] = labels
                consumed_bits += 24 * len(labels)
            if vpn:
                entry["rd"] = format_rd(r.take(8))
                consumed_bits += 64
            plen = bits - consumed_bits
            if plen < 0:
                _issue(issues, ERROR,
                       "MP NLRI: prefix length %d smaller than label/RD "
                       "overhead" % bits)
                break
            nbytes = (plen + 7) // 8
            raw = r.take(nbytes)
            entry["prefix"] = "%s/%d" % (ip_from_bytes(raw, fam), plen)
            entry["length"] = plen
            entries.append(entry)
        except ReadError as exc:
            _issue(issues, ERROR, "MP NLRI: %s" % exc)
            break
    return entries


def _addpath_for(ctx, afi, safi):
    ap = ctx.get("add_path_afi_safi") or set()
    return (afi, safi) in ap


def decode_mp_reach(value, issues, ctx):
    r = Reader(value)
    afi = r.u16()
    safi = r.u8()
    nhlen = r.u8()
    nh = r.take(min(nhlen, r.remaining))
    out = {
        "afi": afi, "afi_name": C.AFI.get(afi, "Unknown(%d)" % afi),
        "safi": safi, "safi_name": C.SAFI.get(safi, "Unknown(%d)" % safi),
        "next_hop": decode_mp_nexthop(afi, nh, issues),
    }
    if r.remaining:
        out["reserved"] = r.u8()
        if out["reserved"] != 0:
            _issue(issues, WARNING,
                   "MP_REACH_NLRI reserved octet is 0x%02X, not 0"
                   % out["reserved"])
    out["nlri"] = _read_mp_nlri(r, afi, safi,
                                _addpath_for(ctx, afi, safi), issues)
    return out


def decode_mp_unreach(value, issues, ctx):
    r = Reader(value)
    afi = r.u16()
    safi = r.u8()
    out = {
        "afi": afi, "afi_name": C.AFI.get(afi, "Unknown(%d)" % afi),
        "safi": safi, "safi_name": C.SAFI.get(safi, "Unknown(%d)" % safi),
    }
    out["withdrawn_routes"] = _read_mp_nlri(r, afi, safi,
                                            _addpath_for(ctx, afi, safi),
                                            issues)
    return out


# --------------------------------------------------------------------------
# UPDATE-level sanity checks (RFC 4271 6.3, RFC 7606)
# --------------------------------------------------------------------------

def _check_update_semantics(upd, present, issues):
    seen = {}
    for a in upd["path_attributes"]:
        seen[a["type_code"]] = seen.get(a["type_code"], 0) + 1
    for tcode, count in seen.items():
        if count > 1:
            _issue(issues, ERROR,
                   "attribute %s appears %d times (RFC 7606: treat-as-withdraw)"
                   % (C.ATTR_TYPES.get(tcode, tcode), count))

    has_v4_nlri = bool(upd["nlri"])
    has_mp_reach = C.ATTR_MP_REACH_NLRI in present
    announces = has_v4_nlri or has_mp_reach

    if announces:
        for tcode in sorted(C.MANDATORY_ATTRS):
            if tcode not in present:
                _issue(issues, ERROR,
                       "missing well-known mandatory attribute %s"
                       % C.ATTR_TYPES[tcode])
        if has_v4_nlri and C.ATTR_NEXT_HOP not in present:
            _issue(issues, ERROR,
                   "IPv4 NLRI present but NEXT_HOP attribute is missing")
    elif not upd["withdrawn_routes"] and not present:
        _issue(issues, INFO,
               "End-of-RIB marker (no NLRI, no withdrawals, no attributes)")

    for a in upd["path_attributes"]:
        if a["type_code"] == C.ATTR_AS_PATH and a.get("value"):
            n = a["value"].get("as_count", 0)
            if n > 100:
                _issue(issues, WARNING,
                       "AS_PATH holds %d AS numbers - long enough to trip "
                       "'bgp maxas-limit' or a peer's own path-length guard"
                       % n)
            for seg in a["value"].get("segments", []):
                if seg["count"] == 255:
                    _issue(issues, INFO,
                           "an AS_PATH segment is at the 255-ASN maximum, so "
                           "the path spilled into another segment")


def summarize(messages):
    """Aggregate counters used by the text/JSON summary blocks."""
    stats = {"total": len(messages), "by_type": {}, "errors": 0,
             "warnings": 0, "truncated": 0}
    for m in messages:
        stats["by_type"][m["type_name"]] = \
            stats["by_type"].get(m["type_name"], 0) + 1
        if m.get("truncated"):
            stats["truncated"] += 1
        for it in all_issues(m):
            if it["severity"] == ERROR:
                stats["errors"] += 1
            elif it["severity"] == WARNING:
                stats["warnings"] += 1
    return stats


def all_issues(msg):
    out = list(msg.get("issues", []))
    for a in msg.get("body", {}).get("path_attributes", []) or []:
        out.extend(a.get("issues", []))
    return out
