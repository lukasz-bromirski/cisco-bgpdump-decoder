"""Human-readable renderer."""

from .. import constants as C
from ..bgp import all_issues, summarize
from ..utils import hexdump

SEV_TAG = {"error": "ERROR  ", "warning": "WARNING", "info": "INFO   "}


class TextRenderer:
    def __init__(self, show_hex=False, wide=False, max_path=0):
        self.show_hex = show_hex
        self.wide = wide
        self.max_path = max_path
        self.out = []

    # ---------------------------------------------------------------- helpers
    def w(self, s=""):
        self.out.append(s)

    def kv(self, indent, key, value, width=28):
        self.w("%s%-*s : %s" % (indent, width, key, value))

    def render(self, records, events=None, source=None):
        self.w("=" * 78)
        self.w("Cisco BGP message dump decode")
        if source:
            self.kv("", "Source", source, 12)
        self.kv("", "Messages", str(len(records)), 12)
        self.w("=" * 78)

        for idx, rec in enumerate(records, 1):
            self._message(idx, rec)

        if events:
            extra = [e for e in events if not e.has_dump]
            if extra:
                self.w("")
                self.w("-" * 78)
                self.w("Related BGP syslog events without a hexdump")
                self.w("-" * 78)
                for e in extra:
                    ts = e.timestamp_text or "?"
                    self.w("  [%s] %%BGP-%d-%s: %s"
                           % (ts, e.severity, e.mnemonic, _trim(e.text, 160)))

        self._summary(records)
        return "\n".join(self.out) + "\n"

    # -------------------------------------------------------------- messages
    def _message(self, idx, rec):
        msg = rec["message"]
        ev = rec.get("event")
        self.w("")
        self.w("-" * 78)
        title = "Message %d  -  %s" % (idx, msg["type_name"])
        self.w(title)
        self.w("-" * 78)
        if ev is not None:
            if ev.seq is not None:
                self.kv("  ", "Syslog sequence", "%06d" % ev.seq)
            self.kv("  ", "Timestamp", ev.timestamp_text or "(none in log)")
            self.kv("  ", "Syslog mnemonic",
                    "%%BGP-%d-%s" % (ev.severity, ev.mnemonic))
            self.kv("  ", "Peer", "%s (%s)" % (ev.peer or "unknown",
                                               ev.direction))
            if ev.chunks > 1:
                self.kv("  ", "Syslog chunks",
                        "%d (stitched across **MSG %s TRUNCATED** seams)"
                        % (ev.chunks, ev.msg_id))
            if ev.text:
                self.kv("  ", "Log text", _trim(ev.text, 120))
        self.kv("  ", "Header marker",
                "valid" if msg["marker_ok"] else "INVALID")
        self.kv("  ", "Header length",
                "%s byte(s)%s" % (msg["length"],
                                  "" if not msg["truncated"]
                                  else "  [dump holds %d]"
                                  % msg["captured_length"]))
        self.kv("  ", "Type", "%s (%s)" % (msg["type"], msg["type_name"]))

        body = msg.get("body") or {}
        if msg["type"] == 1:
            self._open(body)
        elif msg["type"] == 2:
            self._update(body)
        elif msg["type"] == 3:
            self._notification(body)
        elif msg["type"] == 5:
            self._route_refresh(body)

        issues = all_issues(msg)
        if issues:
            self.w("")
            self.w("  Findings:")
            for it in issues:
                self.w("    %s  %s" % (SEV_TAG.get(it["severity"], "?"),
                                       it["text"]))
        if self.show_hex:
            self.w("")
            self.w("  Raw bytes:")
            raw = bytes.fromhex(msg["raw_hex"].replace(" ", ""))
            self.w(hexdump(raw, indent="    "))

    def _open(self, b):
        self.kv("  ", "Version", b.get("version"))
        self.kv("  ", "My AS", b.get("my_as"))
        self.kv("  ", "Hold time", "%s s" % b.get("hold_time"))
        self.kv("  ", "BGP identifier", b.get("bgp_identifier"))
        for p in b.get("optional_parameters", []):
            if "capabilities" not in p:
                self.kv("  ", "Optional param",
                        "%s %s" % (p["type_name"], p.get("raw_hex", "")))
                continue
            self.w("  Capabilities:")
            for c in p["capabilities"]:
                extra = []
                if "afi_name" in c:
                    extra.append("%s/%s" % (c["afi_name"], c["safi_name"]))
                if "as4" in c:
                    extra.append("AS %d" % c["as4"])
                if "hostname" in c:
                    extra.append("%s.%s" % (c["hostname"], c["domain"]))
                for ap in c.get("add_path", []):
                    extra.append("%s/%s %s" % (ap["afi_name"], ap["safi_name"],
                                               ap["mode"]))
                if "restart_time" in c:
                    extra.append("restart %ds" % c["restart_time"])
                self.w("    [%3d] %-40s %s"
                       % (c["code"], c["name"], " ".join(extra)))

    def _notification(self, b):
        self.kv("  ", "Error code", "%s (%s)" % (b.get("error_code"),
                                                 b.get("error_name")))
        self.kv("  ", "Error subcode", "%s (%s)" % (b.get("error_subcode"),
                                                    b.get("error_subname")))
        if b.get("shutdown_communication"):
            self.kv("  ", "Shutdown message", b["shutdown_communication"])
        if b.get("data_hex"):
            self.kv("  ", "Data", _trim(b["data_hex"], 120))

    def _route_refresh(self, b):
        self.kv("  ", "AFI/SAFI", "%s/%s" % (b.get("afi_name"),
                                             b.get("safi_name")))
        self.kv("  ", "Subtype", b.get("subtype_name"))

    def _update(self, b):
        self.kv("  ", "Withdrawn routes length",
                b.get("withdrawn_routes_length"))
        for wpfx in b.get("withdrawn_routes", []):
            self.w("      withdraw %s" % wpfx["prefix"])
        self.kv("  ", "Path attribute length",
                b.get("total_path_attribute_length"))
        attrs = b.get("path_attributes", [])
        if attrs:
            self.w("")
            self.w("  Path attributes (%d):" % len(attrs))
        for n, a in enumerate(attrs, 1):
            self.w("    [%d] %-24s len %-5d %s"
                   % (n, a["type_name"], a["length"], a["flags"]["repr"]))
            self._attr_value(a)
        nlri = b.get("nlri", [])
        if nlri:
            self.w("")
            self.w("  IPv4 NLRI (%d):" % len(nlri))
            for p in nlri:
                self.w("      %s" % p["prefix"])

    def _attr_value(self, a):
        v = a.get("value") or {}
        pad = "        "
        t = a["type_code"]
        if t == C.ATTR_ORIGIN:
            self.w(pad + "%s (%s)" % (v.get("origin_name"), v.get("origin")))
        elif t in (C.ATTR_AS_PATH, C.ATTR_AS4_PATH):
            self.w(pad + "%d-octet ASNs (%s), %d AS number(s)"
                   % (v.get("asn_width", 0), v.get("asn_width_source", "?"),
                      v.get("as_count", 0)))
            for s in v.get("segments", []):
                self.w(pad + "%s, count %d:" % (s["type_name"], s["count"]))
                self.w(pad + "  " + _trim(s["collapsed"], 0 if self.wide else 220))
            path = v.get("path", "")
            if path and (self.wide or self.max_path):
                limit = 0 if self.wide else self.max_path
                self.w(pad + "expanded: " + _trim(path, limit))
        elif t == C.ATTR_NEXT_HOP:
            self.w(pad + str(v.get("next_hop")))
        elif t in (C.ATTR_MED, C.ATTR_LOCAL_PREF):
            self.w(pad + str(v.get("value")))
        elif t in (C.ATTR_AGGREGATOR, C.ATTR_AS4_AGGREGATOR):
            self.w(pad + "AS %s, router %s" % (v.get("as"), v.get("address")))
        elif t == C.ATTR_COMMUNITIES:
            items = [c["text"] + (" (%s)" % c["well_known"]
                                  if "well_known" in c else "")
                     for c in v.get("communities", [])]
            self._wrap(pad, items)
        elif t == C.ATTR_LARGE_COMMUNITY:
            self._wrap(pad, [c["text"] for c in v.get("large_communities", [])])
        elif t == C.ATTR_EXT_COMMUNITIES:
            for c in v.get("extended_communities", []):
                self.w(pad + "%-28s [%s / %s]"
                       % (c["text"], c["type_name"], c["subtype_name"]))
        elif t == C.ATTR_IPV6_EXT_COMMUNITIES:
            for c in v.get("ipv6_extended_communities", []):
                self.w(pad + c["text"])
        elif t == C.ATTR_ORIGINATOR_ID:
            self.w(pad + str(v.get("originator_id")))
        elif t == C.ATTR_CLUSTER_LIST:
            self._wrap(pad, v.get("cluster_list", []))
        elif t == C.ATTR_MP_REACH_NLRI:
            self.w(pad + "AFI/SAFI  : %s/%s" % (v.get("afi_name"),
                                                v.get("safi_name")))
            nh = v.get("next_hop", {})
            self.w(pad + "next hop  : %s (%d byte(s))"
                   % (nh.get("text"), nh.get("length", 0)))
            for p in v.get("nlri", []):
                extra = ""
                if "labels" in p:
                    extra += "  labels=%s" % p["labels"]
                if "rd" in p:
                    extra += "  rd=%s" % p["rd"]
                if "path_id" in p:
                    extra += "  path-id=%s" % p["path_id"]
                self.w(pad + "NLRI      : %s%s" % (p["prefix"], extra))
        elif t == C.ATTR_MP_UNREACH_NLRI:
            self.w(pad + "AFI/SAFI  : %s/%s" % (v.get("afi_name"),
                                                v.get("safi_name")))
            for p in v.get("withdrawn_routes", []):
                self.w(pad + "withdraw  : %s" % p["prefix"])
        elif t == C.ATTR_ATOMIC_AGGREGATE:
            self.w(pad + "(present)")
        elif t == C.ATTR_OTC:
            self.w(pad + "AS %s" % v.get("only_to_customer_as"))
        else:
            self.w(pad + _trim(a.get("value_hex", ""), 160))
        for it in a.get("issues", []):
            self.w(pad + "!! %s: %s" % (it["severity"], it["text"]))

    def _wrap(self, pad, items, per_line=6):
        for i in range(0, len(items), per_line):
            self.w(pad + "  ".join(str(x) for x in items[i:i + per_line]))

    # --------------------------------------------------------------- summary
    def _summary(self, records):
        msgs = [r["message"] for r in records]
        st = summarize(msgs)
        self.w("")
        self.w("=" * 78)
        self.w("Summary")
        self.w("=" * 78)
        self.kv("  ", "Messages decoded", st["total"], 20)
        for k, v in sorted(st["by_type"].items()):
            self.kv("    ", k, v, 18)
        self.kv("  ", "Truncated dumps", st["truncated"], 20)
        self.kv("  ", "Errors", st["errors"], 20)
        self.kv("  ", "Warnings", st["warnings"], 20)


def _trim(s, limit):
    if not limit or len(s) <= limit:
        return s
    return s[:limit] + " ... (+%d chars)" % (len(s) - limit)


def render_text(records, events=None, source=None, show_hex=False,
                wide=False, max_path=0):
    return TextRenderer(show_hex=show_hex, wide=wide,
                        max_path=max_path).render(records, events, source)
