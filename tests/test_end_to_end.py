import io
import json
import os
import struct
import sys
import tempfile
import unittest

from bgpdump.bgp import all_issues, decode_stream
from bgpdump.cli import run
from bgpdump.logparse import parse_log
from bgpdump.render import pcap as pcapout

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLE = os.path.join(HERE, "data", "sample-msgdump.txt")


def ones(data):
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def read_pcap(path):
    with open(path, "rb") as fh:
        d = fh.read()
    magic, vmaj, vmin, tz, sf, snap, lt = struct.unpack("<IHHiIII", d[:24])
    assert magic == 0xA1B2C3D4
    off, pkts = 24, []
    while off < len(d):
        s, u, cl, ol = struct.unpack("<IIII", d[off:off + 16])
        off += 16
        pkts.append((s, u, d[off:off + cl]))
        off += cl
    return lt, pkts


class TestSample(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        with open(SAMPLE, encoding="utf-8") as fh:
            cls.text = fh.read()
        cls.events = parse_log(cls.text, year=2025)
        cls.records = []
        for ev in cls.events:
            if not ev.has_dump:
                continue
            msgs, _ = decode_stream(ev.data)
            for m in msgs:
                cls.records.append((ev, m))

    def test_event_count(self):
        self.assertEqual(len(self.events), 6)
        self.assertEqual(sum(1 for e in self.events if e.has_dump), 5)
        self.assertEqual(sum(1 for e in self.events if not e.has_dump), 1)

    def test_all_updates_from_one_peer(self):
        peers = {ev.peer for ev, _ in self.records}
        self.assertEqual(peers, {"2A03:4620::A"})
        self.assertTrue(all(m["type_name"] == "UPDATE"
                            for _, m in self.records))

    def test_first_message_decodes_exactly(self):
        ev, m = self.records[0]
        self.assertEqual(ev.seq, 22456)
        self.assertEqual(m["length"], 689)
        self.assertFalse(m["truncated"])
        self.assertTrue(m["marker_ok"])
        b = m["body"]
        self.assertEqual(b["withdrawn_routes_length"], 0)
        self.assertEqual(b["total_path_attribute_length"], 666)
        types = [a["type_code"] for a in b["path_attributes"]]
        self.assertEqual(types, [1, 2, 8, 16, 32, 14])

    def test_first_message_as_path(self):
        _, m = self.records[0]
        ap = [a for a in m["body"]["path_attributes"]
              if a["type_code"] == 2][0]["value"]
        self.assertEqual(ap["asn_width"], 4)
        self.assertEqual(ap["as_count"], 129)
        self.assertEqual(ap["asn_list"][:2], [201434, 201434])
        self.assertEqual(ap["asn_list"][-2:], [29535, 205268])
        self.assertEqual(ap["path_collapsed"], "201434 x127 29535 205268")

    def test_first_message_communities(self):
        _, m = self.records[0]
        by = {a["type_code"]: a for a in m["body"]["path_attributes"]}
        comms = [c["text"] for c in by[8]["value"]["communities"]]
        self.assertEqual(comms, ["48850:2", "48850:20", "48850:21",
                                 "48850:22", "24748:6695", "24748:54321",
                                 "24748:29535", "48850:1463", "48850:1000"])
        ext = [c["text"] for c in by[16]["value"]["extended_communities"]]
        self.assertEqual(ext, ["SoO:24748:6695", "SoO:24748:54321",
                               "SoO:29535:24748"])
        large = [c["text"] for c in by[32]["value"]["large_communities"]]
        self.assertEqual(large, ["24748:24748:6695", "24748:24748:54321",
                                 "24748:29535:24748"])

    def test_first_message_mp_reach(self):
        _, m = self.records[0]
        mp = [a for a in m["body"]["path_attributes"]
              if a["type_code"] == 14][0]["value"]
        self.assertEqual(mp["afi_name"], "IPv6")
        self.assertEqual(mp["safi_name"], "unicast")
        self.assertEqual(mp["next_hop"]["addresses"], ["2a03:4620::a"])
        self.assertEqual([p["prefix"] for p in mp["nlri"]],
                         ["2001:678:10e4::/48"])

    def test_as_path_grows_over_time(self):
        counts = []
        for _, m in self.records:
            ap = [a for a in m["body"]["path_attributes"]
                  if a["type_code"] == 2]
            counts.append(ap[0]["value"]["as_count"] if ap else None)
        self.assertEqual(counts[0], 129)
        self.assertEqual(counts[1], 198)
        self.assertEqual(counts[2], 129)

    def test_short_dumps_are_reported_not_guessed(self):
        # Messages 4 and 5 of the pasted buffer are shorter than their own
        # header length; the decoder must say so rather than invent bytes.
        short = [(ev.seq, m["length"], m["captured_length"])
                 for ev, m in self.records if m["truncated"]]
        self.assertEqual([s[0] for s in short], [22460, 22461])
        for _, declared, captured in short:
            self.assertLess(captured, declared)

    def test_timestamps_parsed(self):
        ev, _ = self.records[0]
        self.assertEqual(ev.timestamp.year, 2025)
        self.assertEqual(ev.timestamp.strftime("%m-%d %H:%M:%S.%f")[:18],
                         "07-09 08:51:32.605")


class TestPcapOutput(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.records = []
        with open(SAMPLE, encoding="utf-8") as fh:
            text = fh.read()
        for ev in parse_log(text, year=2025):
            if not ev.has_dump:
                continue
            msgs, _ = decode_stream(ev.data)
            for m in msgs:
                raw = ev.data[m["offset"]:m["offset"] + m["captured_length"]]
                self.records.append({"event": ev, "raw": raw,
                                     "declared_length": m["length"],
                                     "peer": ev.peer,
                                     "direction": ev.direction})

    def test_packet_count_and_payload(self):
        path = os.path.join(self.tmp, "a.pcap")
        n = pcapout.write_pcap(path, self.records)
        self.assertEqual(n, 5)
        lt, pkts = read_pcap(path)
        self.assertEqual(lt, pcapout.LINKTYPE_ETHERNET)
        self.assertEqual(len(pkts), 5)
        _, _, pkt = pkts[0]
        self.assertEqual(pkt[12:14], b"\x86\xdd")
        payload = pkt[14 + 40 + 20:]
        self.assertEqual(len(payload), 689)
        self.assertTrue(payload.startswith(b"\xff" * 16))

    def test_tcp_checksums_valid(self):
        path = os.path.join(self.tmp, "b.pcap")
        pcapout.write_pcap(path, self.records)
        _, pkts = read_pcap(path)
        for _, _, pkt in pkts:
            ip = pkt[14:]
            src, dst, tcp = ip[8:24], ip[24:40], ip[40:]
            pseudo = src + dst + struct.pack("!IBBBB", len(tcp), 0, 0, 0, 6)
            self.assertEqual(ones(pseudo + tcp), 0)

    def test_sequence_numbers_are_contiguous(self):
        path = os.path.join(self.tmp, "c.pcap")
        pcapout.write_pcap(path, self.records)
        _, pkts = read_pcap(path)
        seqs = []
        for _, _, pkt in pkts:
            tcp = pkt[14 + 40:]
            seqs.append(struct.unpack("!I", tcp[4:8])[0])
        lens = [689, 965, 689, 945, 1203]      # padded to declared length
        expect, acc = [], 1
        for ln in lens:
            expect.append(acc)
            acc += ln
        self.assertEqual(seqs, expect)

    def test_no_pad_keeps_captured_length(self):
        path = os.path.join(self.tmp, "d.pcap")
        pcapout.write_pcap(path, self.records, pad_truncated=False)
        _, pkts = read_pcap(path)
        payload = pkts[3][2][14 + 40 + 20:]
        self.assertEqual(len(payload), 933)

    def test_handshake_and_raw_linktype(self):
        path = os.path.join(self.tmp, "e.pcap")
        n = pcapout.write_pcap(path, self.records, handshake=True,
                               linktype=pcapout.LINKTYPE_RAW)
        self.assertEqual(n, 8)
        lt, pkts = read_pcap(path)
        self.assertEqual(lt, pcapout.LINKTYPE_RAW)
        self.assertEqual(pkts[0][2][0] >> 4, 6)

    def test_local_address_override(self):
        path = os.path.join(self.tmp, "f.pcap")
        pcapout.write_pcap(path, self.records, local_addr="2001:db8:7::1")
        _, pkts = read_pcap(path)
        import ipaddress
        dst = ipaddress.ip_address(pkts[0][2][14 + 24:14 + 40])
        self.assertEqual(str(dst), "2001:db8:7::1")


class TestCli(unittest.TestCase):

    def _run(self, argv):
        out, err = io.StringIO(), io.StringIO()
        old = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = out, err
        try:
            rc = run(argv)
        finally:
            sys.stdout, sys.stderr = old
        return rc, out.getvalue(), err.getvalue()

    def test_text_output(self):
        rc, out, _ = self._run([SAMPLE])
        self.assertEqual(rc, 0)
        self.assertIn("2001:678:10e4::/48", out)
        self.assertIn("Messages decoded", out)
        self.assertIn("201434 x127 29535 205268", out)

    def test_summary_output(self):
        _, out, _ = self._run([SAMPLE, "-f", "summary"])
        self.assertIn("as_path=129 ASNs", out)

    def test_json_output(self):
        _, out, _ = self._run([SAMPLE, "-f", "json"])
        doc = json.loads(out)
        self.assertEqual(doc["summary"]["total"], 5)
        self.assertEqual(doc["messages"][0]["log"]["peer"], "2A03:4620::A")
        self.assertEqual(len(doc["other_events"]), 1)
        self.assertEqual(doc["other_events"][0]["mnemonic"], "ASPATH")

    def test_multiple_formats_to_basename(self):
        tmp = tempfile.mkdtemp()
        base = os.path.join(tmp, "out")
        rc, _, _ = self._run([SAMPLE, "-f", "txt", "-f", "json",
                              "-f", "pcap", "-o", base])
        self.assertEqual(rc, 0)
        for ext in (".txt", ".json", ".pcap"):
            self.assertTrue(os.path.isfile(base + ext), ext)

    def test_strict_exit_code(self):
        rc, _, _ = self._run([SAMPLE, "-f", "summary", "--strict"])
        self.assertEqual(rc, 2)

    def test_hex_format_roundtrip(self):
        _, out, _ = self._run([SAMPLE, "-f", "hex"])
        body = [l for l in out.splitlines() if not l.startswith("#")]
        first = bytes.fromhex(body[0].replace(" ", ""))
        self.assertEqual(len(first), 689)


if __name__ == "__main__":
    unittest.main()


CHUNKED = os.path.join(HERE, "data", "sample-chunked.txt")


class TestChunkedDump(unittest.TestCase):
    """IOS-XE splits over-long syslog messages with **MSG n TRUNCATED** /
    **MSG n CONTINUATION #nn** seams, sometimes mid-byte."""

    @classmethod
    def setUpClass(cls):
        with open(CHUNKED, encoding="utf-8") as fh:
            cls.events = parse_log(fh.read())
        cls.ev = cls.events[0]
        cls.msg = decode_stream(cls.ev.data)[0][0]

    def test_single_event_reassembled(self):
        self.assertEqual(len(self.events), 1)
        self.assertEqual(self.ev.chunks, 5)
        self.assertEqual(self.ev.msg_id, "21505")
        self.assertFalse(self.ev.odd_nibble)

    def test_reassembles_to_declared_length(self):
        self.assertEqual(self.msg["length"], 1110)
        self.assertEqual(len(self.ev.data), 1110)
        self.assertFalse(self.msg["truncated"])

    def test_decodes_without_errors(self):
        sev = [i["severity"] for i in all_issues(self.msg)]
        self.assertNotIn("error", sev)

    def test_content(self):
        by = {a["type_code"]: a for a in self.msg["body"]["path_attributes"]}
        self.assertEqual([p["prefix"] for p in by[14]["value"]["nlri"]],
                         ["2804:9524::/32"])
        self.assertEqual(by[14]["value"]["next_hop"]["addresses"],
                         ["2001:1a68:2c:2::179"])
        self.assertEqual(by[2]["value"]["as_count"], 10)
        self.assertEqual(by[2]["value"]["asn_list"][0], 57355)
        self.assertEqual(len(by[8]["value"]["communities"]), 103)

    def test_trailing_non_bgp_syslog_is_not_absorbed(self):
        # The block is followed by %FMANFP lines; they must not be consumed.
        self.assertEqual(len(self.ev.data), self.msg["length"])

    def test_pcap_payload_is_complete(self):
        tmp = tempfile.mkdtemp()
        path = os.path.join(tmp, "chunked.pcap")
        raw = self.ev.data[:self.msg["captured_length"]]
        pcapout.write_pcap(path, [{"event": self.ev, "raw": raw,
                                   "declared_length": self.msg["length"],
                                   "peer": self.ev.peer,
                                   "direction": self.ev.direction}])
        _, pkts = read_pcap(path)
        payload = pkts[0][2][14 + 40 + 20:]
        self.assertEqual(len(payload), 1110)
        self.assertEqual(int.from_bytes(payload[16:18], "big"), 1110)
