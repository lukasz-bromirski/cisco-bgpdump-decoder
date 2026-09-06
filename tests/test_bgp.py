import unittest

from bgpdump import constants as C
from bgpdump.bgp import all_issues, decode_message, decode_stream

MARKER = b"\xff" * 16


def frame(mtype, body):
    return MARKER + (19 + len(body)).to_bytes(2, "big") + bytes([mtype]) + body


def attr(flags, tcode, value):
    if flags & 0x10:
        return bytes([flags, tcode]) + len(value).to_bytes(2, "big") + value
    return bytes([flags, tcode, len(value)]) + value


def update(withdrawn=b"", attrs=b"", nlri=b""):
    return (len(withdrawn).to_bytes(2, "big") + withdrawn
            + len(attrs).to_bytes(2, "big") + attrs + nlri)


def find_attr(msg, tcode):
    for a in msg["body"]["path_attributes"]:
        if a["type_code"] == tcode:
            return a
    return None


def severities(msg):
    return [i["severity"] for i in all_issues(msg)]


class TestHeader(unittest.TestCase):

    def test_keepalive(self):
        m = decode_message(frame(4, b""))
        self.assertEqual(m["type_name"], "KEEPALIVE")
        self.assertTrue(m["marker_ok"])
        self.assertEqual(m["length"], 19)
        self.assertEqual(all_issues(m), [])

    def test_bad_marker(self):
        raw = bytearray(frame(4, b""))
        raw[0] = 0x00
        m = decode_message(bytes(raw))
        self.assertFalse(m["marker_ok"])
        self.assertIn("error", severities(m))

    def test_truncated_dump(self):
        raw = frame(2, update(attrs=b"", nlri=b""))[:-1]
        m = decode_message(raw)
        self.assertTrue(m["truncated"])
        self.assertIn("warning", severities(m))

    def test_oversize_length(self):
        raw = MARKER + (9000).to_bytes(2, "big") + b"\x02" + b"\x00" * 100
        m = decode_message(raw)
        self.assertIn("error", severities(m))
        m2 = decode_message(raw, {"extended_message": True})
        self.assertFalse(any("exceeds" in i["text"] for i in m2["issues"]))

    def test_unknown_type(self):
        m = decode_message(frame(9, b""))
        self.assertIn("UNKNOWN", m["type_name"])

    def test_back_to_back_messages(self):
        data = frame(4, b"") + frame(4, b"")
        msgs, _ = decode_stream(data)
        self.assertEqual(len(msgs), 2)
        self.assertEqual(msgs[1]["offset"], 19)


class TestOpen(unittest.TestCase):

    def test_open_with_capabilities(self):
        caps = (bytes([1, 4]) + b"\x00\x02\x00\x01"      # MP IPv6 unicast
                + bytes([65, 4]) + (201434).to_bytes(4, "big")
                + bytes([2, 0]))                          # route refresh
        params = bytes([2, len(caps)]) + caps
        body = (b"\x04" + (23456).to_bytes(2, "big")
                + (180).to_bytes(2, "big") + bytes([10, 0, 0, 1])
                + bytes([len(params)]) + params)
        m = decode_message(frame(1, body))
        b = m["body"]
        self.assertEqual(b["version"], 4)
        self.assertEqual(b["hold_time"], 180)
        self.assertEqual(b["bgp_identifier"], "10.0.0.1")
        caps = b["optional_parameters"][0]["capabilities"]
        self.assertEqual(caps[0]["afi_name"], "IPv6")
        self.assertEqual(caps[1]["as4"], 201434)
        self.assertEqual(caps[2]["name"], "Route Refresh")


class TestNotification(unittest.TestCase):

    def test_cease_shutdown_communication(self):
        msg = b"maintenance"
        body = bytes([6, 2, len(msg)]) + msg
        m = decode_message(frame(3, body))
        self.assertEqual(m["body"]["error_name"], "Cease")
        self.assertEqual(m["body"]["error_subname"], "Administrative Shutdown")
        self.assertEqual(m["body"]["shutdown_communication"], "maintenance")

    def test_update_error(self):
        m = decode_message(frame(3, bytes([3, 11])))
        self.assertEqual(m["body"]["error_subname"], "Malformed AS_PATH")


class TestRouteRefresh(unittest.TestCase):

    def test_eorr(self):
        m = decode_message(frame(5, b"\x00\x02\x02\x01"))
        self.assertEqual(m["body"]["afi_name"], "IPv6")
        self.assertEqual(m["body"]["subtype_name"], "EoRR (End of RR)")


class TestUpdate(unittest.TestCase):

    def _v4_update(self):
        attrs = (attr(0x40, 1, b"\x00")
                 + attr(0x40, 2, bytes([2, 2]) + (65001).to_bytes(4, "big")
                        + (65002).to_bytes(4, "big"))
                 + attr(0x40, 3, bytes([192, 0, 2, 1]))
                 + attr(0x80, 4, (100).to_bytes(4, "big")))
        nlri = bytes([24, 192, 0, 2])
        return frame(2, update(attrs=attrs, nlri=nlri))

    def test_ipv4_update(self):
        m = decode_message(self._v4_update())
        b = m["body"]
        self.assertEqual(b["nlri"][0]["prefix"], "192.0.2.0/24")
        self.assertEqual(find_attr(m, 3)["value"]["next_hop"], "192.0.2.1")
        self.assertEqual(find_attr(m, 4)["value"]["value"], 100)
        ap = find_attr(m, 2)["value"]
        self.assertEqual(ap["asn_width"], 4)
        self.assertEqual(ap["path"], "65001 65002")
        self.assertNotIn("error", severities(m))

    def test_withdrawals(self):
        raw = frame(2, update(withdrawn=bytes([24, 10, 1, 1])))
        m = decode_message(raw)
        self.assertEqual(m["body"]["withdrawn_routes"][0]["prefix"],
                         "10.1.1.0/24")

    def test_end_of_rib(self):
        m = decode_message(frame(2, update()))
        self.assertTrue(any("End-of-RIB" in i["text"] for i in m["issues"]))

    def test_missing_next_hop_flagged(self):
        attrs = (attr(0x40, 1, b"\x00")
                 + attr(0x40, 2, b""))
        m = decode_message(frame(2, update(attrs=attrs,
                                           nlri=bytes([24, 10, 0, 0]))))
        self.assertTrue(any("NEXT_HOP" in i["text"] for i in m["issues"]))

    def test_duplicate_attribute_flagged(self):
        attrs = attr(0x40, 1, b"\x00") * 2 + attr(0x40, 2, b"")
        m = decode_message(frame(2, update(attrs=attrs,
                                           nlri=bytes([24, 10, 0, 0]))))
        self.assertTrue(any("appears 2 times" in i["text"]
                            for i in m["issues"]))

    def test_bad_origin_value_and_flags(self):
        attrs = attr(0xC0, 1, b"\x07") + attr(0x40, 2, b"")
        m = decode_message(frame(2, update(attrs=attrs,
                                           nlri=bytes([24, 10, 0, 0]))))
        texts = " ".join(i["text"] for i in all_issues(m))
        self.assertIn("invalid ORIGIN value 7", texts)
        self.assertIn("Optional bit clear", texts)

    def test_attribute_length_overrun(self):
        bad = bytes([0x40, 0x03, 0x40]) + b"\x01\x02"
        m = decode_message(frame(2, update(attrs=bad)))
        self.assertIn("error", severities(m))

    def test_as0_flagged(self):
        attrs = (attr(0x40, 1, b"\x00")
                 + attr(0x40, 2, bytes([2, 1]) + (0).to_bytes(4, "big"))
                 + attr(0x40, 3, bytes([192, 0, 2, 1])))
        m = decode_message(frame(2, update(attrs=attrs,
                                           nlri=bytes([24, 10, 0, 0]))))
        self.assertTrue(any("AS 0" in i["text"] for i in all_issues(m)))


class TestAsPathWidth(unittest.TestCase):

    def test_two_octet_autodetect(self):
        val = bytes([2, 3]) + b"".join(x.to_bytes(2, "big")
                                       for x in (65001, 65002, 65003))
        attrs = (attr(0x40, 1, b"\x00") + attr(0x40, 2, val)
                 + attr(0x40, 3, bytes([192, 0, 2, 1])))
        m = decode_message(frame(2, update(attrs=attrs,
                                           nlri=bytes([24, 10, 0, 0]))))
        ap = find_attr(m, 2)["value"]
        self.assertEqual(ap["asn_width"], 2)
        self.assertEqual(ap["path"], "65001 65002 65003")

    def test_as4_path_forces_two_octet_as_path(self):
        v2 = bytes([2, 2]) + b"".join(x.to_bytes(2, "big")
                                      for x in (23456, 23456))
        v4 = bytes([2, 2]) + b"".join(x.to_bytes(4, "big")
                                      for x in (201434, 205268))
        attrs = (attr(0x40, 1, b"\x00") + attr(0x40, 2, v2)
                 + attr(0x40, 3, bytes([192, 0, 2, 1]))
                 + attr(0xC0, 17, v4))
        m = decode_message(frame(2, update(attrs=attrs,
                                           nlri=bytes([24, 10, 0, 0]))))
        self.assertEqual(find_attr(m, 2)["value"]["asn_width"], 2)
        self.assertEqual(find_attr(m, 17)["value"]["path"], "201434 205268")

    def test_explicit_width_override(self):
        val = bytes([2, 3]) + b"".join(x.to_bytes(2, "big")
                                       for x in (65001, 65002, 65003))
        attrs = attr(0x40, 2, val)
        m = decode_message(frame(2, update(attrs=attrs)),
                           {"asn_width": "2"})
        self.assertEqual(find_attr(m, 2)["value"]["asn_width"], 2)

    def test_long_path_warning(self):
        asns = [201434] * 129
        val = bytes([2, len(asns)]) + b"".join(a.to_bytes(4, "big")
                                               for a in asns)
        attrs = (attr(0x50, 2, val) + attr(0x40, 1, b"\x00")
                 + attr(0x40, 3, bytes([192, 0, 2, 1])))
        m = decode_message(frame(2, update(attrs=attrs,
                                           nlri=bytes([24, 10, 0, 0]))))
        ap = find_attr(m, 2)["value"]
        self.assertEqual(ap["as_count"], 129)
        self.assertEqual(ap["path_collapsed"], "201434 x129")
        self.assertTrue(any("maxas-limit" in i["text"] for i in m["issues"]))


class TestCommunities(unittest.TestCase):

    def test_standard_and_well_known(self):
        val = (0xFFFFFF01).to_bytes(4, "big") + (24748 << 16 | 6695).to_bytes(4, "big")
        m = decode_message(frame(2, update(attrs=attr(0xC0, 8, val))))
        comms = find_attr(m, 8)["value"]["communities"]
        self.assertEqual(comms[0]["well_known"], "NO_EXPORT")
        self.assertEqual(comms[1]["text"], "24748:6695")

    def test_large_communities(self):
        val = b"".join(x.to_bytes(4, "big") for x in (24748, 24748, 6695))
        m = decode_message(frame(2, update(attrs=attr(0xC0, 32, val))))
        self.assertEqual(
            find_attr(m, 32)["value"]["large_communities"][0]["text"],
            "24748:24748:6695")

    def test_extended_communities(self):
        rt = bytes([0x00, 0x02]) + (65000).to_bytes(2, "big") + (7).to_bytes(4, "big")
        soo = bytes([0x00, 0x03]) + (24748).to_bytes(2, "big") + (6695).to_bytes(4, "big")
        ip_rt = bytes([0x01, 0x02]) + bytes([10, 0, 0, 1]) + (5).to_bytes(2, "big")
        m = decode_message(frame(2, update(attrs=attr(0xC0, 16, rt + soo + ip_rt))))
        ec = find_attr(m, 16)["value"]["extended_communities"]
        self.assertEqual(ec[0]["text"], "RT:65000:7")
        self.assertEqual(ec[1]["text"], "SoO:24748:6695")
        self.assertEqual(ec[2]["text"], "RT:10.0.0.1:5")

    def test_bad_community_length(self):
        m = decode_message(frame(2, update(attrs=attr(0xC0, 8, b"\x00\x01\x02"))))
        self.assertIn("error", severities(m))


class TestMpBgp(unittest.TestCase):

    def _mp_reach(self, nh, nlri, afi=2, safi=1):
        return (afi.to_bytes(2, "big") + bytes([safi, len(nh)]) + nh
                + b"\x00" + nlri)

    def test_ipv6_unicast(self):
        nh = bytes.fromhex("2a0346200000000000000000000000 0a".replace(" ", ""))
        nlri = bytes([48]) + bytes.fromhex("20010678 10e4".replace(" ", ""))
        val = self._mp_reach(nh, nlri)
        m = decode_message(frame(2, update(attrs=attr(0x90, 14, val))))
        v = find_attr(m, 14)["value"]
        self.assertEqual(v["afi_name"], "IPv6")
        self.assertEqual(v["safi_name"], "unicast")
        self.assertEqual(v["next_hop"]["addresses"], ["2a03:4620::a"])
        self.assertEqual(v["nlri"][0]["prefix"], "2001:678:10e4::/48")

    def test_ipv6_global_plus_link_local(self):
        nh = bytes.fromhex("20010db8000000000000000000000001"
                           "fe800000000000000000000000000001")
        val = self._mp_reach(nh, bytes([32]) + bytes.fromhex("20010db8"))
        m = decode_message(frame(2, update(attrs=attr(0x90, 14, val))))
        v = find_attr(m, 14)["value"]
        self.assertEqual(len(v["next_hop"]["addresses"]), 2)
        self.assertEqual(v["next_hop"]["link_local"], "fe80::1")

    def test_mp_unreach(self):
        val = (2).to_bytes(2, "big") + bytes([1]) + bytes([48]) + \
            bytes.fromhex("2001067810e4")
        m = decode_message(frame(2, update(attrs=attr(0x90, 15, val))))
        v = find_attr(m, 15)["value"]
        self.assertEqual(v["withdrawn_routes"][0]["prefix"],
                         "2001:678:10e4::/48")

    def test_vpnv4_with_labels_and_rd(self):
        rd = (0).to_bytes(2, "big") + (65000).to_bytes(2, "big") + (1).to_bytes(4, "big")
        label = bytes([0x00, 0x01, 0x21])            # label 18, BoS
        nlri = bytes([24 + 24 + 64]) + label + rd + bytes([10, 0, 0])
        nh = (0).to_bytes(8, "big") + bytes([192, 0, 2, 1])
        val = self._mp_reach(nh, nlri, afi=1, safi=128)
        m = decode_message(frame(2, update(attrs=attr(0x90, 14, val))))
        v = find_attr(m, 14)["value"]
        self.assertEqual(v["nlri"][0]["prefix"], "10.0.0.0/24")
        self.assertEqual(v["nlri"][0]["rd"], "65000:1")
        self.assertEqual(v["nlri"][0]["labels"], [18])
        self.assertEqual(v["next_hop"]["addresses"], ["192.0.2.1"])

    def test_add_path_ipv6(self):
        nh = bytes.fromhex("20010db8000000000000000000000001")
        nlri = (7).to_bytes(4, "big") + bytes([32]) + bytes.fromhex("20010db8")
        val = self._mp_reach(nh, nlri)
        m = decode_message(frame(2, update(attrs=attr(0x90, 14, val))),
                           {"add_path_afi_safi": {(2, 1)}})
        v = find_attr(m, 14)["value"]
        self.assertEqual(v["nlri"][0]["path_id"], 7)
        self.assertEqual(v["nlri"][0]["prefix"], "2001:db8::/32")


if __name__ == "__main__":
    unittest.main()
