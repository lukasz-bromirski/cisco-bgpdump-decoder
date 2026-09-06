import datetime as dt
import unittest

from bgpdump.logparse import parse_log

IOS = """\
022456: Jul  9 08:51:32.605: %BGP-6-MSGDUMP_LIMIT: unsupported or mal-formatted message received from 2A03:4620::A:
FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF 0013 04
"""

RELAYED = """\
<189>Jul  9 08:51:32 rtr1.example.net 022456: Jul  9 08:51:32.605 CEST: %BGP-6-MSGDUMP: message received from 192.0.2.9:
rtr1: FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF 0013 04
"""

UPTIME = """\
*00:12:34.567: %BGP-6-MSGDUMP_LIMIT: mal-formatted message received from 10.0.0.1:
FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF 0013 04
"""

ISO = """\
2025-07-09T08:51:32.605+02:00 rtr: %BGP-6-MSGDUMP: message received from 10.0.0.2:
FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF 0013 04
"""

NOISE_AFTER = """\
022456: Jul  9 08:51:32.605: %BGP-6-MSGDUMP_LIMIT: message received from 10.0.0.3:
FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF 0013 04
022457: Jul  9 08:51:33.000: %SYS-5-CONFIG_I: Configured from console by admin
"""

NO_DUMP = """\
022458: Jul  9 08:51:38.273: %BGP-6-ASPATH: Long AS path 201434 201434 received from 2A03:4620::A: BGP(1) Prefixes: 2001:678:10E4::/48
"""


class TestLogParse(unittest.TestCase):

    def test_ios_basic(self):
        ev = parse_log(IOS)[0]
        self.assertEqual(ev.mnemonic, "MSGDUMP_LIMIT")
        self.assertEqual(ev.severity, 6)
        self.assertEqual(ev.seq, 22456)
        self.assertEqual(ev.peer, "2A03:4620::A")
        self.assertEqual(ev.direction, "received")
        self.assertEqual(len(ev.data), 19)
        self.assertTrue(ev.data.startswith(b"\xff" * 16))

    def test_year_and_timezone(self):
        tz = dt.timezone(dt.timedelta(hours=2))
        ev = parse_log(IOS, year=2025, tz=tz)[0]
        self.assertEqual(ev.timestamp.year, 2025)
        self.assertEqual(ev.timestamp.month, 7)
        self.assertEqual(ev.timestamp.day, 9)
        self.assertEqual(ev.timestamp.microsecond, 605000)
        self.assertEqual(ev.timestamp.utcoffset(), dt.timedelta(hours=2))

    def test_relayed_syslog_prefixes(self):
        ev = parse_log(RELAYED)[0]
        self.assertEqual(ev.peer, "192.0.2.9")
        self.assertEqual(len(ev.data), 19)

    def test_uptime_timestamp_has_no_wallclock(self):
        ev = parse_log(UPTIME)[0]
        self.assertIsNone(ev.timestamp)
        self.assertEqual(ev.timestamp_kind, "uptime")
        self.assertEqual(len(ev.data), 19)

    def test_iso_timestamp(self):
        ev = parse_log(ISO)[0]
        self.assertEqual(ev.timestamp.year, 2025)
        self.assertEqual(ev.timestamp.hour, 8)

    def test_unrelated_syslog_line_is_not_swallowed(self):
        evs = parse_log(NOISE_AFTER)
        self.assertEqual(len(evs), 1)
        self.assertEqual(len(evs[0].data), 19)

    def test_event_without_dump(self):
        ev = parse_log(NO_DUMP)[0]
        self.assertEqual(ev.mnemonic, "ASPATH")
        self.assertFalse(ev.has_dump)
        self.assertEqual(ev.peer, "2A03:4620::A")

    def test_stops_at_declared_length(self):
        text = (IOS + "DEAD BEEF CAFE FACE\n")
        ev = parse_log(text)[0]
        self.assertEqual(len(ev.data), 19)

    def test_direction_sent(self):
        text = IOS.replace("received from", "sent to")
        ev = parse_log(text)[0]
        self.assertEqual(ev.direction, "sent")


if __name__ == "__main__":
    unittest.main()
