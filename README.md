# cisco-bgpdump 1.0.0

Decode the raw BGP hexdumps that Cisco IOS / IOS-XE prints in
`%BGP-6-MSGDUMP` and `%BGP-6-MSGDUMP_LIMIT` syslog messages, and turn them
back into readable text, JSON, or a pcap you can open in Wireshark.

Paste the syslog buffer into a text file, point the tool at it, done.

* stdlib only — no pip, no CDN, no build step
* Python 3.8+, tested on FreeBSD and Linux
* outputs: `txt`, `json`, `pcap`, `hex`, `summary`

## Install

Nothing to install. Copy the tree somewhere and run it:

```sh
tar xzf cisco-bgpdump-1.0.0.tar.gz
cd cisco-bgpdump-1.0.0
python3 -m bgpdump examples/sample-msgdump.txt
```

Optionally `pip install .` (or `python3 -m pip install --user .`) to get a
`cisco-bgpdump` command on `$PATH`.

## Usage

```sh
python3 -m bgpdump dump.txt                          # readable decode on stdout
python3 -m bgpdump dump.txt -f summary               # one line per message
python3 -m bgpdump dump.txt -f json -o decode.json
python3 -m bgpdump dump.txt -f pcap -o bgp.pcap --year 2025
python3 -m bgpdump dump.txt -f txt -f json -f pcap -o out/bgp
cat buffer.log | python3 -m bgpdump - -f summary
```

Then:

```sh
wireshark bgp.pcap
tshark -r bgp.pcap -V -d tcp.port==179,bgp
```

### Options that matter

| Option | Why you would use it |
|---|---|
| `--year 2025` | IOS `Mon DD hh:mm:ss` stamps carry no year; without this the tool assumes the current year and rolls back if that lands in the future |
| `--tz-offset 2` | router clock offset from UTC, so pcap timestamps land at the right wall-clock time |
| `--asn-width {auto,2,4}` | force the AS_PATH ASN width instead of auto-detecting it |
| `--add-path 2:1` | the peer negotiated ADD-PATH for that AFI:SAFI, so NLRI carries a 4-byte path-id |
| `--extended-message` | allow RFC 8654 messages above 4096 bytes |
| `--local-addr` | your side of the session, for the synthesised pcap framing |
| `--linktype {ethernet,raw,loop}` | pcap link layer |
| `--handshake` | emit a synthetic TCP three-way handshake per peer |
| `--skip-truncated` | leave short messages out of the pcap altogether, so the rest dissect cleanly |
| `--no-pad` | do not zero-pad truncated messages in the pcap |
| `-x`, `--wide`, `--max-path N` | hexdump, untruncated AS paths, expanded AS path |
| `--strict` | exit 2 if any message decoded with errors (useful in scripts) |

## What it decodes

* Message types: OPEN, UPDATE, NOTIFICATION, KEEPALIVE, ROUTE-REFRESH
* OPEN capabilities: multiprotocol, 4-octet ASN, route refresh, graceful
  restart, ADD-PATH, FQDN, BGP role, enhanced RR
* Path attributes: ORIGIN, AS_PATH, NEXT_HOP, MED, LOCAL_PREF,
  ATOMIC_AGGREGATE, AGGREGATOR, COMMUNITIES, ORIGINATOR_ID, CLUSTER_LIST,
  MP_REACH_NLRI, MP_UNREACH_NLRI, EXTENDED_COMMUNITIES, AS4_PATH,
  AS4_AGGREGATOR, IPv6 address-specific ext communities, AIGP,
  LARGE_COMMUNITY, ONLY_TO_CUSTOMER; anything else is kept as raw hex
* MP-BGP: IPv4/IPv6 unicast and multicast, labeled unicast, VPN (RD + label
  stack), IPv6 global + link-local next hops, ADD-PATH path-ids
* Extended communities: 2-octet AS, 4-octet AS, IPv4-address-specific,
  opaque (colour, encapsulation), with RT / SoO rendering

It also runs the RFC 4271 §6.3 / RFC 7606 sanity checks and reports what it
finds: bad attribute flags, duplicate attributes, missing mandatory
attributes, length overruns, AS 0, invalid ORIGIN, over-long AS paths, and
dumps that are shorter than their own header length.

## Chunked (split) syslog messages

When a dump is longer than the syslog message limit, IOS-XE breaks it into
chunks and marks the seams:

```
2C50 0000 3009 0000 3147 0000 32CC 00**MSG 21505 TRUNCATED**
**MSG 21505 CONTINUATION #01**00 32F6 0000 3FD8 0000 50B9 0000 511C 0000
```

The tool stitches these back together automatically, matching on the message
id. The seam can land in the middle of a byte — and does:

```
... 0000 0003 1020 000**MSG 21505 TRUNCATED**
**MSG 21505 CONTINUATION #03**0
```

so the chunks are joined as a nibble stream, not line by line. A dump that
still ends on a half byte is reported. `examples/sample-chunked.txt` is a
five-chunk 1110-byte UPDATE that exercises this.

If you decode a chunked capture with a tool that does not understand these
markers you get a short message, and anything that pads it to the header
length produces exactly the `[Malformed Packet]` Wireshark shows. The fix is
reassembly, not padding.

## Log formats accepted

```
022456: Jul  9 08:51:32.605: %BGP-6-MSGDUMP_LIMIT: ... received from 2A03:4620::A:
FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF 02B1 0200 0002 9A40 0101 0050 0202 0602
...
```

Also handled: a leading syslog PRI (`<189>`), a relay host name, `Mon DD
YYYY hh:mm:ss.mmm`, RFC 3339 stamps from IOS-XE 17.x, uptime stamps
(`*00:12:34.567`, no wall clock, so pcap falls back to synthetic times),
and hexdump lines that still carry their own syslog prefix.

Only `%BGP-*` lines are consumed. An interleaved `%SYS-5-CONFIG_I` or
`%LINEPROTO` message terminates the dump block rather than being absorbed
into it, and the parser also stops as soon as the message's own Length field
is satisfied.

`%BGP-6-ASPATH`, `%BGP-3-NOTIFICATION` and similar lines that carry no
hexdump are kept and reported separately, so you keep the context around a
dump.

## Assumptions

These are choices the tool makes; all of them are visible in the output or
overridable on the command line.

1. **Year.** IOS timestamps have no year. Default is the current year,
   rolled back one year if that would put the event in the future. Use
   `--year`.
2. **Time zone.** Assumed UTC unless `--tz-offset` is given. IOS prints the
   router's local time, often with no zone name.
3. **AS_PATH ASN width.** Auto-detected per UPDATE: 4-octet is tried first
   and accepted only if the segments consume the attribute exactly,
   otherwise 2-octet. If an `AS4_PATH` attribute is present, `AS_PATH` is
   forced to 2-octet (RFC 6793 — only an old speaker ever sees both).
   Override with `--asn-width`.
4. **ADD-PATH.** Not detectable from the wire, so it is off unless you pass
   `--add-path AFI:SAFI`. If a peer negotiated it and you forget, NLRI will
   decode as nonsense — the tool will usually flag it as a length error.
5. **pcap framing is synthetic.** A syslog hexdump has no L2/L3/L4 context.
   The peer address comes from the log line; the local address defaults to
   `192.0.2.1` (RFC 5737) or `2001:db8::1` (RFC 3849); the BGP speaker side
   is TCP/179 and the local side an ephemeral port; MAC addresses are
   locally-administered placeholders; TCP sequence numbers advance per flow
   and checksums are computed correctly. **Only the BGP payload is real
   data.**
6. **Truncated dumps are zero-padded in the pcap** (`--no-pad` to disable)
   so Wireshark's TCP reassembly stays aligned; otherwise the next message
   gets glued onto the tail of the short one and both dissect as garbage.
   The padding is synthetic, it *will* show up as `[Malformed Packet]`, and
   every short message is flagged in the text and JSON output. Use
   `--skip-truncated` to drop them from the pcap instead.
7. **Direction** comes from the wording of the log line ("received from" vs
   "sent to"), defaulting to received.

## The bundled sample

`examples/sample-msgdump.txt` is a real IOS-XE capture of an AS-path prepend
runaway: AS 201434 keeps prepending itself in front of
`2001:678:10e4::/48`, and the path grows 129 → 198 → 129 → 193 → 257 ASNs
across five seconds. Messages 1–3 reassemble exactly to their declared
length. Messages 4 and 5 are 12 and 32 bytes shorter than their own Length
field — bytes lost between the router and the paste, not a decode failure —
and the tool reports that rather than guessing.

## Layout

```
cisco-bgpdump/
├── bgpdump/
│   ├── __init__.py
│   ├── __main__.py
│   ├── bgp.py           BGP wire-format decoder
│   ├── cli.py           argument handling and output dispatch
│   ├── constants.py     IANA registries
│   ├── logparse.py      Cisco syslog -> raw bytes
│   ├── utils.py         readers, prefix/address helpers
│   └── render/
│       ├── text.py
│       ├── jsonout.py
│       └── pcap.py
├── tests/               67 unit + end-to-end tests
├── examples/           sample-msgdump.txt, sample-chunked.txt
├── run-tests.sh
├── pyproject.toml
└── README.md
```

## Tests

```sh
./run-tests.sh
# or
python3 -m unittest discover -s tests -t .
```

## References

* RFC 4271 — BGP-4: <https://www.rfc-editor.org/rfc/rfc4271>
* RFC 4760 — Multiprotocol Extensions: <https://www.rfc-editor.org/rfc/rfc4760>
* RFC 2545 — IPv6 next hops: <https://www.rfc-editor.org/rfc/rfc2545>
* RFC 4360 / 5668 — Extended communities: <https://www.rfc-editor.org/rfc/rfc4360>
* RFC 8092 — Large communities: <https://www.rfc-editor.org/rfc/rfc8092>
* RFC 6793 — 4-octet ASNs: <https://www.rfc-editor.org/rfc/rfc6793>
* RFC 7606 — Revised error handling: <https://www.rfc-editor.org/rfc/rfc7606>
* RFC 7911 — ADD-PATH: <https://www.rfc-editor.org/rfc/rfc7911>
* RFC 8654 — Extended message size: <https://www.rfc-editor.org/rfc/rfc8654>
* IANA BGP parameters: <https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml>
* IANA BGP extended communities: <https://www.iana.org/assignments/bgp-extended-communities/>
* libpcap file format: <https://www.tcpdump.org/manpages/pcap-savefile.5.html>
* Cisco `bgp dampening`/`debug` message dump behaviour, `%BGP-6-MSGDUMP_LIMIT`:
  <https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/iproute_bgp/configuration/xe-17/irg-xe-17-book.html>

