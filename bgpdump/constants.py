"""IANA registries and other constant tables used by the decoder.

References (all values below are taken from these registries):
  * RFC 4271  - A Border Gateway Protocol 4 (BGP-4)
  * RFC 4760  - Multiprotocol Extensions for BGP-4
  * IANA "Border Gateway Protocol (BGP) Parameters"
    https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml
  * IANA "BGP Extended Communities"
    https://www.iana.org/assignments/bgp-extended-communities/
  * IANA "Address Family Numbers" / "SAFI Values"
"""

BGP_HEADER_LEN = 19
BGP_MARKER = b"\xff" * 16
BGP_MAX_MESSAGE_LEN = 4096          # RFC 4271
BGP_MAX_EXTENDED_MESSAGE_LEN = 65535  # RFC 8654

MSG_TYPES = {
    1: "OPEN",
    2: "UPDATE",
    3: "NOTIFICATION",
    4: "KEEPALIVE",
    5: "ROUTE-REFRESH",
}

# ---------------------------------------------------------------- attributes
ATTR_ORIGIN = 1
ATTR_AS_PATH = 2
ATTR_NEXT_HOP = 3
ATTR_MED = 4
ATTR_LOCAL_PREF = 5
ATTR_ATOMIC_AGGREGATE = 6
ATTR_AGGREGATOR = 7
ATTR_COMMUNITIES = 8
ATTR_ORIGINATOR_ID = 9
ATTR_CLUSTER_LIST = 10
ATTR_MP_REACH_NLRI = 14
ATTR_MP_UNREACH_NLRI = 15
ATTR_EXT_COMMUNITIES = 16
ATTR_AS4_PATH = 17
ATTR_AS4_AGGREGATOR = 18
ATTR_PMSI_TUNNEL = 22
ATTR_TUNNEL_ENCAP = 23
ATTR_TRAFFIC_ENGINEERING = 24
ATTR_IPV6_EXT_COMMUNITIES = 25
ATTR_AIGP = 26
ATTR_PE_DISTINGUISHER_LABELS = 27
ATTR_BGP_LS = 29
ATTR_LARGE_COMMUNITY = 32
ATTR_BGPSEC_PATH = 33
ATTR_OTC = 35
ATTR_SFP = 37
ATTR_BFD_DISCRIMINATOR = 38
ATTR_BGP_PREFIX_SID = 40
ATTR_ATTR_SET = 128

ATTR_TYPES = {
    ATTR_ORIGIN: "ORIGIN",
    ATTR_AS_PATH: "AS_PATH",
    ATTR_NEXT_HOP: "NEXT_HOP",
    ATTR_MED: "MULTI_EXIT_DISC",
    ATTR_LOCAL_PREF: "LOCAL_PREF",
    ATTR_ATOMIC_AGGREGATE: "ATOMIC_AGGREGATE",
    ATTR_AGGREGATOR: "AGGREGATOR",
    ATTR_COMMUNITIES: "COMMUNITIES",
    ATTR_ORIGINATOR_ID: "ORIGINATOR_ID",
    ATTR_CLUSTER_LIST: "CLUSTER_LIST",
    11: "DPA (deprecated)",
    12: "ADVERTISER (deprecated)",
    13: "RCID_PATH (deprecated)",
    ATTR_MP_REACH_NLRI: "MP_REACH_NLRI",
    ATTR_MP_UNREACH_NLRI: "MP_UNREACH_NLRI",
    ATTR_EXT_COMMUNITIES: "EXTENDED_COMMUNITIES",
    ATTR_AS4_PATH: "AS4_PATH",
    ATTR_AS4_AGGREGATOR: "AS4_AGGREGATOR",
    19: "SAFI_SSA (deprecated)",
    20: "CONNECTOR (deprecated)",
    21: "AS_PATHLIMIT (deprecated)",
    ATTR_PMSI_TUNNEL: "PMSI_TUNNEL",
    ATTR_TUNNEL_ENCAP: "TUNNEL_ENCAPSULATION",
    ATTR_TRAFFIC_ENGINEERING: "TRAFFIC_ENGINEERING",
    ATTR_IPV6_EXT_COMMUNITIES: "IPV6_ADDRESS_SPECIFIC_EXT_COMMUNITY",
    ATTR_AIGP: "AIGP",
    ATTR_PE_DISTINGUISHER_LABELS: "PE_DISTINGUISHER_LABELS",
    28: "BGP_ENTROPY_LABEL (deprecated)",
    ATTR_BGP_LS: "BGP-LS_ATTRIBUTE",
    ATTR_LARGE_COMMUNITY: "LARGE_COMMUNITY",
    ATTR_BGPSEC_PATH: "BGPSEC_PATH",
    34: "OTC (draft)",
    ATTR_OTC: "ONLY_TO_CUSTOMER",
    36: "D-PATH",
    ATTR_SFP: "SFP_ATTRIBUTE",
    ATTR_BFD_DISCRIMINATOR: "BFD_DISCRIMINATOR",
    39: "RESERVED",
    ATTR_BGP_PREFIX_SID: "BGP_PREFIX_SID",
    ATTR_ATTR_SET: "ATTR_SET",
}

# Well-known mandatory / discretionary classification (RFC 4271 5.1)
WELL_KNOWN_ATTRS = {
    ATTR_ORIGIN,
    ATTR_AS_PATH,
    ATTR_NEXT_HOP,
    ATTR_LOCAL_PREF,
    ATTR_ATOMIC_AGGREGATE,
}
MANDATORY_ATTRS = {ATTR_ORIGIN, ATTR_AS_PATH}

ORIGIN_TYPES = {0: "IGP", 1: "EGP", 2: "INCOMPLETE"}

AS_PATH_SEGMENT_TYPES = {
    1: "AS_SET",
    2: "AS_SEQUENCE",
    3: "AS_CONFED_SEQUENCE",
    4: "AS_CONFED_SET",
}

# ------------------------------------------------------------- AFI/SAFI
AFI = {
    1: "IPv4",
    2: "IPv6",
    3: "NSAP",
    16388: "BGP-LS",
    25: "L2VPN",
    16398: "EVPN",
}

SAFI = {
    1: "unicast",
    2: "multicast",
    4: "labeled-unicast (MPLS)",
    5: "MCAST-VPN",
    64: "tunnel",
    65: "VPLS",
    66: "MDT",
    70: "EVPN",
    71: "BGP-LS",
    72: "BGP-LS-VPN",
    73: "SR-TE-Policy",
    128: "MPLS-labeled-VPN (unicast)",
    129: "MPLS-labeled-VPN (multicast)",
    132: "route-target-constrain",
    133: "flowspec",
    134: "flowspec-vpn",
}

# ------------------------------------------------------------- NOTIFICATION
NOTIFY_CODES = {
    1: "Message Header Error",
    2: "OPEN Message Error",
    3: "UPDATE Message Error",
    4: "Hold Timer Expired",
    5: "Finite State Machine Error",
    6: "Cease",
    7: "ROUTE-REFRESH Message Error",
}

NOTIFY_SUBCODES = {
    1: {
        1: "Connection Not Synchronized",
        2: "Bad Message Length",
        3: "Bad Message Type",
    },
    2: {
        1: "Unsupported Version Number",
        2: "Bad Peer AS",
        3: "Bad BGP Identifier",
        4: "Unsupported Optional Parameter",
        5: "Authentication Failure (deprecated)",
        6: "Unacceptable Hold Time",
        7: "Unsupported Capability",
        8: "Role Mismatch",
    },
    3: {
        1: "Malformed Attribute List",
        2: "Unrecognized Well-known Attribute",
        3: "Missing Well-known Attribute",
        4: "Attribute Flags Error",
        5: "Attribute Length Error",
        6: "Invalid ORIGIN Attribute",
        7: "AS Routing Loop (deprecated)",
        8: "Invalid NEXT_HOP Attribute",
        9: "Optional Attribute Error",
        10: "Invalid Network Field",
        11: "Malformed AS_PATH",
    },
    5: {
        1: "Receive Unexpected Message in OpenSent State",
        2: "Receive Unexpected Message in OpenConfirm State",
        3: "Receive Unexpected Message in Established State",
    },
    6: {
        1: "Maximum Number of Prefixes Reached",
        2: "Administrative Shutdown",
        3: "Peer De-configured",
        4: "Administrative Reset",
        5: "Connection Rejected",
        6: "Other Configuration Change",
        7: "Connection Collision Resolution",
        8: "Out of Resources",
        9: "Hard Reset",
        10: "BFD Down",
    },
    7: {1: "Invalid Message Length"},
}

# ------------------------------------------------------------- capabilities
CAPABILITIES = {
    1: "Multiprotocol Extensions",
    2: "Route Refresh",
    3: "Outbound Route Filtering",
    4: "Multiple routes to a destination (deprecated)",
    5: "Extended Next Hop Encoding",
    6: "BGP Extended Message",
    7: "BGPsec",
    8: "Multiple Labels",
    9: "BGP Role",
    64: "Graceful Restart",
    65: "Support for 4-octet AS number",
    66: "Deprecated (2003-03-06)",
    67: "Dynamic Capability",
    68: "Multisession BGP",
    69: "ADD-PATH",
    70: "Enhanced Route Refresh",
    71: "Long-Lived Graceful Restart",
    72: "Routing Policy Distribution",
    73: "FQDN",
    128: "Route Refresh (Cisco pre-standard)",
    130: "Outbound Route Filtering (Cisco pre-standard)",
}

ADD_PATH_SEND_RECEIVE = {1: "Receive", 2: "Send", 3: "Send/Receive"}

# ------------------------------------------------------- extended communities
EXTCOMM_TYPE_HIGH = {
    0x00: "Transitive Two-Octet AS-Specific",
    0x01: "Transitive IPv4-Address-Specific",
    0x02: "Transitive Four-Octet AS-Specific",
    0x03: "Transitive Opaque",
    0x04: "QoS Marking",
    0x05: "CoS Capability",
    0x06: "EVPN",
    0x08: "Flow-spec redirect/mirror",
    0x0A: "Transitive Experimental",
    0x40: "Non-Transitive Two-Octet AS-Specific",
    0x41: "Non-Transitive IPv4-Address-Specific",
    0x42: "Non-Transitive Four-Octet AS-Specific",
    0x43: "Non-Transitive Opaque",
    0x44: "QoS Marking (non-transitive)",
    0x80: "Generic Transitive Experimental",
    0x81: "Generic Transitive Experimental Part 2",
    0x82: "Generic Transitive Experimental Part 3",
}

EXTCOMM_SUBTYPE_AS = {
    0x02: "Route Target",
    0x03: "Route Origin",
    0x04: "Link Bandwidth",
    0x05: "OSPF Domain Identifier",
    0x08: "bgp-data-collection",
    0x09: "Source AS",
    0x0A: "L2VPN Identifier",
    0x10: "Cisco VRF Route Import",
}

EXTCOMM_SUBTYPE_OPAQUE = {
    0x01: "Cost Community",
    0x03: "OSPF Route Type",
    0x06: "OSPF Router ID",
    0x0B: "Color",
    0x0C: "Encapsulation",
    0x0D: "Default Gateway",
    0x0E: "Point-to-Point-to-Multipoint",
}

WELL_KNOWN_COMMUNITIES = {
    0xFFFF0000: "GRACEFUL_SHUTDOWN",
    0xFFFF0001: "ACCEPT_OWN",
    0xFFFF0002: "ROUTE_FILTER_TRANSLATED_v4",
    0xFFFF0003: "ROUTE_FILTER_v4",
    0xFFFF0004: "ROUTE_FILTER_TRANSLATED_v6",
    0xFFFF0005: "ROUTE_FILTER_v6",
    0xFFFF0006: "LLGR_STALE",
    0xFFFF0007: "NO_LLGR",
    0xFFFF0008: "accept-own-nexthop",
    0xFFFF0009: "Standby PE",
    0xFFFF029A: "BLACKHOLE",
    0xFFFFFF01: "NO_EXPORT",
    0xFFFFFF02: "NO_ADVERTISE",
    0xFFFFFF03: "NO_EXPORT_SUBCONFED",
    0xFFFFFF04: "NOPEER",
}

ROUTE_REFRESH_SUBTYPE = {
    0: "Route-Refresh",
    1: "BoRR (Beginning of RR)",
    2: "EoRR (End of RR)",
}

# --------------------------------------------------------------- Cisco side
# Syslog mnemonics that carry a raw BGP message hexdump.
DUMP_MNEMONICS = {
    "MSGDUMP",
    "MSGDUMP_LIMIT",
    "BGP_MSGDUMP",
    "UPDATE_DUMP",
    "MALFORMUPDATE",
    "MALFORM_UPDATE",
    "MSG_DUMP",
}

# Informational mnemonics we keep as events but that carry no hexdump.
EVENT_MNEMONICS = {
    "ASPATH",
    "ADJCHANGE",
    "NBR_RESET",
    "BGP_NBR_RESET",
    "NOTIFICATION",
    "MAXPFX",
    "MAXPFXEXCEED",
    "ASPATH_LOOP",
    "BADAS",
}
