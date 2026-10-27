#!/usr/bin/env python3
"""Regenerates the versioned seed corpus under fuzz/corpus/.

The seeds are committed, so this script only needs to run when adding a new
target or a new interesting shape. It is deterministic: re-running it on an
unchanged file list produces byte-identical output.

    python3 fuzz/seeds.py
"""

from pathlib import Path
import struct

CORPUS = Path(__file__).parent / "corpus"


def write(target: str, name: str, data: bytes) -> None:
    directory = CORPUS / target
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"{name}.bin").write_bytes(data)


def name_wire(labels) -> bytes:
    out = b""
    for label in labels:
        out += bytes([len(label)]) + label
    return out + b"\x00"


def opt_record(payload: int = 4096, do_bit: bool = False, version: int = 0,
               options: bytes = b"") -> bytes:
    flags = 0x8000 if do_bit else 0x0000
    # root owner name, TYPE=41, CLASS=UDP payload size, TTL=(rcode, version,
    # flags), RDLENGTH, then the options
    return b"\x00" + struct.pack(">HHBBHH", 41, payload, 0, version, flags, len(options)) + options


def edns_option(code: int, data: bytes) -> bytes:
    return struct.pack(">HH", code, len(data)) + data


def query(labels, qtype: int, qclass: int = 1, edns=None, qid: int = 0x1234) -> bytes:
    arcount = 1 if edns is not None else 0
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, arcount)
    body = name_wire(labels) + struct.pack(">HH", qtype, qclass)
    return header + body + (edns or b"")


def response(labels, qtype: int, answers: bytes, ancount: int, qid: int = 0x1234) -> bytes:
    header = struct.pack(">HHHHHH", qid, 0x8180, 1, ancount, 0, 0)
    body = name_wire(labels) + struct.pack(">HH", qtype, 1)
    return header + body + answers


def a_record(ip: bytes, ttl: int = 300, compressed: bool = True, owner=None) -> bytes:
    name = b"\xc0\x0c" if compressed else name_wire(owner)
    return name + struct.pack(">HHIH", 1, 1, ttl, 4) + ip


# ---------------------------------------------------------------- query_fast_path
EXAMPLE = [b"www", b"example", b"com"]

write("query_fast_path", "a_no_edns", query(EXAMPLE, 1))
write("query_fast_path", "aaaa_no_edns", query(EXAMPLE, 28))
write("query_fast_path", "txt_no_edns", query([b"example", b"com"], 16))
write("query_fast_path", "mx_no_edns", query([b"example", b"com"], 15))
write("query_fast_path", "https_no_edns", query(EXAMPLE, 65))
write("query_fast_path", "a_edns_4096", query(EXAMPLE, 1, edns=opt_record()))
write("query_fast_path", "a_edns_512", query(EXAMPLE, 1, edns=opt_record(payload=512)))
write("query_fast_path", "a_edns_max", query(EXAMPLE, 1, edns=opt_record(payload=65535)))
write("query_fast_path", "a_edns_do_bit", query(EXAMPLE, 1, edns=opt_record(do_bit=True)))
write("query_fast_path", "a_edns_bad_version", query(EXAMPLE, 1, edns=opt_record(version=1)))
write("query_fast_path", "a_edns_client_cookie",
      query(EXAMPLE, 1, edns=opt_record(options=edns_option(10, bytes(range(1, 9))))))
write("query_fast_path", "txt_edns_full_cookie_do",
      query([b"example", b"com"], 16,
            edns=opt_record(do_bit=True, options=edns_option(10, bytes(range(1, 25))))))
write("query_fast_path", "a_edns_padding_then_cookie",
      query(EXAMPLE, 1, edns=opt_record(options=edns_option(12, bytes(3))
                                          + edns_option(10, bytes(range(1, 9))))))
write("query_fast_path", "a_edns_option_overruns_rdata",
      query(EXAMPLE, 1, edns=opt_record(options=struct.pack(">HH", 10, 8) + bytes(4))))
write("query_fast_path", "root_a", query([], 1))
write("query_fast_path", "a_uppercase", query([b"WwW", b"ExAmPlE", b"CoM"], 1))
write("query_fast_path", "a_idn_alabel", query([b"xn--bcher-kva", b"de"], 1))
write("query_fast_path", "a_dotted_label", query([b"ads.example.com"], 1))
write("query_fast_path", "a_max_label", query([b"a" * 63, b"com"], 1))
write("query_fast_path", "a_deep_subdomains", query([b"a"] * 40 + [b"com"], 1))
write("query_fast_path", "a_wrong_qclass", query(EXAMPLE, 1, qclass=3))
write("query_fast_path", "truncated_question", query(EXAMPLE, 1)[:-3])
write("query_fast_path", "compression_pointer_qname",
      struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + b"\xc0\x0c" + struct.pack(">HH", 1, 1))

# ------------------------------------------------------- response_lowercase_0x20
write("response_lowercase_0x20", "answer_compressed",
      response(EXAMPLE, 1, a_record(b"\x5d\xb8\xd8\x22"), 1))
write("response_lowercase_0x20", "answer_mixed_case_qname",
      response([b"WwW", b"ExAmPlE", b"CoM"], 1, a_record(b"\x5d\xb8\xd8\x22"), 1))
write("response_lowercase_0x20", "answer_literal_owner",
      response([b"WwW", b"ExAmPlE", b"CoM"], 1,
               a_record(b"\x5d\xb8\xd8\x22", compressed=False, owner=[b"WwW", b"ExAmPlE", b"CoM"]),
               1))
write("response_lowercase_0x20", "two_answers",
      response(EXAMPLE, 1, a_record(b"\x5d\xb8\xd8\x22") + a_record(b"\x5d\xb8\xd8\x23"), 2))
write("response_lowercase_0x20", "ancount_lies",
      response(EXAMPLE, 1, a_record(b"\x5d\xb8\xd8\x22"), 9))
write("response_lowercase_0x20", "header_only",
      struct.pack(">HHHHHH", 0x1234, 0x8180, 0, 0, 0, 0))
write("response_lowercase_0x20", "nxdomain",
      struct.pack(">HHHHHH", 0x1234, 0x8183, 1, 0, 0, 0)
      + name_wire(EXAMPLE) + struct.pack(">HH", 1, 1))
write("response_lowercase_0x20", "truncated_rdata",
      response(EXAMPLE, 1, a_record(b"\x5d\xb8\xd8\x22")[:-2], 1))

# ----------------------------------------------------------------- upstream_relay
# The ID doubles as the relay's knobs (see the target); 0 swaps in our OPT.
def upstream(qtype: int, answers: bytes, additional: bytes, an: int, ar: int,
             flags: int = 0x8180) -> bytes:
    header = struct.pack(">HHHHHH", 0, flags, 1, an, 0, ar)
    return header + name_wire([b"example", b"com"]) + struct.pack(">HH", qtype, 1) + answers + additional


COOKIE_OPT = opt_record(1232, options=edns_option(10, bytes(24)))
MX = b"\xc0\x0c" + struct.pack(">HHIHH", 15, 1, 300, 7, 10) + b"\x02mx\xc0\x0c"
GLUE = b"\x02mx\xc0\x0c" + struct.pack(">HHIH", 1, 1, 300, 4) + b"\xc0\x00\x02\x19"
write("upstream_relay", "txt_opt_cookie",
      upstream(16, b"\xc0\x0c" + struct.pack(">HHIH", 16, 1, 300, 12) + b"\x0bv=spf1 -all",
               COOKIE_OPT, an=1, ar=1))
write("upstream_relay", "mx_glue_opt_last", upstream(15, MX, GLUE + COOKIE_OPT, an=1, ar=2))
write("upstream_relay", "mx_glue_opt_first", upstream(15, MX, COOKIE_OPT + GLUE, an=1, ar=2))
write("upstream_relay", "badcookie_extended_rcode",
      upstream(1, b"", b"\x00" + struct.pack(">HHBBHH", 41, 1232, 1, 0, 0, 0), an=0, ar=1,
               flags=0x8187))
# TSIG and SIG(0) must stay last (RFC 8945 §5.1, RFC 2931 §3.1); the relay drops them.
# TSIG: key name, class ANY, hmac-sha256, 32-byte MAC.
TSIG_RDATA = (name_wire([b"hmac-sha256"]) + struct.pack(">HIHH", 0, 0x6700_0000, 300, 32)
              + bytes(32) + struct.pack(">HHH", 0, 0, 0))
write("upstream_relay", "tsig_last",
      upstream(1, b"", name_wire([b"key"]) + struct.pack(">HHIH", 250, 255, 0, len(TSIG_RDATA))
               + TSIG_RDATA, an=0, ar=1))
# SIG(0): type covered 0, algo 13, 0 labels, TTL 0, expiry, inception, tag, signer, signature.
SIG0_RDATA = (struct.pack(">HBBIIIH", 0, 13, 0, 0, 0x6800_0000, 0x6700_0000, 0x1234)
              + name_wire([b"example", b"com"]) + bytes(64))
write("upstream_relay", "sig0_last",
      upstream(1, b"", b"\x00" + struct.pack(">HHIH", 24, 255, 0, len(SIG0_RDATA)) + SIG0_RDATA,
               an=0, ar=1))

# ------------------------------------------------------------------ dnssec_records
# RRSIG rdata: type covered A, algo 13, 2 labels, TTL, expiry, inception, tag,
# signer name, then the signature bytes.
write("dnssec_records", "rrsig_a_ecdsa",
      struct.pack(">HBBIIIH", 1, 13, 2, 3600, 0x6800_0000, 0x6700_0000, 0x1234)
      + name_wire([b"example", b"com"])
      + bytes(range(64)))
write("dnssec_records", "rrsig_truncated",
      struct.pack(">HBBIIIH", 1, 13, 2, 3600, 0x6800_0000, 0x6700_0000, 0x1234)[:12])
write("dnssec_records", "rrsig_root_signer",
      struct.pack(">HBBIIIH", 48, 8, 0, 172800, 0x6800_0000, 0x6700_0000, 0x4F66)
      + b"\x00"
      + bytes(256))
write("dnssec_records", "ds_sha256",
      struct.pack(">HBB", 0x4F66, 8, 2) + bytes(32))
write("dnssec_records", "ds_sha1",
      struct.pack(">HBB", 0x4F66, 8, 1) + bytes(20))
write("dnssec_records", "ds_sha384",
      struct.pack(">HBB", 0x4F66, 8, 4) + bytes(48))
write("dnssec_records", "ds_bad_digest_len",
      struct.pack(">HBB", 0x4F66, 8, 2) + bytes(31))
write("dnssec_records", "dnskey_zsk",
      struct.pack(">HBB", 0x0100, 3, 13) + bytes(64))
write("dnssec_records", "dnskey_ksk",
      struct.pack(">HBB", 0x0101, 3, 8) + bytes(260))
write("dnssec_records", "dnskey_odd_key_len",
      struct.pack(">HBB", 0x0101, 3, 8) + bytes(65))
write("dnssec_records", "empty", b"")

# --------------------------------------------------------------- proxy_protocol_v2
SIG = b"\r\n\r\n\x00\r\nQUIT\n"

write("proxy_protocol_v2", "proxy_tcp4",
      SIG + bytes([0x21, 0x11]) + struct.pack(">H", 12)
      + bytes([203, 0, 113, 1]) + bytes([198, 51, 100, 1])
      + struct.pack(">HH", 51234, 53))
write("proxy_protocol_v2", "proxy_tcp6",
      SIG + bytes([0x21, 0x21]) + struct.pack(">H", 36)
      + bytes(16) + bytes(16) + struct.pack(">HH", 51234, 53))
write("proxy_protocol_v2", "local_command",
      SIG + bytes([0x20, 0x00]) + struct.pack(">H", 0))
write("proxy_protocol_v2", "unspec_family",
      SIG + bytes([0x21, 0x00]) + struct.pack(">H", 0))
write("proxy_protocol_v2", "additional_len_too_large",
      SIG + bytes([0x21, 0x11]) + struct.pack(">H", 1024))
write("proxy_protocol_v2", "tcp4_short_address",
      SIG + bytes([0x21, 0x11]) + struct.pack(">H", 3) + b"\x01\x02\x03")
write("proxy_protocol_v2", "bad_version",
      SIG + bytes([0x11, 0x11]) + struct.pack(">H", 0))
write("proxy_protocol_v2", "bad_signature", b"PROXY TCP4 1.2.3.4 5.6.7.8 1 2\r\n")
write("proxy_protocol_v2", "header_only", SIG)

# ------------------------------------------------------------------ blocklist_text
write("blocklist_text", "hosts_format", b"""# Title: seed hosts list
0.0.0.0 ads.example.com
0.0.0.0 tracker.example.net
127.0.0.1 metrics.example.org
0.0.0.0 localhost
::1 ip6-localhost
""")
write("blocklist_text", "abp_format", b"""! seed adblock list
||ads.example.com^
||tracker.example.net^$third-party
@@||allowed.example.com^
||no-dot-here^
""")
write("blocklist_text", "plain_domains", b"ads.example.com\ntracker.example.net\nnodot\n")
write("blocklist_text", "wildcards", b"*.ads.example.com\n||*.tracker.example.net^\n")
write("blocklist_text", "regex_rules", b"/^ads[0-9]+\\.example\\.com$/\n//\n/(/\n")
write("blocklist_text", "whitespace_and_comments", b"\n   \n#\n!\n\t\n   0.0.0.0    a.b   \n")
write("blocklist_text", "empty", b"")

# -------------------------------------------------------------- mdns_announcement
# The fuzz target treats 192.168.1.20 as the datagram's source.
MDNS_SOURCE = bytes([192, 168, 1, 20])
MDNS_FLUSH_IN = 0x8001
HOST = [b"iPhone-de-Ana", b"local"]


def mdns(flags: int, questions: bytes, qd: int, records: bytes, an: int, ar: int = 0) -> bytes:
    return struct.pack(">HHHHHH", 0, flags, qd, an, 0, ar) + questions + records


def mdns_record(owner: bytes, rtype: int, rdata: bytes, ttl: int = 120,
                rclass: int = MDNS_FLUSH_IN) -> bytes:
    return owner + struct.pack(">HHIH", rtype, rclass, ttl, len(rdata)) + rdata


# The first record's owner starts right after the 12-byte header.
FIRST_OWNER = b"\xc0\x0c"
V6_LINK = bytes.fromhex("fe800000000000001c2d3e4f5a6b7c8d")

write("mdns_announcement", "self_announcement_a_aaaa",
      mdns(0x8400, b"", 0,
           mdns_record(name_wire(HOST), 1, MDNS_SOURCE)
           + mdns_record(FIRST_OWNER, 28, V6_LINK), an=1, ar=1))
write("mdns_announcement", "other_address",
      mdns(0x8400, b"", 0, mdns_record(name_wire([b"HP-LaserJet", b"local"]), 1,
                                       bytes([192, 168, 1, 30])), an=1))
write("mdns_announcement", "goodbye",
      mdns(0x8400, b"", 0, mdns_record(name_wire(HOST), 1, MDNS_SOURCE, ttl=0), an=1))
write("mdns_announcement", "query_with_known_answer",
      mdns(0x0000, name_wire(HOST) + struct.pack(">HH", 1, 0x8001), 1,
           mdns_record(FIRST_OWNER, 1, MDNS_SOURCE), an=1))
SERVICE = name_wire([b"_airplay", b"_tcp", b"local"])
INSTANCE = name_wire([b"Living Room", b"_airplay", b"_tcp", b"local"])
write("mdns_announcement", "service_with_host",
      mdns(0x8400, b"", 0,
           mdns_record(SERVICE, 12, INSTANCE, ttl=4500, rclass=1)
           + mdns_record(INSTANCE, 33, struct.pack(">HHH", 0, 0, 7000) + name_wire(HOST))
           + mdns_record(INSTANCE, 16, b"\x09model=TV1")
           + mdns_record(name_wire(HOST), 1, MDNS_SOURCE), an=4))

total = sum(1 for _ in CORPUS.rglob("*.bin"))
print(f"wrote {total} seed files under {CORPUS}")
