"""Write the seed corpora for the mcd fuzz harnesses.

Usage: python3 gen_seeds.py <corpus-dir> [<repo-root>]

Writes <corpus-dir>/<harness>/<name> for every harness. Seeds are valid,
protocol-correct inputs, so the fuzzer starts from the interesting paths
(a v3 report with records, a query that wins the election, a config that
sets up VLANs and static groups, ...) instead of having to discover the
framing first. Packet seeds use the framing in packet.h: a mode byte,
then u16 big-endian length-prefixed packets.

With a repo root, the sample mcd.conf is added to the config corpus.
"""

import ipaddress
import os
import struct
import sys

# Mode bits, fuzz_harness.h
V1, V2, V3 = 1, 2, 3
PROXY, DISABLED, TIMERS, VLAN, HIGH = 0x04, 0x08, 0x10, 0x20, 0x80

PEER4 = "10.0.0.20"
PEER6 = "fe80::20"


def csum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def ip4(src, dst, payload, ra=True):
    opts = b"\x94\x04\x00\x00" if ra else b""
    ihl = (20 + len(opts)) // 4
    hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x40 | ihl, 0xC0, 20 + len(opts) + len(payload), 0, 0, 1, 2, 0,
        ipaddress.IPv4Address(src).packed, ipaddress.IPv4Address(dst).packed,
    ) + opts
    hdr = hdr[:10] + struct.pack("!H", csum(hdr)) + hdr[12:]
    return hdr + payload


def igmp(type_, code, group, extra=b""):
    body = struct.pack("!BBH4s", type_, code, 0, ipaddress.IPv4Address(group).packed) + extra
    return body[:2] + struct.pack("!H", csum(body)) + body[4:]


def igmpv3_query(group, mrc=100, qqic=125, sources=()):
    extra = struct.pack("!BBH", 2, qqic, len(sources))
    extra += b"".join(ipaddress.IPv4Address(s).packed for s in sources)
    return igmp(0x11, mrc, group, extra)


def igmpv3_report(records):
    body = b""
    for rtype, group, sources in records:
        body += struct.pack("!BBH4s", rtype, 0, len(sources), ipaddress.IPv4Address(group).packed)
        body += b"".join(ipaddress.IPv4Address(s).packed for s in sources)
    msg = struct.pack("!BBHHH", 0x22, 0, 0, 0, len(records)) + body
    return msg[:2] + struct.pack("!H", csum(msg)) + msg[4:]


def ip6(src, dst, icmp, hbh=True):
    s = ipaddress.IPv6Address(src).packed
    d = ipaddress.IPv6Address(dst).packed
    pseudo = s + d + struct.pack("!IxxxB", len(icmp), 58)
    icmp = icmp[:2] + struct.pack("!H", csum(pseudo + icmp[:2] + b"\0\0" + icmp[4:])) + icmp[4:]
    if hbh:
        # Hop-by-hop with Router Alert (MLD), padded to 8 bytes.
        ext = struct.pack("!BB", 58, 0) + b"\x05\x02\x00\x00" + b"\x01\x00"
        nxt, payload = 0, ext + icmp
    else:
        nxt, payload = 58, icmp
    return struct.pack("!IHBB", 0x60000000, len(payload), nxt, 1) + s + d + payload


def mld(type_, group="::", delay=10000, extra=b""):
    return struct.pack("!BBHHH16s", type_, 0, 0, delay, 0, ipaddress.IPv6Address(group).packed) + extra


def mldv2_query(group="::", mrc=10000, qqic=125, sources=()):
    extra = struct.pack("!BBH", 2, qqic, len(sources))
    extra += b"".join(ipaddress.IPv6Address(s).packed for s in sources)
    return mld(130, group, mrc, extra)


def mldv2_report(records):
    body = b""
    for rtype, group, sources in records:
        body += struct.pack("!BBH16s", rtype, 0, len(sources), ipaddress.IPv6Address(group).packed)
        body += b"".join(ipaddress.IPv6Address(s).packed for s in sources)
    return struct.pack("!BBHHH", 143, 0, 0, 0, len(records)) + body


def frame(mode, *packets):
    return bytes([mode]) + b"".join(struct.pack("!H", len(p)) + p for p in packets)


def igmp_seeds():
    q2 = ip4(PEER4, "224.0.0.1", igmp(0x11, 100, "0.0.0.0"))
    q1 = ip4(PEER4, "224.0.0.1", igmp(0x11, 0, "0.0.0.0"))
    q3 = ip4(PEER4, "224.0.0.1", igmpv3_query("0.0.0.0"))
    gsq = ip4(PEER4, "239.1.2.3", igmpv3_query("239.1.2.3", sources=["10.0.0.99"]))
    r1 = ip4(PEER4, "239.1.2.3", igmp(0x12, 0, "239.1.2.3"))
    r2 = ip4(PEER4, "239.1.2.3", igmp(0x16, 0, "239.1.2.3"))
    leave = ip4(PEER4, "224.0.0.2", igmp(0x17, 0, "239.1.2.3"))
    r3 = ip4(PEER4, "224.0.0.22", igmpv3_report([
        (1, "239.1.2.3", []),             # MODE_IS_INCLUDE
        (2, "239.4.5.6", ["10.0.0.99"]),  # MODE_IS_EXCLUDE
        (4, "239.7.8.9", []),             # CHANGE_TO_EXCLUDE (join)
        (3, "239.1.2.3", []),             # CHANGE_TO_INCLUDE {} (leave)
    ]))
    proxy_q = ip4("0.0.0.0", "224.0.0.1", igmp(0x11, 100, "0.0.0.0"))
    return {
        "query-v2": frame(V3, q2),
        "query-v1": frame(V1, q1),
        "query-v3-wins": frame(V3 | HIGH, q3),
        "query-v3-group-specific": frame(V3, gsq),
        "report-v1": frame(V1 | TIMERS, r1),
        "report-v2-leave": frame(V2 | TIMERS, r2, leave),
        "report-v3-records": frame(V3 | TIMERS, r3),
        "report-then-query": frame(V3 | HIGH | TIMERS, r2, q3, leave),
        "proxy-query": frame(V3 | PROXY, proxy_q, r2),
        "vlan-report": frame(V2 | VLAN | TIMERS, r2, leave),
        "disabled": frame(V3 | DISABLED, q3, r3),
    }


def mld_seeds():
    q1 = ip6(PEER6, "ff02::1", mld(130))
    q2 = ip6(PEER6, "ff02::1", mldv2_query())
    gsq = ip6(PEER6, "ff0e::123", mldv2_query("ff0e::123", sources=["fe80::99"]))
    r1 = ip6(PEER6, "ff0e::123", mld(131, "ff0e::123"))
    done = ip6(PEER6, "ff02::2", mld(132, "ff0e::123"))
    r2 = ip6(PEER6, "ff02::16", mldv2_report([
        (1, "ff0e::123", []),
        (2, "ff0e::456", ["fe80::99"]),
        (4, "ff0e::789", []),
        (3, "ff0e::123", []),
    ]))
    nohbh = ip6(PEER6, "ff02::1", mldv2_query(), hbh=False)
    return {
        "query-v1": frame(V2, q1),
        "query-v2-wins": frame(V3 | HIGH, q2),
        "query-v2-group-specific": frame(V3, gsq),
        "report-v1-done": frame(V2 | TIMERS, r1, done),
        "report-v2-records": frame(V3 | TIMERS, r2),
        "report-then-query": frame(V3 | HIGH | TIMERS, r1, q2, done),
        "query-no-hop-by-hop": frame(V3, nohbh),
        "vlan-report": frame(V3 | VLAN | TIMERS, r2),
    }


CONFIGS = {
    "empty": "",
    "globals": (
        "global-query-interval 30\n"
        "global-response-interval 5\n"
        "global-last-member-interval 1\n"
        "robustness 3\n"
        "router-timeout 255\n"
        "router-alert on\n"
    ),
    "iface": "iface eth0 enable igmpv2 query-interval 10\n",
    "proxy": "iface br0 enable proxy-mode\n",
    "vlans": (
        "iface br0 vlan 1 enable igmpv3 mldv2\n"
        "iface br0 vlan 2 enable igmpv2 mldv1\n"
    ),
    "static-groups": (
        "iface br0 enable\n"
        "  static-group 239.1.2.3\n"
        "  static-group ff0e::123\n"
    ),
    "proto-off": "iface br0 enable igmp off\niface br1 enable mld off\n",
    "disable": "# comment line\nno router-alert\niface eth1 disable\n",
}

IPC = [
    "help", "version", "show", "show json", "show igmp", "show igmp json",
    "show groups", "show groups json", "show interfaces detail",
    "show mdb", "show router-ports", "show compat", "show status",
    "check", "show compat detail",
]

INET = [
    (4, "10.0.0.1"), (4, "255.255.255.255"), (4, "0.0.0.0"), (3, "192.168.1"),
    (1, "10"), (2, "172.16"), (4, "1.2.3.4.5"), (4, "256.1.1.1"), (4, "1..2.3"),
]

BRIDGE_MDB = (
    "dev br0 port eth1 grp 239.1.2.3 temp\n"
    "dev br0 port eth2 grp 239.1.2.3 vid 10 temp\n"
    "dev br0 port br0 grp ff0e::123 permanent\n"
)
BRIDGE_JSON = '[{"ifname":"br0","linkinfo":{"info_data":{"mcast_querier":1,"mcast_snooping":1,"mcast_router":1}}}]\n'
ROUTER_PORTS = "br0 eth1\nbr0 eth2\n"
NEIGH = "10.0.0.20 dev eth1 lladdr 02:00:00:00:00:20 REACHABLE\n02:00:00:00:00:20 dev eth1 master br0\n"


# Inputs that reproduced a bug, one row per bug. They join their harness's
# corpus as regress-<name>, so checks.fuzz-replay fails if the bug returns
# (and fuzzing starts from them). Row: harness, name, description, input.
REGRESSIONS = [
    {
        "harness": "ipc",
        "name": "chomp-all-newlines",
        "description": "a command of only newlines: chomp() read before the buffer",
        "input": "\n",
    },
    {
        "harness": "cfparse",
        "name": "long-dotted-quad",
        "description": "a 64-digit token: sscanf(\"%[.0-9]\") overflowed the global s1",
        "input": "router-timeout " + "1" * 64 + "\n",
    },
    {
        "harness": "cfparse",
        "name": "full-line-no-newline",
        "description": "a token filling fgets()'s 1023 bytes: yytoken() stepped past buf",
        "input": "x" * 1023,
    },
    {
        "harness": "bridge_mdb",
        "name": "mdb-line-ends-after-keyword",
        "description": "`bridge mdb show` line ending after `port`: strlcpy() got strtok()'s NULL",
        "input": b"\x00dev br0 port",
    },
    {
        "harness": "bridge_mdb",
        "name": "mdb-line-ends-after-vid",
        "description": "`bridge mdb show` line ending after `vid`: strtol() got strtok()'s NULL",
        "input": b"\x00dev br0 port eth1 grp 239.1.2.3 vid",
    },
    {
        "harness": "bridge_mdb",
        "name": "mdb-many-ports-one-group",
        "description": "40 long port names in one group: strcat() overflowed the 576-byte port list",
        "input": b"\x00" + b"".join(
            b"dev br0 port p%016d grp 239.1.2.3 temp\n" % i for i in range(40)
        ),
    },
    {
        "harness": "bridge_mdb",
        "name": "json-keys-without-values",
        "description": "an object of keys with no values ending 256 tokens: "
        "bridge_prop() read key/value pairs past the token array",
        "input": b"\x02[" + b"1," * 252 + b'{"a" "b"}]\n',
    },
    {
        "harness": "bridge_mdb",
        "name": "json-fills-read-buffer",
        "description": "bridge property JSON of BUFSIZ (8192) bytes or more: "
        "bridge_prop() terminated it one byte past its buffer",
        "input": b"\x02" + b" " * 8192,
    },
]


def write(corpus, harness, name, data):
    d = os.path.join(corpus, harness)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, name), "wb") as f:
        f.write(data if isinstance(data, bytes) else data.encode())


def main():
    corpus = sys.argv[1]
    root = sys.argv[2] if len(sys.argv) > 2 else None

    for name, data in igmp_seeds().items():
        write(corpus, "igmp", name, data)
    for name, data in mld_seeds().items():
        write(corpus, "mld", name, data)
    for name, text in CONFIGS.items():
        write(corpus, "cfparse", name, text)
    if root:
        with open(os.path.join(root, "mcd.conf"), "rb") as f:
            write(corpus, "cfparse", "sample-mcd.conf", f.read())
    for i, cmd in enumerate(IPC):
        write(corpus, "ipc", f"cmd{i:02d}", cmd + "\n")
    for i, (n, s) in enumerate(INET):
        write(corpus, "inet_parse", f"addr{i:02d}", bytes([n - 1]) + s.encode())
    for sel, (name, text) in enumerate([
        ("mdb", BRIDGE_MDB), ("groups", BRIDGE_MDB), ("prop-json", BRIDGE_JSON),
        ("router-ports", ROUTER_PORTS), ("router-ports-all", ROUTER_PORTS), ("dumpster", NEIGH),
    ]):
        write(corpus, "bridge_mdb", name, bytes([sel]) + text.encode())
    for r in REGRESSIONS:
        write(corpus, r["harness"], "regress-" + r["name"], r["input"])


if __name__ == "__main__":
    main()
