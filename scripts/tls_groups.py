#!/usr/bin/env python3
#
# @author Couchbase <info@couchbase.com>
# @copyright 2026-Present Couchbase, Inc.
#
# Use of this software is governed by the Business Source License included in
# the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
# file, in accordance with the Business Source License, use of this software
# will be governed by the Apache License, Version 2.0, included in the file
# licenses/APL2.txt.
"""Discover the TLS 1.3 key exchange groups a server supports, in the order
the server prefers them.

How it works: every probe is a TLS 1.3 ClientHello that lists candidate
groups in supported_groups but sends an empty key_share. A server that
supports at least one of them has to answer with a HelloRetryRequest naming
the group it selected, so no key exchange crypto is needed. Removing the
selected group and probing again yields the server's priority order. Probing
each pair of neighbours in that order reversed tells whether the server
decides between them or lets the client's order decide; groups the server
lets the client decide between form a tier of equal priority (like OpenSSL's
group tuples).

Groups whose probe ends with an unexpected alert (e.g. the server crashes
while preparing the HelloRetryRequest) are probed one by one and reported in
`failing`.

Usage as a library:

    from tls_groups import discover_tls13_groups
    report = discover_tls13_groups("127.0.0.1", 19000)
    print([[g.name for g in tier] for tier in report.tiers])
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import socket
import sys
from dataclasses import dataclass, field
from typing import (Dict, Iterable, List, NamedTuple, Optional, Sequence,
                    Tuple, Union)


class Group(NamedTuple):
    name: str
    code: int
    kind: str  # classic | hybrid | post_quantum | unknown

    def __str__(self) -> str:
        return self.name


# IANA TLS Supported Groups registry, only the groups valid in TLS 1.3
KNOWN_GROUPS: List[Group] = [
    Group("x25519", 0x001D, "classic"),
    Group("x448", 0x001E, "classic"),
    Group("secp256r1", 0x0017, "classic"),
    Group("secp384r1", 0x0018, "classic"),
    Group("secp521r1", 0x0019, "classic"),
    Group("brainpoolP256r1tls13", 0x001F, "classic"),
    Group("brainpoolP384r1tls13", 0x0020, "classic"),
    Group("brainpoolP512r1tls13", 0x0021, "classic"),
    Group("ffdhe2048", 0x0100, "classic"),
    Group("ffdhe3072", 0x0101, "classic"),
    Group("ffdhe4096", 0x0102, "classic"),
    Group("ffdhe6144", 0x0103, "classic"),
    Group("ffdhe8192", 0x0104, "classic"),
    Group("X25519MLKEM768", 0x11EC, "hybrid"),
    Group("SecP256r1MLKEM768", 0x11EB, "hybrid"),
    Group("SecP384r1MLKEM1024", 0x11ED, "hybrid"),
    Group("X25519Kyber768Draft00", 0x6399, "hybrid"),
    Group("MLKEM512", 0x0200, "post_quantum"),
    Group("MLKEM768", 0x0201, "post_quantum"),
    Group("MLKEM1024", 0x0202, "post_quantum"),
]

_BY_CODE = {g.code: g for g in KNOWN_GROUPS}
_BY_NAME = {g.name.lower(): g for g in KNOWN_GROUPS}

ALERTS = {
    0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac",
    40: "handshake_failure", 42: "bad_certificate", 43:
    "unsupported_certificate", 47: "illegal_parameter", 50: "decode_error",
    51: "decrypt_error", 70: "protocol_version", 71: "insufficient_security",
    80: "internal_error", 86: "inappropriate_fallback", 90: "user_canceled",
    109: "missing_extension", 110: "unsupported_extension",
    112: "unrecognized_name", 116: "certificate_required",
    120: "no_application_protocol",
}

# Alerts that mean "none of the offered groups is acceptable"
_NO_COMMON_GROUP_ALERTS = {40, 71}

_HRR_RANDOM = bytes.fromhex(
    "CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C")

_CIPHER_SUITES = [0x1302, 0x1303, 0x1301, 0x1304, 0x1305]

_SIGNATURE_ALGORITHMS = [
    0x0403, 0x0503, 0x0603,          # ecdsa_secp*_sha*
    0x0807, 0x0808,                  # ed25519, ed448
    0x0804, 0x0805, 0x0806,          # rsa_pss_rsae_sha*
    0x0809, 0x080A, 0x080B,          # rsa_pss_pss_sha*
    0x0401, 0x0501, 0x0601,          # rsa_pkcs1_sha*, for certificates
    0x0201, 0x0203,                  # sha1, for certificates
]


def group_from(value: Union[str, int, Group]) -> Group:
    """Resolve a group name (case-insensitive), a codepoint, or a "0x..."
    string."""
    if isinstance(value, Group):
        return value
    if isinstance(value, str):
        known = _BY_NAME.get(value.lower())
        if known:
            return known
        try:
            value = int(value, 0)
        except ValueError:
            raise ValueError(f"unknown TLS group: {value}") from None
    if value in _BY_CODE:
        return _BY_CODE[value]
    if not 0 <= value <= 0xFFFF:
        raise ValueError(f"invalid TLS group codepoint: {value}")
    return Group(f"0x{value:04x}", value, "unknown")


class TLSProbeError(Exception):
    pass


@dataclass
class _ProbeResult:
    selected: Optional[int] = None    # group the server picked
    alert: Optional[int] = None       # alert the server sent instead
    closed: bool = False              # connection closed without an alert
    tls12: bool = False               # server negotiated TLS 1.2 or lower

    def describe(self) -> str:
        if self.alert is not None:
            return ALERTS.get(self.alert, f"alert {self.alert}")
        if self.closed:
            return "connection closed"
        if self.tls12:
            return "TLS 1.3 not negotiated"
        return f"selected {group_from(self.selected)}"


@dataclass
class TLSGroupsReport:
    host: str
    port: int
    # Supported groups, most preferred first
    supported: List[Group] = field(default_factory=list)
    # `supported` split into tiers of equal priority, the client's order
    # decides between groups of the same tier
    tiers: List[List[Group]] = field(default_factory=list)
    # True: the server enforces its own order; False: it follows the client's
    # order; None: mixed (see tiers) or fewer than two groups
    server_preference: Optional[bool] = None
    # Groups the server could not complete a handshake step for, with the
    # reason (usually the alert the server sent)
    failing: Dict[Group, str] = field(default_factory=dict)
    # Supported groups whose relative priority couldn't be determined
    unordered: List[Group] = field(default_factory=list)
    probes: int = 0

    def to_dict(self) -> dict:
        def g(x: Group) -> dict:
            return {"name": x.name, "code": f"0x{x.code:04x}", "kind": x.kind}
        return {
            "host": self.host,
            "port": self.port,
            "supported": [dict(g(x), tier=i)
                          for i, tier in enumerate(self.tiers, 1)
                          for x in tier],
            "server_preference": self.server_preference,
            "unordered": [g(x) for x in self.unordered],
            "failing": [dict(g(x), reason=r) for x, r in self.failing.items()],
            "probes": self.probes,
        }


def _u8(b: bytes) -> bytes:
    return len(b).to_bytes(1, "big") + b


def _u16(b: bytes) -> bytes:
    return len(b).to_bytes(2, "big") + b


def _u24(b: bytes) -> bytes:
    return len(b).to_bytes(3, "big") + b


def _ext(ext_type: int, data: bytes) -> bytes:
    return ext_type.to_bytes(2, "big") + _u16(data)


def _client_hello(groups: Sequence[int], server_name: Optional[str]) -> bytes:
    exts = b""
    if server_name:
        name = server_name.encode("idna")
        exts += _ext(0, _u16(b"\x00" + _u16(name)))
    exts += _ext(10, _u16(b"".join(g.to_bytes(2, "big") for g in groups)))
    exts += _ext(13, _u16(b"".join(a.to_bytes(2, "big")
                                   for a in _SIGNATURE_ALGORITHMS)))
    exts += _ext(43, _u8(b"\x03\x04"))   # supported_versions: TLS 1.3
    exts += _ext(45, _u8(b"\x01"))       # psk_key_exchange_modes: psk_dhe_ke
    exts += _ext(51, _u16(b""))          # key_share: empty, forces HRR
    body = (b"\x03\x03" + os.urandom(32) + _u8(os.urandom(32))
            + _u16(b"".join(c.to_bytes(2, "big") for c in _CIPHER_SUITES))
            + _u8(b"\x00") + _u16(exts))
    handshake = b"\x01" + _u24(body)
    return b"\x16\x03\x01" + _u16(handshake)


def _recv_exact(sock: socket.socket, n: int) -> Optional[bytes]:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def _parse_server_hello(body: bytes) -> _ProbeResult:
    off = 34
    off += 1 + body[off]           # session id
    off += 3                       # cipher suite, compression
    exts_end = off + 2 + int.from_bytes(body[off:off + 2], "big")
    off += 2
    selected = version = None
    while off + 4 <= exts_end:
        ext_type = int.from_bytes(body[off:off + 2], "big")
        ext_len = int.from_bytes(body[off + 2:off + 4], "big")
        data = body[off + 4:off + 4 + ext_len]
        if ext_type == 51 and len(data) >= 2:
            selected = int.from_bytes(data[:2], "big")
        elif ext_type == 43 and len(data) == 2:
            version = int.from_bytes(data, "big")
        off += 4 + ext_len
    if version != 0x0304:
        return _ProbeResult(tls12=True)
    if selected is None:
        raise TLSProbeError("TLS 1.3 ServerHello without key_share")
    return _ProbeResult(selected=selected)


def _probe(host: str, port: int, groups: Sequence[int],
           server_name: Optional[str], timeout: float) -> _ProbeResult:
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall(_client_hello(groups, server_name))
        handshake = b""
        while True:
            header = _recv_exact(sock, 5)
            if header is None:
                return _ProbeResult(closed=True)
            content_type = header[0]
            record = _recv_exact(sock, int.from_bytes(header[3:5], "big"))
            if record is None:
                return _ProbeResult(closed=True)
            if content_type == 21:                      # alert
                return _ProbeResult(alert=record[1])
            if content_type == 20:                      # change_cipher_spec
                continue
            if content_type != 22:
                raise TLSProbeError(
                    f"unexpected TLS record type {content_type}")
            handshake += record
            if len(handshake) < 4:
                continue
            msg_len = int.from_bytes(handshake[1:4], "big")
            if len(handshake) < 4 + msg_len:
                continue
            if handshake[0] != 2:
                raise TLSProbeError(
                    f"expected ServerHello, got handshake type {handshake[0]}")
            return _parse_server_hello(handshake[4:4 + msg_len])


def discover_tls13_groups(
        host: str,
        port: int = 443,
        *,
        server_name: Optional[str] = None,
        timeout: float = 5.0,
        groups: Optional[Iterable[Union[str, int, Group]]] = None,
) -> TLSGroupsReport:
    """Find which of `groups` (all known TLS 1.3 groups by default) the server
    supports and in which order it prefers them.

    `server_name` is sent as SNI; it defaults to `host` unless that is an IP
    address. Raises OSError on connection problems and TLSProbeError when the
    server's reply can't be interpreted.
    """
    if server_name is None:
        try:
            ipaddress.ip_address(host)
        except ValueError:
            server_name = host
    candidates = [group_from(g) for g in (groups or KNOWN_GROUPS)]
    by_code = {g.code: g for g in candidates}
    report = TLSGroupsReport(host=host, port=port)

    def probe(offered: Sequence[Group]) -> _ProbeResult:
        report.probes += 1
        return _probe(host, port, [g.code for g in offered], server_name,
                      timeout)

    def no_common_group(r: _ProbeResult) -> bool:
        return r.alert in _NO_COMMON_GROUP_ALERTS

    remaining = list(candidates)
    isolated = False   # whether the remaining groups were probed one by one
    while remaining:
        r = probe(remaining)
        if r.selected is not None and r.selected in by_code and \
                by_code[r.selected] in remaining:
            group = by_code[r.selected]
            report.supported.append(group)
            remaining.remove(group)
            continue
        if no_common_group(r):
            break
        if r.tls12 and not report.supported:
            raise TLSProbeError("server doesn't support TLS 1.3")
        if isolated:
            # Every remaining group works on its own, but not together
            report.unordered = remaining
            break
        # Something in the offer breaks the server, find out what
        working = []
        for group in remaining:
            single = probe([group])
            if single.selected == group.code:
                working.append(group)
            elif not no_common_group(single):
                report.failing[group] = single.describe()
        reasons = set(report.failing.values())
        if not report.supported and not working and len(report.failing) > 1 \
                and len(reasons) == 1:
            raise TLSProbeError(
                f"TLS 1.3 handshake fails with every group: {reasons.pop()}")
        remaining = working
        isolated = True

    for group in report.supported:
        if report.tiers:
            prev = report.tiers[-1][-1]
            if probe([group, prev]).selected == group.code:
                report.tiers[-1].append(group)
                continue
        report.tiers.append([group])
    if len(report.supported) >= 2:
        if len(report.tiers) == len(report.supported):
            report.server_preference = True
        elif len(report.tiers) == 1:
            report.server_preference = False
    return report


def _parse_target(target: str, default_port: int) -> Tuple[str, int]:
    if target.startswith("["):                      # [ipv6]:port
        host, _, rest = target[1:].partition("]")
        return host, int(rest[1:]) if rest.startswith(":") else default_port
    if target.count(":") == 1:
        host, port = target.split(":")
        return host, int(port)
    return target, default_port


def _print_report(report: TLSGroupsReport) -> None:
    print(f"TLS 1.3 groups supported by {report.host}:{report.port}")
    if not report.supported and not report.unordered:
        print("  none of the probed groups")
    width = max([len(g.name) for g in KNOWN_GROUPS] + [10])
    for i, tier in enumerate(report.tiers, 1):
        for g in tier:
            print(f"  {i:>2}. {g.name:<{width}}  0x{g.code:04x}  {g.kind}")
    for g in report.unordered:
        print(f"   -  {g.name:<{width}}  0x{g.code:04x}  {g.kind}"
              "  (priority unknown)")
    if report.server_preference is True:
        print("Group selection follows: server's order")
    elif report.server_preference is False:
        print("Group selection follows: client's order")
    elif len(report.supported) >= 2:
        print("Group selection follows: server's order, except that the "
              "client's order decides between groups with the same number")
    if report.failing:
        print("Groups that make the handshake fail:")
        for g, reason in report.failing.items():
            print(f"      {g.name:<{width}}  0x{g.code:04x}  {reason}")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Discover a server's TLS 1.3 groups and their priority.")
    parser.add_argument("target", help="host, host:port or [ipv6]:port")
    parser.add_argument("-p", "--port", type=int, default=443,
                        help="port if not given in target (default: 443)")
    parser.add_argument("--sni", help="server name to send "
                        "(default: the host unless it is an IP address)")
    parser.add_argument("--groups", help="comma separated groups to probe, "
                        "names or codepoints (default: all known)")
    parser.add_argument("--timeout", type=float, default=5.0,
                        help="per-connection timeout in seconds")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = parser.parse_args(argv)

    host, port = _parse_target(args.target, args.port)
    groups = args.groups.split(",") if args.groups else None
    try:
        report = discover_tls13_groups(host, port, server_name=args.sni,
                                       timeout=args.timeout, groups=groups)
    except (OSError, TLSProbeError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        _print_report(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
