#!/usr/bin/env python3
"""Four availability cases, using real mosdns and nft in an isolated Linux network namespace.

    sudo unshare --net python3 -B integration_geo.py --mosdns /usr/local/lib/awg-geo/mosdns
"""

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import shutil
import socket
import socketserver
import struct
import subprocess
import tempfile
import threading
import time
from unittest.mock import patch

import geo_update as updater
from render import render, settings
from test_geo_update import Release


HERE = Path(__file__).resolve().parent
TABLE = "awg_geo_accept"
PROBE_PORT = 49001
DNS_PORT = 19553
PHASES = {"before": 10, "after": 20}
HOSTS = {f"{phase}.site{v}2.example": f"192.0.2.{offset + v}"
         for phase, offset in PHASES.items() for v in (1, 2)}
HOSTS["ready.example"] = "192.0.2.254"


def require(value, message):
    if not value:
        raise RuntimeError(message)


def command(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, capture_output=True, **kwargs).stdout


def nft_script(script):
    command("nft", "-f", "-", input=script + "\n")


def table():
    nft_script(f"""
table inet {TABLE} {{
    set ru_nets {{ type ipv4_addr; flags interval; auto-merge; }}
    set ru_dns_a {{ type ipv4_addr; }}
    set ru_dns_b {{ type ipv4_addr; }}
    counter ip_hits {{}}
    counter dns_a_hits {{}}
    counter dns_b_hits {{}}
    chain output {{
        type filter hook output priority filter; policy accept;
        udp dport {PROBE_PORT} ip daddr @ru_nets counter name ip_hits
        udp dport {PROBE_PORT} ip daddr @ru_dns_a counter name dns_a_hits
        udp dport {PROBE_PORT} ip daddr @ru_dns_b counter name dns_b_hits
    }}
}}
""")


def packets(name):
    result = json.loads(command("nft", "-j", "list", "counter", "inet", TABLE, name))
    return next(obj["counter"]["packets"] for obj in result["nftables"] if "counter" in obj)


def packet_matches(address, name):
    before = packets(name)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(b"probe", (address, PROBE_PORT))
    after = packets(name)
    require(after - before in (0, 1), f"unexpected packet counter delta for {address}")
    return after != before


def dns_slots(address):
    return [slot for slot in ("a", "b") if packet_matches(address, f"dns_{slot}_hits")]


def upstream_answer(query):
    pos = 12
    labels = []
    while query[pos]:
        size = query[pos]
        labels.append(query[pos + 1:pos + 1 + size].decode("ascii"))
        pos += size + 1
    host = ".".join(labels).lower()
    qtype, = struct.unpack_from("!H", query, pos + 1)
    if qtype == 28:
        address = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
    else:
        address = socket.inet_aton(HOSTS[host])
    header = query[:2] + struct.pack("!5H", 0x8180, 1, 1, 0, 0)
    rr = struct.pack("!HHHIH", 0xC00C, qtype, 1, 60, len(address)) + address
    return host, qtype, header + query[12:pos + 5] + rr


class StubHandler(socketserver.StreamRequestHandler):
    def handle(self):
        while True:
            prefix = self.rfile.read(2)
            if len(prefix) != 2:
                return
            size, = struct.unpack("!H", prefix)
            host, qtype, answer = upstream_answer(self.rfile.read(size))
            self.server.record_query(host, qtype)
            self.wfile.write(struct.pack("!H", len(answer)) + answer)


class StubServer(socketserver.ThreadingTCPServer):
    daemon_threads = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), StubHandler)
        self.queries = set()
        self.lock = threading.Lock()

    @property
    def url(self):
        host, port = self.server_address
        return f"tcp://{host}:{port}"

    def record_query(self, host, qtype):
        with self.lock:
            self.queries.add((host, qtype))

    def received(self, host, qtype):
        with self.lock:
            return (host, qtype) in self.queries


@contextmanager
def stub_server():
    with StubServer() as server:
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        thread.start()
        try:
            yield server
        finally:
            server.shutdown()
            thread.join()


def query(host, qtype=1):
    qid = os.urandom(2)
    name = b"".join(bytes([len(x)]) + x.encode() for x in host.split(".")) + b"\0"
    wire = qid + struct.pack("!5H", 0x100, 1, 0, 0, 0) + name + struct.pack("!2H", qtype, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(0.4)
        sock.connect(("127.0.0.1", DNS_PORT))
        sock.send(wire)
        data = sock.recv(4096)
    require(data[:2] == qid and len(data) >= 12, "invalid DNS transaction")
    flags, _, count = struct.unpack_from("!3H", data, 2)
    require(flags & 0x800F == 0x8000, f"invalid DNS response for {host} type {qtype}")
    if qtype == 28:
        require(count == 0, f"unexpected AAAA answer for {host}")
    else:
        require(count == 1 and data[-4:] == socket.inet_aton(HOSTS[host]), f"wrong A record for {host}")


class LiveBackend:
    def __init__(self, root, mosdns, upstreams):
        self.root = root
        self.mosdns = mosdns
        self.upstreams = upstreams
        self.process = None
        self.hooks = []
        example = HERE / "site.example.json"
        values = settings(example)
        rendered = root / "rendered"
        render(example, rendered)
        functions = runpy.run_path(str(rendered / "apply-data"))
        self.load_geoip = functions["load_geoip"]
        self.rotate = functions["rotate"]
        self.load_geoip.__globals__.update(ROOT=root, FAMILY_TABLE=f"inet {TABLE}", NFT=shutil.which("nft"))
        config = (rendered / "mosdns.yaml").read_text()
        for original, local in (
            ("/var/lib/awg-geo/geosite/current/rules.txt", str(root / "geosite/current/rules.txt")),
            (f"tcp://{values['DNS_IP']}:53", upstreams["amnezia"].url),
            (f"{values['BRIDGE_GW']}:1053", f"127.0.0.1:{DNS_PORT}"),
            ("inet,awg_geo,", f"inet,{TABLE},"),
        ):
            require(original in config, f"fixture substitution missing: {original}")
            config = config.replace(original, local)
        for dial_addr in ("77.88.8.8:853", "77.88.8.1:853"):
            pattern = (r"(?m)^([ \t]*- addr:[ \t]+)tls://common\.dot\.dns\.yandex\.net[ \t]*\n"
                       rf"[ \t]+dial_addr:[ \t]+{re.escape(dial_addr)}[ \t]*\n")
            config, count = re.subn(pattern, rf"\g<1>{upstreams['yandex'].url}\n", config)
            require(count == 1, f"invalid number of fixture Yandex endpoints for {dial_addr}: {count}")
        self.config = root / "mosdns.yaml"
        self.config.write_text(config)

    def stop(self):
        if self.process is not None:
            if self.process.poll() is None:
                self.process.terminate()
            self.process.wait(timeout=5)
            self.process = None

    def apply(self, source):
        self.hooks.append(source)
        if source == "geoip":
            self.load_geoip()
        elif source == "rotate":
            self.rotate()
        else:
            self.stop()
            self.process = subprocess.Popen([self.mosdns, "start", "-c", self.config, "-d", self.root])
            until = time.monotonic() + 8
            while time.monotonic() < until and self.process.poll() is None:
                try:
                    query("ready.example")
                    return
                except OSError:
                    time.sleep(0.1)
            raise RuntimeError("fixture mosdns failed to answer")

    def upstream_paths(self, host, qtype):
        return [name for name, server in self.upstreams.items() if server.received(host, qtype)]

    def observe(self, phase):
        hashes = {}
        for source in updater.CATEGORIES:
            current = self.root / source / "current"
            hashes[source] = {
                "dat_sha256": updater.sha256_file(current / (source + ".dat")),
                "rules_sha256": updater.sha256_file(current / "rules.txt"),
            }
        nftset = json.loads(command("nft", "-j", "list", "set", "inet", TABLE, "ru_nets"))
        elements = next(o["set"]["elem"] for o in nftset["nftables"] if "set" in o)
        hashes["geoip"]["nft_elements_sha256"] = hashlib.sha256(
            json.dumps(elements, sort_keys=True).encode()
        ).hexdigest()
        hits = {"geoip": [], "geosite": []}
        upstream_paths = []
        for v in (1, 2):
            hits["geoip"].append(packet_matches(f"198.51.100.{v * 32 + 9}", "ip_hits"))
            host = f"{phase}.site{v}2.example"
            query(host)
            upstream_paths.append(self.upstream_paths(host, 1))
            slots = dns_slots(HOSTS[host])
            require(len(slots) != 1, f"address for {host} appears in only one DNS set: {slots}")
            hits["geosite"].append(bool(slots))
            query(host, qtype=28)
            require(not self.upstream_paths(host, 28), f"AAAA query reached an upstream for {host}")
        return hashes, hits, upstream_paths


def check_case(root, mosdns, upstreams, enabled):
    backend = LiveBackend(root, mosdns, upstreams)
    table()
    try:
        with patch.object(updater, "download", Release(1).download):
            require(updater.run(root, backend.apply, today="2000-01-01") == 0, "bootstrap failed")
        before, old_hits, old_paths = backend.observe("before")
        require(old_hits == {s: [True, False] for s in updater.CATEGORIES}, f"invalid baseline {old_hits}")
        baseline_paths = [["yandex"], ["amnezia"]]
        require(old_paths == baseline_paths, f"wrong baseline DNS upstreams: {old_paths}")
        old_rotation = root / "dns-rotation.json"
        rotation = json.loads(old_rotation.read_text())
        rotation["day"] = "2000-01-01"
        old_rotation.write_text(json.dumps(rotation))
        backend.hooks.clear()
        release = Release(2)
        for source in updater.CATEGORIES:
            if source not in enabled:
                release.set_data(source, b"")
        with patch.object(updater, "download", release.download):
            code = updater.run(root, backend.apply)
        require(code == int(len(enabled) < 2), f"unexpected exit status {code}")
        after, new_hits, new_paths = backend.observe("after")
        for source in updater.CATEGORIES:
            expected = source in enabled
            require(all((before[source][k] != result) == expected for k, result in after[source].items()),
                    f"wrong on-disk or live nft hash change: {source}")
            require(new_hits[source] == [not expected, expected], f"wrong kernel matches for {source}: {new_hits}")
        geosite_updated = "geosite" in enabled
        expected_paths = baseline_paths[::-1] if geosite_updated else baseline_paths
        require(new_paths == expected_paths, f"wrong active DNS upstreams: {new_paths}")
        expected_hooks = [s for s in updater.CATEGORIES if s in enabled]
        if geosite_updated:
            expected_hooks.append("rotate")
        require(backend.hooks == expected_hooks, f"unexpected hooks {backend.hooks}")
        warm_slots = dns_slots(HOSTS["before.site12.example"])
        require(len(warm_slots) == (1 if geosite_updated else 2), f"wrong warm DNS sets: {warm_slots}")
        print(json.dumps(dict(available=sorted(enabled), before=before, after=after, baseline_hits=old_hits,
                              active_hits=new_hits, baseline_upstreams=old_paths, active_upstreams=new_paths,
                              hooks=backend.hooks, warm_dns_retained=True, result="PASS")))
    finally:
        backend.stop()
        command("nft", "delete", "table", "inet", TABLE)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mosdns", type=Path, default=Path("/usr/local/lib/awg-geo/mosdns"))
    mosdns = parser.parse_args().mosdns.resolve(strict=True)
    require(os.stat("/proc/self/ns/net").st_ino != os.stat("/proc/1/ns/net").st_ino,
            "run with unshare --net outside the network namespace of PID 1")
    fallbacks = {"tunl0": "ipip", "gre0": "gre", "gretap0": "gretap", "erspan0": "erspan",
                 "sit0": "sit", "ip6tnl0": "ip6tnl", "ip6gre0": "ip6gre",
                 "ip6gretap0": "ip6gretap", "ip6erspan0": "ip6erspan"}
    links = json.loads(command("ip", "-j", "-d", "link", "show"))
    for link in links:
        if link["ifname"] == "lo":
            continue
        kind = link.get("linkinfo", {}).get("info_kind", "")
        require(fallbacks.get(link["ifname"]) == kind and "UP" not in link["flags"],
                f"unexpected interface in test namespace: {link['ifname']} type={kind} flags={link['flags']}")
    for family in ("-4", "-6"):
        routes = json.loads(command("ip", "-j", family, "route", "show", "table", "main"))
        require(not routes, f"test namespace already has {family} routes: {routes}")
    command("ip", "link", "set", "lo", "up")
    for prefix in ("198.51.100.0/24", "192.0.2.0/24"):
        command("ip", "route", "add", "local", prefix, "dev", "lo")
    for enabled in (set(updater.CATEGORIES), {"geoip"}, {"geosite"}, set()):
        with tempfile.TemporaryDirectory(prefix="awg-geo-accept-") as work, stub_server() as amnezia, stub_server() as yandex:
            check_case(Path(work), mosdns, {"amnezia": amnezia, "yandex": yandex}, enabled)


if __name__ == "__main__":
    main()
