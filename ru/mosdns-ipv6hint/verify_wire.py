#!/usr/bin/env python3
"""Check a mosdns binary with a synthetic DNS upstream on loopback."""

import argparse
import ipaddress
import os
from pathlib import Path
import socket
import socketserver
import struct
import subprocess
import tempfile
import threading
import time
from typing import NamedTuple


LOOPBACK = "127.0.0.1"
A, NS, MX, AAAA, SVCB, HTTPS, ANY = 1, 2, 15, 28, 64, 65, 255
TYPES = {A: "A", NS: "NS", MX: "MX", AAAA: "AAAA", SVCB: "SVCB", HTTPS: "HTTPS", ANY: "ANY"}
SECTIONS = ("answer", "authority", "additional")
ADDRESS = ipaddress.IPv4Address("192.0.2.40").packed
GLUE = ipaddress.IPv4Address("192.0.2.41").packed
IPV6 = ipaddress.IPv6Address("2001:db8::40").packed


class Record(NamedTuple):
    owner: str
    type: int
    data: bytes
    ttl: int = 60
    dns_class: int = 1


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def wire_name(name):
    labels = [label.encode("ascii") for label in name.split(".")]
    return b"".join(bytes([len(label)]) + label for label in labels) + b"\0"


def read_name(message, offset):
    labels = []
    end = None
    visited = set()
    while True:
        require(offset < len(message), "truncated DNS name")
        size = message[offset]
        if size & 0xC0 == 0xC0:
            require(offset not in visited, "DNS name compression loop")
            visited.add(offset)
            if end is None:
                end = offset + 2
            (pointer,) = struct.unpack_from("!H", message, offset)
            offset = pointer & 0x3FFF
            continue
        offset += 1
        if not size:
            return b".".join(labels).decode("ascii").lower(), end or offset
        require(size <= 63 and offset + size <= len(message), "invalid DNS label")
        labels.append(message[offset:offset + size])
        offset += size


def service_record(ipv6hint):
    parameters = [
        (1, b"\x02h2\x02h3"),
        (3, struct.pack("!H", 8443)),
        (4, ipaddress.IPv4Address("192.0.2.20").packed),
    ]
    if ipv6hint:
        parameters.append((6, ipaddress.IPv6Address("2001:db8::20").packed))
    fields = b"".join(struct.pack("!HH", key, len(value)) + value for key, value in parameters)
    return struct.pack("!H", 3) + wire_name("service.example") + fields


def mx_record():
    return Record("mail.example", MX, struct.pack("!H", 10) + wire_name("mx.example"))


def ns_record():
    return Record("example", NS, wire_name("ns.example"))


def fixture_records(name, qtype):
    if (name, qtype) == ("plain.example", A):
        return (Record(name, A, ADDRESS),), (), ()
    if (name, qtype) == ("plain.example", AAAA):
        return (Record(name, AAAA, IPV6),), (), ()
    if (name, qtype) == ("mixed.example", ANY):
        return (Record(name, A, ADDRESS), Record(name, AAAA, IPV6)), (), ()
    if (name, qtype) == ("mail.example", MX):
        answer = (mx_record(),)
        # Insert AAAA in authority as well to exercise every section.
        authority = (ns_record(), Record("ns.example", AAAA, IPV6))
        additional = (Record("mx.example", A, GLUE), Record("mx.example", AAAA, IPV6))
        return answer, authority, additional
    require(qtype in (SVCB, HTTPS) and name in ("with-hint.example", "without-hint.example"),
            f"unexpected upstream question {name} type {qtype}")
    return (Record(name, qtype, service_record(ipv6hint=name == "with-hint.example")),), (), ()


def pack_record(record):
    return (wire_name(record.owner)
            + struct.pack("!HHIH", record.type, record.dns_class, record.ttl, len(record.data))
            + record.data)


def frame(message):
    return struct.pack("!H", len(message)) + message


class UpstreamHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(2)
        while True:
            prefix = self.rfile.read(2)
            if not prefix:
                return
            (size,) = struct.unpack("!H", prefix)
            query = self.rfile.read(size)
            name, end = read_name(query, 12)
            qtype, qclass = struct.unpack_from("!HH", query, end)
            require(qclass == 1, f"unexpected upstream DNS class {qclass}")
            if qtype == AAAA:
                self.server.aaaa_forwarded.set()
            sections = fixture_records(name, qtype)
            header = query[:2] + struct.pack("!5H", 0x8180, 1, *map(len, sections))
            records = b"".join(pack_record(record) for section in sections for record in section)
            self.wfile.write(frame(header + query[12:end + 4] + records))


class UpstreamServer(socketserver.ThreadingTCPServer):
    daemon_threads = True

    def __init__(self):
        self.aaaa_forwarded = threading.Event()
        super().__init__((LOOPBACK, 0), UpstreamHandler)


def read_record(message, offset):
    owner, offset = read_name(message, offset)
    rrtype, rrclass, ttl, size = struct.unpack_from("!HHIH", message, offset)
    data_start = offset + 10
    end = data_start + size
    require(end <= len(message), "truncated DNS record")
    data = message[data_start:end]
    if rrtype in (NS, MX):
        name_start = data_start + (2 if rrtype == MX else 0)
        target, name_end = read_name(message, name_start)
        require(name_end == end, "invalid NS or MX record length")
        data = message[data_start:name_start] + wire_name(target)
    return Record(owner, rrtype, data, ttl, rrclass), end


def query(port, protocol, name, qtype, timeout):
    qid = os.urandom(2)
    question = wire_name(name) + struct.pack("!HH", qtype, 1)
    message = qid + struct.pack("!5H", 0x0100, 1, 0, 0, 0) + question
    if protocol == "TCP":
        with socket.create_connection((LOOPBACK, port), timeout) as client:
            client.sendall(frame(message))
            with client.makefile("rb") as stream:
                (size,) = struct.unpack("!H", stream.read(2))
                reply = stream.read(size)
            require(len(reply) == size, "truncated TCP DNS response")
    else:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(timeout)
            client.connect((LOOPBACK, port))
            client.send(message)
            reply = client.recv(4096)

    prefix = f"{protocol} {TYPES[qtype]} {name}"
    require(reply[:2] == qid and len(reply) >= 12, f"{prefix}: invalid transaction")
    flags, questions, answers, authority, additional = struct.unpack_from("!5H", reply, 2)
    require(flags & 0x820F == 0x8000, f"{prefix}: invalid flags {flags:#06x}")
    require(questions == 1, f"{prefix}: unexpected DNS question count {questions}")
    require(reply[12:12 + len(question)] == question, f"{prefix}: DNS question changed")
    sections = []
    offset = 12 + len(question)
    for count in (answers, authority, additional):
        records = []
        for _ in range(count):
            record, offset = read_record(reply, offset)
            records.append(record)
        sections.append(tuple(records))
    require(offset == len(reply), f"{prefix}: unexpected trailing bytes")
    return tuple(sections)


def listener_port():
    for _ in range(8):
        with socket.socket() as tcp, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            tcp.bind((LOOPBACK, 0))
            port = tcp.getsockname()[1]
            try:
                udp.bind((LOOPBACK, port))
                return port
            except OSError:
                continue
    raise RuntimeError("could not find a loopback port available for UDP and TCP")


def write_config(path, listen_port, upstream_port):
    path.write_text(f"""\
log:
  level: warn
plugins:
  - tag: upstream
    type: forward
    args:
      upstreams:
        - addr: tcp://{LOOPBACK}:{upstream_port}
          enable_pipeline: false
  - tag: resolve
    type: sequence
    args:
      - matches:
          - qtype 28
        exec: reject 0
      - exec: $upstream
      - exec: strip_ipv6hint
  - type: udp_server
    args:
      entry: resolve
      listen: {LOOPBACK}:{listen_port}
  - type: tcp_server
    args:
      entry: resolve
      listen: {LOOPBACK}:{listen_port}
""", encoding="ascii")


def check_records(port, protocol, name, qtype, expected, timeout=2):
    actual = query(port, protocol, name, qtype, timeout)
    for label, records, wanted in zip(SECTIONS, actual, expected):
        require(records == wanted, f"{protocol} {TYPES[qtype]} {name} {label}: "
                f"expected {wanted}, received {records}")


def wait_ready(port, protocol, process):
    deadline = time.monotonic() + 5
    while True:
        require(process.poll() is None, f"mosdns exited with status {process.returncode}")
        try:
            check_records(port, protocol, "plain.example", A, ((Record("plain.example", A, ADDRESS),), (), ()),
                          timeout=0.25)
            return
        except OSError as exc:
            if time.monotonic() >= deadline:
                raise RuntimeError(f"mosdns did not answer the {protocol} readiness query") from exc
            time.sleep(0.05)


def verify(port, process, upstream):
    for protocol in ("UDP", "TCP"):
        wait_ready(port, protocol, process)
        print(f"PASS {protocol} A: preserved address")
        for qtype in (SVCB, HTTPS):
            for name in ("with-hint.example", "without-hint.example"):
                expected = ((Record(name, qtype, service_record(ipv6hint=False)),), (), ())
                check_records(port, protocol, name, qtype, expected)
            print(f"PASS {protocol} {TYPES[qtype]}: stripped ipv6hint, preserved all other fields")
        check_records(port, protocol, "mixed.example", ANY, ((Record("mixed.example", A, ADDRESS),), (), ()))
        print(f"PASS {protocol} ANY: stripped AAAA, preserved A")
        check_records(port, protocol, "mail.example", MX, ((mx_record(),), (ns_record(),),
                                                           (Record("mx.example", A, GLUE),)))
        print(f"PASS {protocol} MX: stripped AAAA from authority and additional, preserved MX, NS and A glue")
        check_records(port, protocol, "plain.example", AAAA, ((), (), ()))
        require(not upstream.aaaa_forwarded.is_set(), f"{protocol} AAAA query was forwarded upstream")
        print(f"PASS {protocol} AAAA: returned NOERROR with empty answer locally")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mosdns", type=Path, required=True, help="path to the candidate mosdns binary")
    mosdns = parser.parse_args().mosdns.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="mosdns-ipv6hint-") as work, UpstreamServer() as upstream:
        root = Path(work)
        port = listener_port()
        config = root / "mosdns.yaml"
        write_config(config, port, upstream.server_address[1])
        worker = threading.Thread(target=upstream.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        worker.start()
        try:
            with (root / "mosdns.log").open("w+", encoding="utf-8", errors="replace") as log:
                process = subprocess.Popen([mosdns, "start", "-c", config, "-d", root],
                                           stdout=log, stderr=subprocess.STDOUT)
                try:
                    verify(port, process, upstream)
                except Exception as exc:
                    log.seek(0)
                    parser.exit(1, f"FAIL {exc}\n{log.read()}")
                finally:
                    if process.poll() is None:
                        process.terminate()
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
        finally:
            upstream.shutdown()
            worker.join()


if __name__ == "__main__":
    main()
