#!/usr/bin/env python3
"""Подставить проверенные параметры одного входного узла в конфигурацию."""
import argparse
import ipaddress
import json
from pathlib import Path
import re

TEMPLATES = Path(__file__).resolve().with_name("templates")
ADDRESSES = ("INGRESS_PUBLIC", "EXIT_PUBLIC", "BRIDGE_GW", "DNS_IP")
INTERFACES = ("WAN_IF", "AWG_IF", "BRIDGE_IF")
RESERVED = (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
    "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15",
    "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
)
TOKEN = re.compile(r"@([A-Z][A-Z0-9_]*)@")


def settings(path):
    data = json.loads(path.read_text(encoding="utf-8"))
    required = {*ADDRESSES, *INTERFACES, "DOCKER_NET", "CLIENT_NET", "BYPASS_IPV4"}
    if not isinstance(data, dict) or set(data) != required:
        raise ValueError("Проверьте имена параметров по site.example.json")
    for key in required - {"BYPASS_IPV4"}:
        if not isinstance(data[key], str):
            raise ValueError(f"{key}: требуется строка")
    for key in ADDRESSES:
        data[key] = str(ipaddress.IPv4Address(data[key]))
    if len({data[key] for key in ADDRESSES}) != len(ADDRESSES):
        raise ValueError("Адреса двух серверов, шлюза и DNS должны различаться")
    for key in INTERFACES:
        if not re.fullmatch(r"[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,14}", data[key]):
            raise ValueError(f"{key}: недопустимое имя интерфейса")
    if data["BRIDGE_IF"] == data["WAN_IF"]:
        raise ValueError("BRIDGE_IF и WAN_IF должны различаться")
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}", data["DOCKER_NET"]):
        raise ValueError("DOCKER_NET: недопустимое имя сети Docker")
    clients = ipaddress.IPv4Network(data["CLIENT_NET"])
    data["CLIENT_NET"] = str(clients)
    overlays = [ipaddress.IPv4Network(f"100.65.{n}.0/30") for n in (1, 2)]
    if any(ipaddress.IPv4Address(data[k]) in clients for k in ADDRESSES) or any(
        clients.overlaps(net) for net in overlays
    ):
        raise ValueError("CLIENT_NET пересекается с инфраструктурой")
    bypass = data.pop("BYPASS_IPV4")
    if not isinstance(bypass, list) or not all(isinstance(net, str) for net in bypass):
        raise ValueError("BYPASS_IPV4: нужен список IPv4-префиксов")
    exclusions = [ipaddress.IPv4Network(n) for n in (*RESERVED, *bypass)]
    exclusions.extend(ipaddress.IPv4Network(data[k]) for k in ADDRESSES)
    exclusions.append(clients)
    data["RESERVED_NETS"] = ", ".join(map(str, ipaddress.collapse_addresses(exclusions)))
    return data


def render(config, output):
    data = settings(config)
    output.mkdir(parents=True, exist_ok=True)
    for source in sorted(TEMPLATES.glob("*.in")):
        target = output / source.stem
        rendered = TOKEN.sub(lambda m: data[m[1]], source.read_text(encoding="utf-8"))
        target.write_bytes(rendered.encode("utf-8"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    try:
        render(args.config, args.output)
    except (ValueError, KeyError, OSError) as error:
        parser.exit(1, f"{error}\n")
