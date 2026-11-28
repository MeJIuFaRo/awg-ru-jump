#!/usr/bin/env python3
"""Isolated Linux integration test for recover-wgcf-profile.

Run with python3 -B exit/test_recover_wgcf.py. This requires WireGuard,
nftables, iproute2, and util-linux `mount`/`unshare`/`nsenter`. If unprivileged
network namespaces are disabled, run the same command with sudo.
"""
from contextlib import ExitStack
import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time


SELF = Path(__file__).resolve()
WORKER = SELF.with_name("recover-wgcf-profile")
INTERFACE = "exit-warp"
OLD_ADDRESS = "198.18.8.2"
NEW_ADDRESS = "198.18.9.2"
DESTINATION = "203.0.113.80"
OLD_ENDPOINT = "192.0.2.21:2408"
NEW_ENDPOINT = "198.51.100.22:8443"
ECHO_PORT = 55331
TEST_TOKEN = "integration-only-registration-token"


def command(*args, data=None):
    executable = Path(args[0]).name
    try:
        result = subprocess.run(args, input=data, text=True, capture_output=True, timeout=15)
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"{executable} timed out") from None
    if result.returncode:
        raise RuntimeError(f"{executable} failed with status {result.returncode}")
    return result.stdout


def kernel_links():
    return json.loads(command("ip", "-j", "link", "show"))


def addresses():
    links = json.loads(command("ip", "-4", "-j", "addr", "show", "dev", INTERFACE))
    return {item["local"] for link in links for item in link["addr_info"]}


def ifindex():
    return next(link["ifindex"] for link in kernel_links() if link["ifname"] == INTERFACE)


def udp_probe():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, INTERFACE.encode() + b"\0")
        sock.settimeout(1.5)
        sock.connect((DESTINATION, ECHO_PORT))
        local = sock.getsockname()[0]
        sock.send(b"transit-proof")
        return sock.recv(64).decode(), local


def wait_for_transport(label, address):
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        try:
            if udp_probe() == (label, address):
                return
        except OSError:
            continue
        break
    raise RuntimeError(f"WireGuard transport did not reach the {label} test peer")


def echo(label, ready):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((DESTINATION, ECHO_PORT))
        ready.touch()
        while True:
            data, source = sock.recvfrom(64)
            if data == b"transit-proof":
                sock.sendto(label.encode(), source)


def fake_api(fixture, args):
    if args[0] != "generate" or "--keepalive" not in args:
        return 2
    account = Path(args[args.index("--config") + 1])
    target = Path(args[args.index("--profile") + 1])
    if not target.is_absolute() or TEST_TOKEN not in account.read_text():
        return 2
    with (fixture / "api.calls").open("a") as log:
        log.write("generate\n")
    scenario = (fixture / "scenario").read_text()
    if scenario == "api-failure":
        print(TEST_TOKEN)
        print((fixture / "client.key").read_text().strip(), file=sys.stderr)
        return 23
    candidate = (fixture / "candidate.conf").read_text()
    if scenario == "bad-profile":
        candidate = candidate.replace(NEW_ADDRESS, "invalid-ipv4-address")
    target.write_text(candidate)
    return 0


def fake_curl(fixture, args):
    if args[args.index("--interface") + 1] != f"if!{INTERFACE}":
        return 2
    if args[-1] not in ("https://1.1.1.1/cdn-cgi/trace", "https://1.0.0.1/cdn-cgi/trace"):
        return 2
    try:
        label, local = udp_probe()
    except OSError:
        return 28
    with (fixture / "proof.calls").open("a") as log:
        log.write(f"{label} {local}\n")
    scenario = (fixture / "scenario").read_text()
    if label == "new" and scenario == "interrupted":
        (fixture / "candidate.ready").touch()
        signal.pause()
    if label == "new" or (label == "old" and scenario == "healthy"):
        # Even a real reply cannot prove the candidate when the source is wrong.
        reported = OLD_ADDRESS if scenario == "unproven" else local
        print(f"warp=on\n\n{reported}")
    else:
        print(f"warp=off\n\n{local}")
    return 0


def stop_process(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def wait_for_file(path, process):
    deadline = time.monotonic() + 5
    while not path.exists():
        if process.poll() is not None or time.monotonic() >= deadline:
            raise RuntimeError("A synthetic endpoint did not start")
        time.sleep(0.05)


def private_key(path):
    key = command("wg", "genkey")
    path.write_text(key)
    return command("wg", "pubkey", data=key).strip()


def profile(key, peer, address, endpoint, *, source=False):
    interface_options = "" if source else "MTU = 1280\nTable = off\n"
    if source:
        address += ", 2001:db8::2/128"
    allowed = "0.0.0.0/0, ::/0" if source else "0.0.0.0/0"
    return (f"[Interface]\nPrivateKey = {key}\nAddress = {address}\n{interface_options}"
            f"\n[Peer]\nPublicKey = {peer}\nEndpoint = {endpoint}\n"
            f"AllowedIPs = {allowed}\nPersistentKeepalive = 25\n")


def configure_remote(stack, fixture, name, client_public, client_address, local_underlay, endpoint):
    host, _, port = endpoint.partition(":")
    remote_key = fixture / f"{name}.key"
    public = private_key(remote_key)
    ready = fixture / f"{name}.namespace"
    proc = subprocess.Popen(["unshare", "-n", "--", sys.executable, str(SELF), "--hold", str(ready)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    stack.callback(stop_process, proc)
    wait_for_file(ready, proc)
    ns = ("nsenter", "-t", str(proc.pid), "-n", "--")
    device = f"qa-{name}"
    command("ip", "link", "add", device, "type", "veth", "peer", "name", "uplink", "netns", str(proc.pid))
    command("ip", "addr", "add", local_underlay + "/24", "dev", device)
    command("ip", "link", "set", device, "up")
    command(*ns, "ip", "addr", "add", host + "/24", "dev", "uplink")
    command(*ns, "ip", "link", "set", "uplink", "up")
    command(*ns, "ip", "link", "set", "lo", "up")
    host_mac = json.loads(command("ip", "-j", "link", "show", "dev", device))[0]["address"]
    peer_mac = json.loads(command(*ns, "ip", "-j", "link", "show", "dev", "uplink"))[0]["address"]
    command("ip", "neigh", "replace", host, "lladdr", peer_mac, "nud", "permanent", "dev", device)
    command(*ns, "ip", "neigh", "replace", local_underlay, "lladdr", host_mac, "nud", "permanent", "dev", "uplink")
    command(*ns, "ip", "link", "add", "peer", "type", "wireguard")
    command(*ns, "ip", "addr", "add", DESTINATION + "/32", "dev", "peer")
    command(*ns, "wg", "set", "peer", "private-key", str(remote_key), "listen-port", port,
            "peer", client_public, "allowed-ips", client_address + "/32")
    command(*ns, "ip", "link", "set", "peer", "up")
    command(*ns, "ip", "route", "add", client_address + "/32", "dev", "peer")
    echo_ready = fixture / f"{name}.echo"
    server = subprocess.Popen([*ns, sys.executable, str(SELF), "--echo", name, str(echo_ready)],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    stack.callback(stop_process, server)
    wait_for_file(echo_ready, server)
    return public


def fixture_wrappers(directory):
    tools = directory / "tools"
    tools.mkdir()
    for binary, mode in [("curl", "--fake-curl"), ("wgcf", "--fake-api")]:
        target = tools / binary
        launcher = shlex.join([sys.executable, str(SELF), mode, str(directory)])
        target.write_text(f'#!/bin/sh\nexec {launcher} "$@"\n')
        target.chmod(0o700)
    return tools


def assert_profile_state(active, expected_address, expected_endpoint, expected_peer):
    assert addresses() == {expected_address}, "Unexpected addresses on live WireGuard interface"
    endpoints = command("wg", "show", INTERFACE, "endpoints").split()
    assert endpoints == [expected_peer, expected_endpoint], "Unexpected active peer or endpoint"
    fields = active.read_text().splitlines()
    assert f"Address = {expected_address}/32" in fields, "Persisted address did not match live state"
    assert f"PublicKey = {expected_peer}" in fields, "Persisted peer did not match live state"


def worker_args(tools, active, source, account, state):
    return [sys.executable, str(WORKER), INTERFACE, str(active), str(source), str(tools / "wgcf"),
            str(account), str(state)]


def worker_env(tools):
    return dict(os.environ, PATH=str(tools) + os.pathsep + os.environ["PATH"])


def assert_no_secrets(output, secrets):
    assert not any(secret in output for secret in secrets), "Worker exposed a synthetic secret"


def prepare_case(fixture, scenario):
    (fixture / "scenario").write_text(scenario)
    (fixture / "api.calls").write_text("")
    (fixture / "proof.calls").write_text("")
    state = fixture / scenario
    state.mkdir()
    return state


def run_case(fixture, tools, active, source, account, scenario, secrets):
    state = prepare_case(fixture, scenario)
    result = subprocess.run(worker_args(tools, active, source, account, state),
                            text=True, capture_output=True, env=worker_env(tools), timeout=75)
    assert_no_secrets(result.stdout + result.stderr, secrets)
    expected = scenario in ("healthy", "success")
    assert (result.returncode == 0) == expected, f"Unexpected recovery status for {scenario}"
    assert not (state / "pending").exists(), "Worker left an unfinished recovery"
    return (fixture / "api.calls").read_text().splitlines(), (fixture / "proof.calls").read_text().splitlines()


def interrupt_candidate(fixture, tools, active, source, account, secrets):
    state = prepare_case(fixture, "interrupted")
    args = worker_args(tools, active, source, account, state)
    env = worker_env(tools)
    with subprocess.Popen(args, env=env, start_new_session=True, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
        try:
            wait_for_file(fixture / "candidate.ready", process)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
            stdout, stderr = process.communicate(timeout=5)
    assert_no_secrets(stdout + stderr, secrets)
    assert (state / "pending").is_dir(), "The process terminated without a rollback journal"
    assert addresses() == {NEW_ADDRESS}, "The interrupted candidate was not actually applied"
    calls = (fixture / "api.calls").read_text()
    result = subprocess.run(args, env=env, text=True, capture_output=True, timeout=20)
    assert_no_secrets(result.stdout + result.stderr, secrets)
    assert result.returncode == 0 and not (state / "pending").exists(), "Interrupted recovery was not completed"
    assert (fixture / "api.calls").read_text() == calls, "Journal recovery called the registration API"


def integration(parent_mount, parent_net):
    assert os.readlink("/proc/self/ns/net") != parent_net, "A fresh network namespace is required"
    # Loaded tunnel modules create these inactive fallback links even in a new namespace.
    fallback = {"tunl0": "ipip", "gre0": "gre", "gretap0": "gretap",
                "erspan0": "erspan", "sit0": "sit", "ip6tnl0": "ip6tnl",
                "ip6gre0": "ip6gre"}
    for link in json.loads(command("ip", "-j", "-d", "link", "show")):
        if link["ifname"] != "lo":
            assert link["ifname"] in fallback and "UP" not in link["flags"] and (
                fallback[link["ifname"]] == link.get("linkinfo", {}).get("info_kind")
            ), "Unexpected interface in test namespace"
    assert not command("ip", "-4", "route", "show", "table", "main").strip()
    assert os.readlink("/proc/self/ns/mnt") != parent_mount, "A fresh mount namespace is required"
    command("mount", "-t", "tmpfs", "-o", "mode=1777", "tmpfs", "/run/lock")
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="recover-wgcf-test-", dir="/tmp") as temp, ExitStack() as stack:
        fixture = Path(temp)
        client_private = fixture / "client.key"
        client_public = private_key(client_private)
        old_peer = configure_remote(stack, fixture, "old", client_public, OLD_ADDRESS, "192.0.2.10", OLD_ENDPOINT)
        new_peer = configure_remote(stack, fixture, "new", client_public, NEW_ADDRESS, "198.51.100.10", NEW_ENDPOINT)
        command("ip", "link", "set", "lo", "up")
        command("ip", "link", "add", INTERFACE, "type", "wireguard")
        command("ip", "addr", "add", OLD_ADDRESS + "/32", "dev", INTERFACE)
        command("wg", "set", INTERFACE, "private-key", str(client_private), "listen-port", "45219",
                "peer", old_peer, "endpoint", OLD_ENDPOINT, "allowed-ips", "0.0.0.0/0", "persistent-keepalive", "25")
        command("ip", "link", "set", INTERFACE, "mtu", "1280", "up")
        # The isolated namespace has no WAN default for IPv4 reverse-path checks.
        command("ip", "-4", "route", "add", DESTINATION + "/32", "dev", INTERFACE)
        command("ip", "-4", "route", "add", "table", "51873", "default", "dev", INTERFACE)
        command("ip", "-4", "route", "add", "table", "51873", "unreachable", "default", "metric", "32760")
        command("ip", "-4", "rule", "add", "pref", "18573", "oif", INTERFACE, "lookup", "51873")
        command("nft", "add", "table", "ip", "exit_transit")
        command("nft", 'add set ip exit_transit official_ingress { type ifname; elements = {"rn-gre", "rn-ipip"}; }')
        command("nft", "add set ip exit_transit warp_ingress { type ifname; }")
        standby = command("nft", "-j", "list", "table", "ip", "exit_transit")
        old_index = ifindex()
        key = client_private.read_text().strip()
        active = fixture / "exit-warp.conf"
        active.write_text(profile(key, old_peer, OLD_ADDRESS + "/32", OLD_ENDPOINT))
        source = fixture / "wgcf-profile.conf"
        source.write_text(profile(key, old_peer, OLD_ADDRESS + "/32", OLD_ENDPOINT, source=True))
        account = fixture / "wgcf-account.toml"
        account.write_text(f'device_id = "integration-only-device"\naccess_token = "{TEST_TOKEN}"\nprivate_key = "{key}"\n')
        candidate = profile(key, new_peer, NEW_ADDRESS + "/32", NEW_ENDPOINT, source=True)
        (fixture / "candidate.conf").write_text(candidate)
        tools = fixture_wrappers(fixture)
        secrets = [TEST_TOKEN, key, old_peer, new_peer, client_public]
        before = (active.read_bytes(), source.read_bytes(), command("wg", "showconf", INTERFACE))
        wait_for_transport("old", OLD_ADDRESS)

        for scenario in ("healthy", "api-failure", "bad-profile", "unproven"):
            calls, proofs = run_case(fixture, tools, active, source, account, scenario, secrets)
            assert bool(calls) == (scenario != "healthy"), "Unexpected call to the registration API"
            expected_candidate_proof = scenario == "unproven"
            assert (f"new {NEW_ADDRESS}" in proofs) == expected_candidate_proof, "Unexpected candidate traffic"
            assert (active.read_bytes(), source.read_bytes(), command("wg", "showconf", INTERFACE)) == before, \
                "Failed recovery changed files or the current WireGuard settings"
            assert_profile_state(active, OLD_ADDRESS, OLD_ENDPOINT, old_peer)
            assert ifindex() == old_index, "Recovery recreated the interface"
            wait_for_transport("old", OLD_ADDRESS)
            assert command("nft", "-j", "list", "table", "ip", "exit_transit") == standby, "Standby routing changed"
            print(f"{scenario}: old WireGuard traffic, profiles and standby selector intact")

        interrupt_candidate(fixture, tools, active, source, account, secrets)
        assert (active.read_bytes(), source.read_bytes(), command("wg", "showconf", INTERFACE)) == before, \
            "Journal recovery did not restore files and live WireGuard settings"
        assert_profile_state(active, OLD_ADDRESS, OLD_ENDPOINT, old_peer)
        assert ifindex() == old_index, "Journal recovery recreated the interface"
        wait_for_transport("old", OLD_ADDRESS)
        assert command("nft", "-j", "list", "table", "ip", "exit_transit") == standby, "Standby routing changed"
        print("interrupted: a fresh worker rolled back an applied candidate using the journal")

        calls, proofs = run_case(fixture, tools, active, source, account, "success", secrets)
        assert calls and f"new {NEW_ADDRESS}" in proofs, "The successful candidate was not proven"
        assert_profile_state(active, NEW_ADDRESS, NEW_ENDPOINT, new_peer)
        assert ifindex() == old_index, "Recovery recreated the interface"
        wait_for_transport("new", NEW_ADDRESS)
        assert command("wg", "show", INTERFACE, "public-key").strip() == client_public, "Client identity changed"
        assert f"Endpoint = {NEW_ENDPOINT}" in active.read_text().splitlines(), "New endpoint was not persisted"
        assert source.read_text() == candidate, "Latest wgcf profile was not persisted"
        assert stat.S_IMODE(active.stat().st_mode) == stat.S_IMODE(source.stat().st_mode) == 0o600, \
            "Profile file permissions changed"
        assert f"Endpoint = {NEW_ENDPOINT}" in command("wg-quick", "strip", str(active)).splitlines(), \
            "wg-quick could not use the persisted profile"
        assert command("nft", "-j", "list", "table", "ip", "exit_transit") == standby, "Standby routing changed"
        print("success: encrypted traffic passes through the new peer, endpoint port and IPv4; both profiles persisted")


def main():
    args = sys.argv[1:]
    if not args:
        for tool in ("unshare", "nsenter", "mount", "ip", "wg", "wg-quick", "nft"):
            if not shutil.which(tool):
                raise RuntimeError(f"Missing Linux tool: {tool}")
        user = [] if os.geteuid() == 0 else ["--user", "--map-root-user"]
        namespaces = ["unshare", *user, "--net", "--mount", "--propagation", "private"]
        parent = os.readlink("/proc/self/ns/mnt")
        return subprocess.run([*namespaces, "--", sys.executable, "-B", str(SELF), "--isolated",
                               parent, os.readlink("/proc/self/ns/net")]).returncode
    if args[0] == "--isolated":
        integration(args[1], args[2])
    elif args[0] == "--hold":
        Path(args[1]).touch()
        signal.pause()
    elif args[0] == "--echo":
        echo(args[1], Path(args[2]))
    elif args[0] == "--fake-api":
        return fake_api(Path(args[1]), args[2:])
    elif args[0] == "--fake-curl":
        return fake_curl(Path(args[1]), args[2:])
    else:
        raise ValueError("Unexpected test argument")
    return 0


if __name__ == "__main__":
    sys.exit(main())
