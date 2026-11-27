"""Offline tests for refreshing an existing peer after an outage."""
import contextlib
import io
import json
import socket
import subprocess
import tempfile
import unittest
from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
from pathlib import Path
from unittest.mock import patch


loader = SourceFileLoader("wg_refresh", str(Path(__file__).with_name("refresh-wgcf-endpoint")))
worker = module_from_spec(spec_from_loader(loader.name, loader))
loader.exec_module(worker)


class RefreshTests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        folder = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.config = folder / "active.conf"
        self.source = folder / "source.conf"
        self.profile(self.config, "warp.example:2408")
        self.current = "192.0.2.2:2408"
        self.addresses = ["192.0.2.2"]
        self.live_rows = None
        self.links = [{"ifname": "wg0", "flags": ["UP"]}]
        self.writes = []
        self.probes = []
        self.traces = {}
        self.stack.enter_context(patch.object(worker.subprocess, "check_output", side_effect=self.show_links))
        self.stack.enter_context(patch.object(worker.subprocess, "run", side_effect=self.wg))
        self.dns = self.stack.enter_context(patch.object(worker.socket, "getaddrinfo", side_effect=self.resolve))
        self.output = self.stack.enter_context(contextlib.redirect_stdout(io.StringIO()))

    @staticmethod
    def profile(path, endpoint, key="test-peer"):
        path.write_text(f"[Interface]\nPrivateKey=test-secret\n[Peer]\nPublicKey={key}\nEndpoint={endpoint}\n")

    def show_links(self, args, **kwargs):
        self.assertEqual(args, ["ip", "-j", "link", "show"])
        return json.dumps(self.links)

    def wg(self, args, **kwargs):
        if args[0] == "curl":
            self.assertEqual(args[args.index("--interface") + 1], "if!wg0")
            self.assertLessEqual(float(args[args.index("--max-time") + 1]), 2)
            self.probes.append(args[-1])
            rc, body = self.traces.get(args[-1], (28, b""))
            return subprocess.CompletedProcess(args, rc, body)
        if args == ["wg", "show", "wg0", "endpoints"]:
            return subprocess.CompletedProcess(args, 0, self.live_rows if self.live_rows is not None
                                               else f"test-peer\t{self.current}\n")
        self.assertEqual(args[:6], ["wg", "set", "wg0", "peer", "test-peer", "endpoint"])
        self.writes.append(args[6])
        self.current = args[6]
        return subprocess.CompletedProcess(args, 0)

    def resolve(self, host, port, family, kind):
        self.assertEqual((family, kind), (socket.AF_INET, socket.SOCK_DGRAM))
        return [(family, kind, 17, "", (address, port)) for address in self.addresses]

    def refresh(self):
        before = self.config.read_bytes()
        worker.refresh("wg0", self.config, self.source)
        self.assertEqual(self.config.read_bytes(), before)
        self.assertNotIn("test-peer", self.output.getvalue())
        self.assertNotIn("test-secret", self.output.getvalue())

    def test_dns_is_fresh_and_unchanged_endpoint_is_left_alone(self):
        self.refresh()
        self.assertEqual(self.probes, [])
        self.addresses = ["192.0.2.3"]
        self.refresh()
        self.assertEqual(self.dns.call_count, 2)
        self.assertEqual(self.writes, ["192.0.2.3:2408"])

    def test_round_robin_sorted_unique_ipv4(self):
        self.addresses = ["192.0.2.10", "192.0.2.2", "192.0.2.2", "192.0.2.5"]
        for _ in range(3):
            self.refresh()
        self.assertEqual(self.writes, ["192.0.2.5:2408", "192.0.2.10:2408", "192.0.2.2:2408"])

    def test_original_hostname_with_active_literal_and_overridden_port(self):
        self.profile(self.config, "192.0.2.2:443")
        self.profile(self.source, "original.example:2408")
        self.refresh()
        self.dns.assert_called_once_with("original.example", 443, socket.AF_INET, socket.SOCK_DGRAM)
        self.assertEqual(self.writes, ["192.0.2.2:443"])

    def test_recovered_warp_via_secondary_trace_skips_rotation(self):
        self.addresses = ["192.0.2.2", "192.0.2.9"]
        self.traces = {"https://1.1.1.1/cdn-cgi/trace": (0, b"warp=off\n"),
                       "https://1.0.0.1/cdn-cgi/trace": (0, b"ip=192.0.2.1\nwarp=plus\n")}
        self.refresh()
        self.assertEqual(len(self.probes), 2)
        self.assertEqual(self.writes, [])

    def test_dns_source_must_be_named_and_for_same_peer(self):
        self.profile(self.config, "192.0.2.2:443")
        self.refresh()  # No source profile.
        self.profile(self.source, "unrelated.example:443", key="other-peer")
        self.refresh()
        self.profile(self.source, "192.0.2.10:2408")
        self.refresh()
        self.dns.assert_not_called()
        self.assertEqual(self.writes, [])

    def test_skip_missing_admin_down_multiple_or_unmatched_live_peer(self):
        self.links = []
        self.refresh()
        self.links = [{"ifname": "wg0", "flags": []}]
        self.refresh()
        self.links[0]["flags"] = ["UP"]
        self.live_rows = "test-peer\t192.0.2.2:2408\nother-peer\t(none)\n"
        self.refresh()
        self.live_rows = "other-peer\t(none)\n"
        self.refresh()
        self.dns.assert_not_called()
        self.assertEqual(self.writes, [])

    def test_dns_failure_and_live_peer_change_do_not_write(self):
        self.dns.side_effect = socket.gaierror("temporary DNS failure")
        with self.assertRaises(socket.gaierror):
            self.refresh()
        self.dns.side_effect = self.resolve
        self.addresses = ["192.0.2.9"]
        with patch.object(worker, "live_peer", side_effect=[("test-peer", self.current), None]):
            self.refresh()
        self.assertEqual(self.writes, [])


if __name__ == "__main__":
    unittest.main()
