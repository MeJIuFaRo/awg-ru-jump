"""Offline tests for the IPv4 exit controller, without routing privileges."""
import contextlib
import io
import json
from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

loader = SourceFileLoader("exit_health", str(Path(__file__).with_name("exit-health")))
controller = module_from_spec(spec_from_loader(loader.name, loader))
loader.exec_module(controller)


def result(stdout="", *, rc=0, stderr=""):
    return subprocess.CompletedProcess([], rc, stdout, stderr)


class HealthTests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        state = Path(self.stack.enter_context(tempfile.TemporaryDirectory())) / "health.json"
        self.stack.enter_context(patch.object(controller, "STATE", state))
        self.stack.enter_context(patch.object(controller, "TRIAL_LOCK", state.with_name("trial.lock")))
        self.stack.enter_context(patch.object(controller, "PENDING", state.with_name("pending")))
        self.stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        self.active = {"wgcf": set(), "official": set()}
        self.probes = {"wgcf": (True, {"192.0.2.19"}), "official": (True, {"10.254.247.1"})}
        self.batches = []
        self.deletes = []

    def command(self, args, *, data=None, **kwargs):
        if args == ["nft", "-f", "-"]:
            self.batches.append(data)
            for line in data.splitlines():
                operation, _, _, _, name, *rest = line.split()
                path = next(path for path, policy_set in controller.SETS.items() if policy_set == name)
                if operation == "flush":
                    self.active[path].clear()
                else:
                    elements = " ".join(rest)[1:-1]
                    self.active[path] = set(json.loads(f"[{elements}]"))
            return result()
        self.assertEqual(args[:4], ["conntrack", "-D", "-f", "ipv4"])
        self.assertIn("--src-nat", args)
        self.deletes.append((args[args.index("-p") + 1], args[args.index("--mark") + 1],
                             args[args.index("--reply-dst") + 1]))
        return result(rc=1, stderr="conntrack v1.4.8 (conntrack-tools): 0 flow entries have been deleted.")

    def simulate(self):
        self.stack.enter_context(patch.object(controller, "selectors", return_value=self.active))
        self.stack.enter_context(patch.object(controller, "run", side_effect=self.command))
        return self.stack.enter_context(patch.object(controller, "probe", side_effect=self.probes.get))

    def tick(self, expected):
        controller.health()
        self.assertEqual(controller.effective(self.active), expected)

    def test_outage_priority_recovery_and_draining(self):
        self.simulate()
        self.tick("wgcf")
        self.probes["wgcf"] = False, set()
        self.tick("official")
        self.assertEqual(set(self.deletes), {(p, m + "/0xf0000", "192.0.2.19")
                         for p in ("udp", "icmp") for m in ("0x50000", "0x60000")})
        self.probes["wgcf"] = True, {"192.0.2.19"}
        self.tick("wgcf")
        self.assertEqual(len(self.deletes), 4)
        self.probes["official"] = False, set()
        self.tick("wgcf")   # A formerly selected standby can still have datagrams.
        self.assertEqual(set(self.deletes[4:]), {(p, m + "/0xf0000", "10.254.247.1")
                         for p in ("udp", "icmp") for m in ("0xd0000", "0xe0000")})
        self.tick("wgcf")
        self.assertEqual(len(self.deletes), 8)
        self.probes["wgcf"] = False, set()
        self.tick("wan")
        self.probes["official"] = True, {"10.254.247.1"}
        self.tick("official")
        self.probes["wgcf"] = True, {"192.0.2.19"}
        self.tick("wgcf")
        self.assertEqual(len(self.deletes), 12)
        self.assertIn("flush set ip exit_transit official_ingress", self.batches[-1])
        self.assertIn("add element ip exit_transit warp_ingress", self.batches[-1])

    def test_old_installation_without_gateway(self):
        self.simulate()
        self.probes["official"] = False, set()
        self.tick("wgcf")
        self.probes["wgcf"] = False, set()
        self.tick("wan")
        self.probes["wgcf"] = True, {"192.0.2.19"}
        self.tick("wgcf")

    def test_uncommitted_primary_cannot_preempt_standby(self):
        self.simulate()
        self.tick("wgcf")
        with controller.TRIAL_LOCK.open("a") as writer:
            controller.fcntl.flock(writer, controller.fcntl.LOCK_EX)
            self.tick("official")
        controller.PENDING.mkdir()
        self.tick("official")
        self.assertFalse(self.deletes)
        controller.PENDING.rmdir()
        self.tick("wgcf")

    def test_concurrent_probes_and_error_preserves_selector(self):
        probe = self.simulate()
        gate = threading.Barrier(2, timeout=2)
        def meet(path):
            gate.wait()
            return self.probes[path]
        probe.side_effect = meet
        self.tick("wgcf")
        probe.side_effect = PermissionError("operation not permitted")
        with self.assertRaises(PermissionError):
            controller.health()
        self.assertEqual(controller.effective(self.active), "wgcf")
        self.assertFalse(self.deletes)

    def test_cleanup_failure_retries_after_atomic_selection(self):
        self.simulate()
        self.tick("wgcf")
        self.probes["wgcf"] = False, set()
        def denied(args, **kwargs):
            if args[0] == "conntrack":
                return result(rc=1, stderr="Operation not permitted\nconntrack: 0 flow entries have been deleted.")
            return self.command(args, **kwargs)
        with patch.object(controller, "run", side_effect=denied):
            with self.assertRaisesRegex(RuntimeError, "permitted"):
                controller.health()
        self.tick("official")
        self.assertEqual(len(self.deletes), 4)

    def test_probes_use_two_verified_tls_traces(self):
        for path, dev, source in (("wgcf", "exit-warp", "192.0.2.19"),
                                  ("official", "cfw-host", "10.254.247.1")):
            curl = []
            def command(args, **kwargs):
                if "addr" in args:
                    return result(json.dumps([{"addr_info": [{"family": "inet", "local": source}]}]))
                if "route" in args:
                    return result(json.dumps([{"dev": dev, "gateway": "10.254.247.2"}]))
                self.assertEqual(args[0], "curl")
                curl.append(args)
                return result("warp=off\n" if len(curl) == 1 else "warp=plus\n")
            with patch.object(controller, "run", side_effect=command), patch.object(controller,
                  "repair_wgcf_route", return_value=True):
                self.assertEqual(controller.probe(path), (True, {source}))
            self.assertEqual(len(curl), 2)
            self.assertNotEqual(curl[0][-1], curl[1][-1])
            for cmd in curl:
                self.assertEqual(cmd[cmd.index("--interface") + 1], "if!" + dev)
                self.assertEqual(cmd[cmd.index("--max-time") + 1], "3")


if __name__ == "__main__":
    unittest.main()
