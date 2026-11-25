"""Offline acceptance tests. Run on Linux: python3 -m unittest -v test_geo_update."""

import contextlib
import hashlib
import io
import ipaddress
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import geo_update as updater


def vint(value):
    result = bytearray()
    while value >= 128:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def field(number, value):
    if isinstance(value, int):
        return vint(number << 3) + vint(value)
    return vint((number << 3) | 2) + vint(len(value)) + value


def geoip(octet):
    def cidr(ip, prefix):
        return field(2, field(1, ipaddress.ip_address(ip).packed) + field(2, prefix))
    other = field(1, field(1, b"EXAMPLE") + cidr("192.0.2.0", 24))
    selected = cidr(f"198.51.100.{octet * 32}", 27) + cidr("2001:db8::", 32)
    return other + field(1, selected + field(1, b"RU"))


def geosite(octet):
    def domain(kind, name):
        return field(2, field(1, kind) + field(2, name.encode("utf-8")))
    selected = b"".join(domain(kind, f"site{octet}{kind}.example") for kind in range(4))
    other = field(1, field(1, b"RU-BLOCKED") + domain(2, "excluded.example"))
    return other + field(1, field(1, b"CATEGORY-RU") + selected)


class Release:
    """Serve the same byte streams and asset sizes as the two GitHub endpoints."""

    def __init__(self, version):
        self.tag = str(version)
        self.files = {}
        self.offline = set()
        self.requests = []
        self.set_data("geoip", geoip(version))
        self.set_data("geosite", geosite(version))

    def set_data(self, source, data):
        name = source + ".dat"
        self.files[name] = data
        digest = hashlib.sha256(data).hexdigest()
        self.files[name + ".sha256sum"] = f"{digest}  {name}\n".encode()

    def download(self, url, output, limit):
        self.requests.append(url)
        if url == updater.LATEST:
            assets = [dict(name=name, size=len(data)) for name, data in self.files.items()]
            data = json.dumps(dict(tag_name=self.tag, assets=assets)).encode()
        else:
            prefix = f"https://github.com/{updater.REPO}/releases/download/{self.tag}/"
            if not url.startswith(prefix):
                raise AssertionError(f"unexpected URL {url}")
            name = url[len(prefix):]
            if name in self.offline:
                raise OSError(f"{name} unavailable")
            data = self.files[name]
        if len(data) > limit:
            raise ValueError("download size limit exceeded")
        output.write(data)
        return len(data)


class UpdateAcceptance(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.live = {}
        self.calls = []
        self.fail_next = set()
        self.rotation_count = 0
        self.initial = Release(1)
        self.assertEqual(self.update(self.initial, day=1), 0)
        self.current_before = {s: self.current(s).resolve() for s in updater.CATEGORIES}
        self.live_before = self.live.copy()
        self.calls.clear()

    def current(self, source):
        return self.root / source / "current"

    def apply(self, action):
        self.calls.append(action)
        if action != "rotate":
            # This simulates a backend that can fail *after* changing its live set.
            self.live[action] = (self.current(action) / "rules.txt").read_text()
        if action in self.fail_next:
            self.fail_next.remove(action)
            raise RuntimeError(f"{action} hook failed")
        if action == "rotate":
            self.rotation_count += 1

    def update(self, release, day=2):
        self.logs = io.StringIO()
        with patch.object(updater, "download", release.download), contextlib.redirect_stdout(self.logs):
            return updater.run(self.root, self.apply, today=f"2026-01-{day:02}")

    def assert_effects(self, release, expected):
        for source in updater.CATEGORIES:
            directory = self.current(source)
            data = release if source in expected else self.initial
            meta = json.loads((directory / "metadata.json").read_text())
            self.assertEqual(meta["tag"], data.tag)
            self.assertEqual((directory / f"{source}.dat").read_bytes(), data.files[f"{source}.dat"])
            self.assertEqual((directory / f"{source}.dat.sha256sum").read_bytes(),
                             data.files[f"{source}.dat.sha256sum"])
            rules = (directory / "rules.txt").read_text()
            self.assertEqual(self.live[source], rules)
            self.assertEqual(meta["count"], len(rules.splitlines()))
            self.assertEqual(meta["rules_sha256"], hashlib.sha256(rules.encode()).hexdigest())
            self.assertEqual(source in expected, directory.resolve() != self.current_before[source])
            self.assertEqual(source in expected, rules != self.live_before[source])
            if source in expected:
                self.assertEqual((directory.parent / "previous").resolve(), self.current_before[source])
            else:
                self.assertFalse((directory.parent / "previous").is_symlink())
            self.assertIn(f" {source} ", self.logs.getvalue())

    def test_both_available(self):
        release = Release(2)
        self.assertEqual(self.update(release), 0)
        self.assert_effects(release, {"geoip", "geosite"})
        self.assertEqual(self.calls, ["geoip", "geosite", "rotate"])
        self.assertEqual(self.live["geoip"], "198.51.100.64/27\n")
        self.assertEqual(set(self.live["geosite"].splitlines()),
                         {f"{t}:site2{i}.example" for i, t in enumerate(updater.DOMAIN_TYPES)})

    def test_geoip_only(self):
        release = Release(2)
        release.offline.add("geosite.dat")
        self.assertEqual(self.update(release), 1)
        self.assert_effects(release, {"geoip"})
        self.assertEqual(self.calls, ["geoip"])

    def test_geosite_only(self):
        release = Release(2)
        release.offline.add("geoip.dat.sha256sum")
        self.assertEqual(self.update(release), 1)
        self.assert_effects(release, {"geosite"})
        self.assertEqual(self.calls, ["geosite", "rotate"])

    def test_neither_available(self):
        release = Release(2)
        release.offline.update(("geoip.dat", "geosite.dat"))
        self.assertEqual(self.update(release), 1)
        self.assert_effects(release, set())
        self.assertEqual(self.calls, [])

    def test_wrong_checksum_and_empty_category(self):
        release = Release(2)
        release.files["geoip.dat"] += b"changed"
        release.set_data("geosite", field(1, field(1, b"CATEGORY-RU")))
        self.assertEqual(self.update(release), 1)
        self.assert_effects(release, set())
        self.assertIn("SHA-256 mismatch", self.logs.getvalue())
        self.assertIn("empty or absent category", self.logs.getvalue())
        self.assertEqual(self.calls, [])

    def test_same_tag_still_validates_and_rotates_once_a_day(self):
        self.assertEqual(self.update(self.initial), 0)
        self.assertEqual(self.calls, ["rotate"])
        self.assertEqual(self.update(self.initial), 0)
        self.assertEqual(self.calls, ["rotate"])
        self.assertEqual(self.rotation_count, 2)
        self.initial.set_data("geosite", b"\x0a\x07trunc")
        self.assertEqual(self.update(self.initial, day=3), 1)
        self.assertEqual(self.calls, ["rotate"])
        self.assertEqual(self.live, self.live_before)
        self.assertIn("truncated protobuf", self.logs.getvalue())

    def test_hook_failure_after_live_change_rolls_back_one_source(self):
        release = Release(2)
        self.fail_next.add("geosite")
        self.assertEqual(self.update(release), 1)
        self.assert_effects(release, {"geoip"})
        self.assertEqual(self.calls, ["geoip", "geosite", "geosite"])
        self.assertIn("geosite rolled-back", self.logs.getvalue())
        self.calls.clear()
        self.assertEqual(self.update(release), 0)
        self.assertEqual(self.calls, ["geosite", "rotate"])
        self.assert_effects(release, {"geoip", "geosite"})

    def test_failed_rotation_is_retried(self):
        self.fail_next.add("rotate")
        self.assertEqual(self.update(self.initial), 1)
        self.assertEqual(self.update(self.initial), 0)
        self.assertEqual(self.calls, ["rotate", "rotate"])
        self.assertEqual(self.rotation_count, 2)

    def test_only_current_and_previous_versions_remain(self):
        for version in (2, 3, 4):
            self.assertEqual(self.update(Release(version), day=version), 0)
        for source in updater.CATEGORIES:
            parent = self.current(source).parent
            self.assertEqual({p.resolve() for p in parent.glob("version-*")},
                             {(parent / "current").resolve(), (parent / "previous").resolve()})
            self.assertEqual(json.loads((parent / "previous" / "metadata.json").read_text())["tag"], "3")


if __name__ == "__main__":
    unittest.main()
