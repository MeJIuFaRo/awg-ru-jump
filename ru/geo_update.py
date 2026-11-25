#!/usr/bin/env python3
"""Refresh independent RunetFreedom GeoIP and GeoSite snapshots on Linux."""

import argparse
import contextlib
import datetime as dt
import fcntl
import hashlib
import io
import ipaddress
import json
import mmap
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
from urllib.parse import quote
from urllib.request import Request, urlopen


REPO = "runetfreedom/russia-v2ray-rules-dat"
LATEST = f"https://api.github.com/repos/{REPO}/releases/latest"
CATEGORIES = {"geoip": "RU", "geosite": "CATEGORY-RU"}
APPLY = "/usr/local/lib/awg-geo/apply-data"
DOMAIN_TYPES = ("keyword", "regexp", "domain", "full")
CHUNK = 1024 * 1024


def download(url, output, limit):
    request = Request(url, headers={"User-Agent": "awg-geo-updater/1"})
    for attempt in range(3):
        try:
            with urlopen(request, timeout=60) as response:
                output.seek(0)
                output.truncate()
                size = 0
                while True:
                    chunk = response.read(CHUNK)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > limit:
                        raise ValueError(f"download exceeds {limit} bytes")
                    output.write(chunk)
                return size
        except OSError:
            if attempt == 2:
                raise
            time.sleep(2 ** attempt)


def get_release():
    response = io.BytesIO()
    download(LATEST, response, CHUNK)
    release = json.loads(response.getvalue())
    tag = release["tag_name"]
    if not isinstance(tag, str) or not re.fullmatch(r"[a-zA-Z0-9_.-]+", tag):
        raise ValueError("invalid release tag")
    return tag, {asset["name"]: asset for asset in release["assets"]}


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def varint(data, pos, end):
    value = 0
    for shift in range(0, 70, 7):
        if pos == end:
            break
        byte = data[pos]
        pos += 1
        if shift == 63 and byte > 1:
            break
        value |= (byte & 127) << shift
        if byte < 128:
            return value, pos
    raise ValueError("invalid protobuf varint")


def fields(data, start, end):
    """Yield (field, wire, value, end), keeping length-delimited values as offsets."""
    pos = start
    while pos < end:
        key, pos = varint(data, pos, end)
        number, wire = key >> 3, key & 7
        if number == 0:
            raise ValueError("invalid protobuf field number")
        if wire == 0:
            value, pos = varint(data, pos, end)
        elif wire in (1, 2, 5):
            if wire == 2:
                length, pos = varint(data, pos, end)
            else:
                length = 8 if wire == 1 else 4
            value = pos
            pos += length
            if pos > end:
                raise ValueError("truncated protobuf field")
        else:
            raise ValueError(f"unsupported protobuf wire type {wire}")
        yield number, wire, value, pos


def cidr_rule(data, start, end):
    address, prefix = b"", 0
    for number, wire, value, stop in fields(data, start, end):
        if (number, wire) == (1, 2):
            address = data[value:stop]
        elif (number, wire) == (2, 0):
            prefix = value
    network = ipaddress.ip_network((address, prefix), strict=True)
    return str(network) if network.version == 4 else None


def domain_rule(data, start, end):
    kind, name = 0, ""
    for number, wire, value, stop in fields(data, start, end):
        if (number, wire) == (1, 0):
            kind = value
        elif (number, wire) == (2, 2):
            name = data[value:stop].decode("utf-8")
    if kind >= len(DOMAIN_TYPES) or not name or "#" in name or any(
        not char.isprintable() or char.isspace() for char in name
    ):
        raise ValueError("unsupported or empty mosdns domain rule")
    return f"{DOMAIN_TYPES[kind]}:{name}"


def extract_rules(source, path):
    category = CATEGORIES[source].encode("ascii")
    rule = cidr_rule if source == "geoip" else domain_rule
    rules = set()
    with path.open("rb") as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
        for number, wire, start, end in fields(data, 0, len(data)):
            if (number, wire) != (1, 2):
                continue
            code = next(
                (data[a:b].upper() for n, w, a, b in fields(data, start, end) if (n, w) == (1, 2)),
                None,
            )
            if code != category:
                continue
            for n, w, a, b in fields(data, start, end):
                if source == "geoip" and (n, w) == (3, 0) and a:
                    raise ValueError("inverse GeoIP category")
                if (n, w) == (2, 2):
                    value = rule(data, a, b)
                    if value is not None:
                        rules.add(value)
    if not rules:
        raise ValueError(f"empty or absent category {CATEGORIES[source]}")
    return sorted(rules)


def prepare(source, release, stage):
    tag, assets = release
    name = f"{source}.dat"
    manifest = name + ".sha256sum"
    base = f"https://github.com/{REPO}/releases/download/{quote(tag, safe='')}/"
    for item, limit in ((manifest, 4096), (name, 512 * CHUNK)):
        asset = assets[item]
        expected_size = asset["size"]
        if not 0 < expected_size <= limit:
            raise ValueError(f"invalid release size for {item}")
        with (stage / item).open("wb") as output:
            if download(base + item, output, expected_size) != expected_size:
                raise ValueError(f"incomplete download of {item}")

    check = (stage / manifest).read_text(encoding="ascii").strip()
    match = re.fullmatch(r"([A-Fa-f0-9]{64})\s+\*?(?:\./)?" + re.escape(name), check)
    digest = sha256_file(stage / name)
    if not match or match[1].lower() != digest:
        raise ValueError(f"SHA-256 mismatch for {name}")
    published = assets[name].get("digest")
    if published and published.lower() != "sha256:" + digest:
        raise ValueError(f"release API digest mismatch for {name}")

    rules = extract_rules(source, stage / name)
    rules_path = stage / "rules.txt"
    rules_path.write_bytes(("\n".join(rules) + "\n").encode("utf-8"))
    meta = dict(tag=tag, sha256=digest, category=CATEGORIES[source], count=len(rules),
                rules_sha256=sha256_file(rules_path))
    (stage / "metadata.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    for item in stage.iterdir():
        item.chmod(0o644)
    stage.chmod(0o755)
    return meta


def log(source, result, detail):
    print(f"{dt.datetime.now(dt.timezone.utc).isoformat()} {source} {result} {detail}", flush=True)


def atomic_text(path, value):
    tmp = path.with_name("." + path.name + ".new")
    tmp.write_text(value, encoding="utf-8")
    os.replace(tmp, path)


def set_link(link, target):
    if target is None:
        link.unlink(missing_ok=True)
        return
    tmp = link.with_name("." + link.name + ".new")
    tmp.unlink(missing_ok=True)
    tmp.symlink_to(target, target_is_directory=True)
    os.replace(tmp, link)


def read_link(path):
    return os.readlink(path) if path.is_symlink() else None


def recover(directory, apply):
    journal = directory / "pending.json"
    if not journal.exists():
        return
    txn = json.loads(journal.read_text(encoding="utf-8"))
    set_link(directory / "current", txn["current"])
    set_link(directory / "previous", txn["previous"])
    if txn["apply"] and txn["current"]:
        if apply is None:
            raise RuntimeError("pending live rollback requires the apply hook")
        apply(directory.name)
    journal.unlink()
    log(directory.name, "rolled-back", f"current={txn['current']}")


def prune(directory):
    keep = {read_link(directory / name) for name in ("current", "previous")}
    for path in directory.glob("version-*"):
        if path.name not in keep and not path.is_symlink() and path.is_dir():
            shutil.rmtree(path)


def is_current(directory, source, meta):
    current = directory / "current"
    try:
        return (
            json.loads((current / "metadata.json").read_text(encoding="utf-8")) == meta
            and sha256_file(current / "rules.txt") == meta["rules_sha256"]
            and sha256_file(current / f"{source}.dat") == meta["sha256"]
        )
    except (OSError, ValueError):
        return False


def update_source(directory, release, apply):
    source = directory.name
    with tempfile.TemporaryDirectory(prefix=".stage-", dir=directory) as work:
        staged = Path(work) / "candidate"
        staged.mkdir()
        meta = prepare(source, release, staged)
        detail = f"tag={meta['tag']} sha256={meta['sha256']} count={meta['count']}"
        if is_current(directory, source, meta):
            log(source, "unchanged", detail)
            return
        saved = Path(tempfile.mkdtemp(prefix=f"version-{meta['tag']}-", dir=directory))
        os.replace(staged, saved)
        old = read_link(directory / "current")
        journal = directory / "pending.json"
        atomic_text(journal, json.dumps(dict(current=old, previous=read_link(directory / "previous"),
                                             apply=apply is not None)))
        try:
            set_link(directory / "current", saved.name)
            if apply is not None:
                apply(source)
            set_link(directory / "previous", old)
        except BaseException:
            recover(directory, apply)
            raise
        journal.unlink()
        log(source, "updated", detail)


def run(state, apply, today=None):
    state.mkdir(parents=True, exist_ok=True)
    today = today or dt.datetime.now(dt.timezone.utc).date().isoformat()
    failed = False
    with (state / ".update.lock").open("a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            release = get_release()
            discovery_error = None
        except Exception as exc:
            discovery_error = exc
        for source in CATEGORIES:
            directory = state / source
            try:
                directory.mkdir(exist_ok=True)
                recover(directory, apply)
                prune(directory)
                # A killed download can leave a staging directory behind.
                for stale in directory.glob(".stage-*"):
                    if stale.is_dir() and not stale.is_symlink():
                        shutil.rmtree(stale)
                if discovery_error is not None:
                    raise discovery_error
                update_source(directory, release, apply)
                prune(directory)
                if source == "geosite" and apply is not None:
                    marker = directory / "last-rotation"
                    if not marker.exists() or marker.read_text().strip() != today:
                        apply("rotate")
                        atomic_text(marker, today + "\n")
                        log(source, "rotated", f"date={today} UTC")
            except Exception as exc:
                failed = True
                log(source, "failed", f"{exc}; current={read_link(directory / 'current')}")
    return int(failed)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, default=Path("/var/lib/awg-geo"))
    parser.add_argument("--no-apply", action="store_true", help="bootstrap snapshots before starting services")
    args = parser.parse_args()
    apply = None if args.no_apply else lambda action: subprocess.run([APPLY, action], check=True)
    return run(args.state_dir, apply)


if __name__ == "__main__":
    sys.exit(main())
