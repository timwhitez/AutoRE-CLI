#!/usr/bin/env python3
"""Read-only recipe/release metadata check; never downloads or executes binaries.

Offline: python3 -B packaging/check_release_metadata.py --release-before before.json
         --release-after after.json
Live:    python3 -B packaging/check_release_metadata.py --online
Tests:   python3 -B -m unittest discover -s packaging/tests -v

Capture before.json before collecting/downloading evidence and after.json after it.
A saved-snapshot pass certifies only those snapshots, not current remote state or
package-manager installation. Live mode brackets local recipe reads with API GETs.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "https://github.com/timwhitez/AutoRE-CLI"
API = "https://api.github.com/repos/timwhitez/AutoRE-CLI/releases/tags/v"
TARGETS = ("macos-arm64", "macos-x86_64", "linux-arm64", "linux-x86_64", "windows-x86_64")
RECIPES = ("packaging/homebrew/autore-cli.rb", "packaging/scoop/autore-cli.json")
SHA256 = re.compile(r"[0-9a-f]{64}")
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")


class MetadataError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise MetadataError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def read_json(text):
    return json.loads(text, object_pairs_hook=unique_object)


def asset_name(version, target):
    suffix = "zip" if target.startswith("windows-") else "tar.gz"
    return f"AutoRE-CLI-{version}-{target}.{suffix}"


def asset_url(version, target):
    return f"{REPOSITORY}/releases/download/v{version}/{asset_name(version, target)}"


def read_recipes(root):
    scoop = read_json((root / RECIPES[1]).read_text(encoding="utf-8"))
    require(isinstance(scoop, dict), "Scoop manifest must be an object")
    version = scoop.get("version")
    require(isinstance(version, str) and VERSION.fullmatch(version), "invalid Scoop version")
    architecture = scoop.get("architecture")
    require(isinstance(architecture, dict) and set(architecture) == {"64bit"},
            "Scoop must contain exactly the Windows x86_64 target")
    windows = architecture["64bit"]
    require(isinstance(windows, dict), "invalid Scoop target")
    require(scoop.get("extract_dir") == f"AutoRE-CLI-{version}-windows-x86_64",
            "Scoop extract directory/version mismatch")
    formula = (root / RECIPES[0]).read_text(encoding="utf-8")
    versions = re.findall(r'^\s*version "([^"]+)"\s*$', formula, re.M)
    require(versions == [version], "Homebrew/Scoop version mismatch")
    # Deliberately recognize only the current declarative selector grammar.
    # Never evaluate Ruby; changed selectors require an explicit checker update.
    lines = "\n".join(line.strip() for line in formula.splitlines() if line.strip())
    pair = r'url "([^"\n]+)"\nsha256 "([^"\n]+)"\n'
    pattern = (r'on_macos do\nif Hardware::CPU.arm\?\n' + pair + r'else\n' + pair +
               r'end\nend\non_linux do\nif Hardware::CPU.arm\? && Hardware::CPU.is_64_bit\?\n' + pair +
               r'elsif Hardware::CPU.intel\? && Hardware::CPU.is_64_bit\?\n' + pair +
               r'else\nodie "AutoRE-CLI has no release for this Linux architecture"\nend\nend')
    matches = list(re.finditer(pattern, lines))
    require(len(matches) == 1 and len(re.findall(r'^url ', lines, re.M)) == 4 and
            len(re.findall(r'^sha256 ', lines, re.M)) == 4 and
            len(re.findall(r'^on_(?:macos|linux) do$', lines, re.M)) == 2,
            "Homebrew must contain exactly four supported platform selectors")
    values = matches[0].groups()
    recipes = {target: {"url": values[i * 2], "sha256": values[i * 2 + 1]}
               for i, target in enumerate(TARGETS[:4])}
    recipes[TARGETS[4]] = {"url": windows.get("url"), "sha256": windows.get("hash")}
    for target, record in recipes.items():
        require(record["url"] == asset_url(version, target), f"recipe URL/architecture mismatch: {target}")
        require(isinstance(record["sha256"], str) and SHA256.fullmatch(record["sha256"]),
                f"invalid recipe SHA-256: {target}")
    return version, recipes


def release_identity(release, version):
    require(isinstance(release, dict), "release response must be an object")
    require(type(release.get("id")) is int and release["id"] > 0, "missing release ID")
    require(release.get("tag_name") == f"v{version}", "release/recipe version mismatch")
    require(release.get("draft") is False and release.get("prerelease") is False,
            "release must be published and stable")
    require(isinstance(release.get("updated_at"), str) and bool(release["updated_at"]),
            "missing release update timestamp")
    assets = release.get("assets")
    require(isinstance(assets, list) and bool(assets), "missing release assets")
    names, ids, records = set(), set(), {}
    fields = ("id", "name", "browser_download_url", "digest", "size", "state", "created_at", "updated_at")
    for asset in assets:
        require(isinstance(asset, dict), "invalid release asset")
        name, identity = asset.get("name"), asset.get("id")
        require(isinstance(name, str) and bool(name) and name not in names, "missing/duplicate asset name")
        require(type(identity) is int and identity > 0 and identity not in ids, "missing/duplicate asset ID")
        require(asset.get("state") == "uploaded", f"asset is unavailable: {name}")
        require(type(asset.get("size")) is int and asset["size"] > 0, f"invalid asset size: {name}")
        digest = asset.get("digest")
        require(isinstance(digest, str) and digest.startswith("sha256:") and
                SHA256.fullmatch(digest[7:]), f"invalid asset digest: {name}")
        require(all(isinstance(asset.get(key), str) and asset[key]
                    for key in ("browser_download_url", "created_at", "updated_at")),
                f"incomplete asset metadata: {name}")
        names.add(name)
        ids.add(identity)
        records[name] = tuple(asset[key] for key in fields)
    for target in TARGETS:
        name = asset_name(version, target)
        require(name in records, f"missing release target: {target}")
        require(records[name][2] == asset_url(version, target), f"release URL mismatch: {target}")
    # Ignore volatile download counts; bind all published asset identities/bytes.
    identity = (release["id"], release["tag_name"], release["updated_at"],
                release.get("published_at"), release.get("target_commitish"),
                tuple(sorted(records.items())))
    return identity, {target: records[asset_name(version, target)][3][7:] for target in TARGETS}


def verify_recipe_checksums(root):
    rows = {}
    for line in (root / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  (.+)', line)
        require(match is not None, "malformed repository checksum row")
        digest, relative = match.groups()
        require(relative not in rows, "duplicate repository checksum row")
        rows[relative] = digest
    for relative in RECIPES:
        require(rows.get(relative) == hashlib.sha256((root / relative).read_bytes()).hexdigest(),
                f"repository checksum mismatch: {relative}")


def check(root, before, after, *, verify_checksums=True):
    version, recipes = read_recipes(root)
    first, digests = release_identity(before, version)
    last, _ = release_identity(after, version)
    require(first == last, "release/asset metadata changed during evidence collection")
    mismatches = [target for target in TARGETS if recipes[target]["sha256"] != digests[target]]
    require(not mismatches, "recipe/archive SHA-256 mismatch: " + ", ".join(mismatches))
    if verify_checksums:
        verify_recipe_checksums(root)
    return {"ok": True, "version": version, "release_id": before["id"],
            "targets_checked": list(TARGETS), "scope": "metadata only; no installation or binary execution"}


def fetch_release(version):
    request = Request(API + version, headers={"Accept": "application/vnd.github+json",
                                               "User-Agent": "AutoRE-CLI-metadata-check"})
    with urlopen(request, timeout=30) as response:
        data = response.read(4 * 1024 * 1024 + 1)
    require(len(data) <= 4 * 1024 * 1024, "release response exceeds 4 MiB")
    return read_json(data.decode("utf-8"))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--online", action="store_true")
    parser.add_argument("--release-before", type=Path)
    parser.add_argument("--release-after", type=Path)
    args = parser.parse_args(argv)
    try:
        require((args.online and not args.release_before and not args.release_after) or
                (not args.online and args.release_before and args.release_after),
                "choose --online or both --release-before and --release-after")
        if args.online:
            version, _ = read_recipes(args.root)
            before = fetch_release(version)
            # Freeze the local inputs before the second API observation.
            # check() reads again below; ensure those local reads did not drift.
            local_before = {p: (args.root / p).read_bytes() for p in (*RECIPES, "SHA256SUMS")}
            after = fetch_release(version)
            result = check(args.root, before, after)
            require(all((args.root / p).read_bytes() == data for p, data in local_before.items()),
                    "local metadata changed during evidence collection")
        else:
            before = read_json(args.release_before.read_text(encoding="utf-8"))
            after = read_json(args.release_after.read_text(encoding="utf-8"))
            result = check(args.root, before, after)
        result["observation"] = "live API bracket" if args.online else "saved snapshots"
    except (MetadataError, OSError, ValueError, TypeError, KeyError) as error:
        print(json.dumps({"ok": False, "error": str(error)}), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
