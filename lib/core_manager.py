#!/usr/bin/env python3
"""Resolve the newest published XTLS/Xray-core *pre-release* without altering system Xray.

The official GitHub API is queried at the start of every live scan. An immutable,
SHA256-verified binary is cached per version in the current user's home directory.
No systemd, sudo, installer shell script, or global PATH modification is used.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
import zipfile

# Small pages avoid GitHub's large release metadata (30 releases > 3 MiB).
# Search subsequent pages only if the initial page has no verified pre-release.
API = "https://api.github.com/repos/XTLS/Xray-core/releases?per_page=10"
PAGE_SIZE = 10
MAX_RELEASE_PAGES = 8
MAX_METADATA_BYTES = 8 * 1024 * 1024
REPO_RELEASES = "https://github.com/XTLS/Xray-core/releases/download/"
CACHE_ROOT = Path.home() / ".local" / "share" / "xray-finalmask-scanner" / "cores"
MAX_ZIP_BYTES = 150 * 1024 * 1024
TAG_RE = re.compile(r"^v[0-9]+(?:\.[0-9]+){2}$")
SHA_RE = re.compile(r"^sha256:([a-fA-F0-9]{64})$")


class CoreError(RuntimeError):
    """A safe, credential-free core resolution error."""


def linux_archive() -> str:
    if sys.platform != "linux":
        raise CoreError("Only Linux binaries are managed automatically")
    machine = platform.machine().lower()
    mapping = {
        "x86_64": "Xray-linux-64.zip", "amd64": "Xray-linux-64.zip",
        "aarch64": "Xray-linux-arm64-v8a.zip", "arm64": "Xray-linux-arm64-v8a.zip",
        "i386": "Xray-linux-32.zip", "i686": "Xray-linux-32.zip",
        "armv7l": "Xray-linux-arm32-v7a.zip",
    }
    if machine not in mapping:
        raise CoreError(f"Unsupported architecture for automatic Xray install: {machine}")
    return mapping[machine]


def fetch_releases(timeout=12) -> list[dict]:
    """Find the latest usable pre-release using bounded, paginated API requests.

    The GitHub /releases API returns enormous JSON documents because every
    release embeds all platform assets. Fetch ten releases per page rather than
    treating ordinary GitHub responses as an error. Continue through a bounded
    number of pages when the first ones contain only stable/unusable releases.
    Never silently substitute an unverified or stale cached executable.
    """
    asset_name = linux_archive()
    releases = []
    for page in range(1, MAX_RELEASE_PAGES + 1):
        request = urllib.request.Request(f"{API}&page={page}", headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "xray-finalmask-scanner-prerelease-manager",
            "X-GitHub-Api-Version": "2022-11-28",
        })
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                data = response.read(MAX_METADATA_BYTES + 1)
        except urllib.error.HTTPError as exc:
            if exc.code in (403, 429):
                raise CoreError("GitHub API rate limited or access denied; retry later") from exc
            raise CoreError(f"GitHub release API HTTP error {exc.code}") from exc
        except (OSError, urllib.error.URLError) as exc:
            raise CoreError("Unable to check official Xray pre-releases; check network or GitHub API limits") from exc
        if len(data) > MAX_METADATA_BYTES:
            raise CoreError("Unexpectedly large GitHub release metadata page")
        try:
            batch = json.loads(data)
        except (ValueError, UnicodeDecodeError) as exc:
            raise CoreError("Invalid GitHub release metadata") from exc
        if not isinstance(batch, list):
            raise CoreError("GitHub API did not return a release list")
        releases.extend(batch)
        try:
            select_latest(releases, asset_name)
            break
        except CoreError:
            if len(batch) < PAGE_SIZE:
                break
    return releases


def select_latest(releases: list[dict], asset_name: str) -> dict:
    candidates = []
    for release in releases:
        if not isinstance(release, dict) or not release.get("prerelease") or release.get("draft"):
            continue
        tag = release.get("tag_name", "")
        if not TAG_RE.fullmatch(tag):
            continue
        asset = next((a for a in (release.get("assets") or [])
                      if isinstance(a, dict) and a.get("name") == asset_name), None)
        if asset is None:
            continue
        url = asset.get("browser_download_url", "")
        digest = asset.get("digest", "")
        if (not isinstance(url, str) or not isinstance(digest, str) or
            not url.startswith(REPO_RELEASES + tag + "/") or not SHA_RE.fullmatch(digest)):
            continue
        if (not isinstance(asset.get("size"), int) or asset["size"] <= 0
            or asset["size"] > MAX_ZIP_BYTES):
            continue
        candidates.append({"tag": tag, "url": url, "digest": digest,
                           "size": asset["size"], "published_at": release.get("published_at") or ""})
    if not candidates:
        raise CoreError("No verified official Xray pre-release archive found for this platform")
    return max(candidates, key=lambda c: (c["published_at"], c["tag"]))


def version_matches(exe: Path, tag: str) -> bool:
    try:
        result = subprocess.run([str(exe), "version"], capture_output=True, text=True, timeout=12)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0 and bool(re.search(
        r"^Xray\s+" + re.escape(tag[1:]) + r"(?:\s|$)", result.stdout, re.M))


def _download(url: str, expected_size: int, expected_digest: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "xray-finalmask-scanner"})
    try:
        with urllib.request.urlopen(req, timeout=50) as response:
            # Stream into a bounded buffer; no unverified blob is ever executed.
            stream = io.BytesIO()
            digest = hashlib.sha256()
            size = 0
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_ZIP_BYTES:
                    raise CoreError("Xray archive exceeds the maximum allowed size")
                stream.write(chunk)
                digest.update(chunk)
    except (OSError, urllib.error.URLError) as exc:
        raise CoreError("Failed to download official Xray pre-release archive") from exc
    if size != expected_size or digest.hexdigest().lower() != expected_digest.split(":", 1)[1].lower():
        raise CoreError("Xray archive SHA256/size mismatch; refusing to install")
    return stream.getvalue()


def ensure_latest(cache_root: Path = CACHE_ROOT, *, releases=None) -> tuple[Path, str]:
    asset_name = linux_archive()
    selected = select_latest(fetch_releases() if releases is None else releases, asset_name)
    tag = selected["tag"]
    directory = Path(cache_root).expanduser() / tag
    binary = directory / "xray"
    marker = directory / "release.json"
    if binary.is_file() and marker.is_file():
        try:
            metadata = json.loads(marker.read_text(encoding="utf-8"))
            expected_exe_digest = metadata.get("binary_sha256", "")
            if (metadata.get("digest") == selected["digest"] and
                SHA_RE.fullmatch("sha256:" + expected_exe_digest) and
                hashlib.sha256(binary.read_bytes()).hexdigest() == expected_exe_digest and
                version_matches(binary, tag)):
                return binary, tag
        except (ValueError, OSError):
            pass
    content = _download(selected["url"], selected["size"], selected["digest"])
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            entry = archive.getinfo("xray")
            if entry.is_dir() or entry.file_size > 100 * 1024 * 1024:
                raise CoreError("Unexpected Xray executable in release archive")
            executable = archive.read(entry)
    except (zipfile.BadZipFile, KeyError, RuntimeError) as exc:
        raise CoreError("Downloaded Xray release archive is invalid") from exc
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(directory, 0o700)
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(dir=directory, prefix=".xray-", delete=False) as fh:
            temp_path = Path(fh.name)
            fh.write(executable)
        os.chmod(temp_path, 0o700)
        if not version_matches(temp_path, tag):
            raise CoreError("Downloaded Xray executable version does not match the selected pre-release")
        temp_path.replace(binary)
        marker_tmp = directory / ".release.json.tmp"
        marker_tmp.write_text(json.dumps({"tag": tag, "digest": selected["digest"],
                                          "binary_sha256": hashlib.sha256(executable).hexdigest(),
                                          "archive": asset_name}), encoding="utf-8")
        os.chmod(marker_tmp, 0o600)
        marker_tmp.replace(marker)
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)
    return binary, tag


def core_identity(exe: str) -> str:
    if not exe:
        return "DRY_RUN_NO_CORE"
    try:
        result = subprocess.run([exe, "version"], capture_output=True, text=True, timeout=12)
        if result.returncode == 0 and result.stdout:
            return result.stdout.splitlines()[0][:120]
    except (OSError, subprocess.TimeoutExpired):
        pass
    return "UNKNOWN"


def resolve_core(explicit: str | None = None, *, dry_run=False) -> str:
    if explicit:
        path = Path(explicit).expanduser()
        if not path.is_file() or not os.access(path, os.X_OK):
            raise CoreError("Specified --xray executable is missing or not executable")
        return str(path)
    if dry_run:
        return ""  # Offline generation never needs a core binary or network.
    binary, tag = ensure_latest()
    print(f"Xray core: latest official pre-release {tag} ({binary})", flush=True)
    return str(binary)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Manage Xray-core latest official prerelease (user-local)")
    parser.add_argument("--ensure", action="store_true", help="Install/update and print absolute executable path")
    parser.add_argument("--latest", action="store_true", help="Print the latest official pre-release tag")
    args = parser.parse_args(argv)
    if args.latest:
        print(select_latest(fetch_releases(), linux_archive())["tag"])
        return 0
    path, _tag = ensure_latest()
    print(path if args.ensure else f"Xray ready: {path}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except CoreError as exc:
        print(f"Xray pre-release: {exc}", file=sys.stderr)
        sys.exit(2)
