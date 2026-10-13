"""Offline tests: no connection to GitHub, no real Xray install or systemd."""
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))
import core_manager as c

TAG = "v26.10.10"

def archive_bytes():
    binary = b'#!/bin/sh\nprintf "Xray 26.10.10 mock-build\\n"\n'
    f = io.BytesIO()
    with zipfile.ZipFile(f, "w") as z:
        z.writestr("xray", binary)
    return f.getvalue()


def release(tag=TAG, prerelease=True, name="Xray-linux-64.zip", content=None):
    content = content or archive_bytes()
    return {"tag_name": tag, "prerelease": prerelease, "draft": False,
            "published_at": "2026-10-10T09:22:39Z", "assets": [{
                "name": name, "size": len(content),
                "digest": "sha256:" + hashlib.sha256(content).hexdigest(),
                "browser_download_url": f"https://github.com/XTLS/Xray-core/releases/download/{tag}/{name}",
            }]}

class CoreManagerTests(unittest.TestCase):
    def test_newest_prerelease_not_latest_stable(self):
        older = release(tag="v26.9.30")
        older["published_at"] = "2026-09-30T00:00:00Z"
        stable = release(tag="v26.12.31", prerelease=False)
        stable["published_at"] = "2026-12-31T00:00:00Z"
        self.assertEqual(c.select_latest([stable, older, release()], "Xray-linux-64.zip")["tag"], TAG)

    def test_reject_absent_unverified_and_external_assets(self):
        bad = release()
        bad["assets"][0]["digest"] = None
        with self.assertRaises(c.CoreError):
            c.select_latest([bad], "Xray-linux-64.zip")
        bad = release()
        bad["assets"][0]["browser_download_url"] = "https://attacker.invalid/binary"
        with self.assertRaises(c.CoreError):
            c.select_latest([bad], "Xray-linux-64.zip")
        with self.assertRaises(c.CoreError):
            c.select_latest([release(prerelease=False)], "Xray-linux-64.zip")


    def test_paginated_release_fetch_stops_after_verified_prerelease(self):
        """First page can contain stable releases without blocking pre-release lookup."""
        class Reply:
            def __init__(self, rows):
                self.data = io.BytesIO(json.dumps(rows).encode())
            def __enter__(self): return self
            def __exit__(self, *exc): return False
            def read(self, length): return self.data.read(length)

        first = [release(tag=f"v26.10.{10+i}", prerelease=False) for i in range(c.PAGE_SIZE)]
        second = [release()]
        urls = []
        def urlopen(request, timeout):
            urls.append(request.full_url)
            return Reply(first if "&page=1" in request.full_url else second)

        with patch.object(c, "linux_archive", return_value="Xray-linux-64.zip"), \
             patch.object(c.urllib.request, "urlopen", side_effect=urlopen):
            got = c.fetch_releases()
        self.assertEqual(len(got), c.PAGE_SIZE + 1)
        self.assertEqual(len(urls), 2)
        self.assertIn("per_page=10&page=2", urls[-1])
        self.assertEqual(c.select_latest(got, "Xray-linux-64.zip")["tag"], TAG)

    def test_fetch_metadata_has_safe_bounded_size_and_fails_closed(self):
        class Oversized:
            def __enter__(self): return self
            def __exit__(self, *exc): return False
            def read(self, length): return b"x" * length

        with patch.object(c, "linux_archive", return_value="Xray-linux-64.zip"), \
             patch.object(c.urllib.request, "urlopen", return_value=Oversized()):
            with self.assertRaisesRegex(c.CoreError, "Unexpectedly large"):
                c.fetch_releases()

    def test_valid_first_page_does_not_fetch_more(self):
        class Reply:
            def __enter__(self): return self
            def __exit__(self, *exc): return False
            def read(self, _max): return json.dumps([release()]).encode()

        with patch.object(c, "linux_archive", return_value="Xray-linux-64.zip"), \
             patch.object(c.urllib.request, "urlopen", return_value=Reply()) as fetch:
            got = c.fetch_releases()
        self.assertEqual(len(got), 1)
        fetch.assert_called_once()

    def test_cached_verified_version_and_no_redownload(self):
        with tempfile.TemporaryDirectory() as d, patch.object(c, "linux_archive", return_value="Xray-linux-64.zip"):
            data = archive_bytes()
            with patch.object(c, "_download", return_value=data) as downloader:
                path, tag = c.ensure_latest(Path(d), releases=[release(content=data)])
                self.assertEqual(tag, TAG)
                self.assertEqual(path.parent.name, TAG)
                self.assertEqual(path.stat().st_mode & 0o777, 0o700)
                self.assertEqual((path.parent / "release.json").stat().st_mode & 0o777, 0o600)
                self.assertTrue(c.version_matches(path, TAG))
                self.assertEqual(downloader.call_count, 1)
                same, _ = c.ensure_latest(Path(d), releases=[release(content=data)])
                self.assertEqual(same, path)
                self.assertEqual(downloader.call_count, 1)
                # A locally modified cached executable must not be trusted based on its version string alone.
                path.write_text('#!/bin/sh\nprintf "Xray 26.10.10 mock-build\\n"\n# tampered\n')
                with patch.object(c, "_download", return_value=data) as reinstaller:
                    c.ensure_latest(Path(d), releases=[release(content=data)])
                    self.assertEqual(reinstaller.call_count, 1)

    def test_download_digest_mismatch_never_executes(self):
        class Response:
            def __init__(self, value): self.input = io.BytesIO(value)
            def __enter__(self): return self
            def __exit__(self, *a): pass
            def read(self, n): return self.input.read(n)
        with patch.object(c.urllib.request, "urlopen", return_value=Response(b"bad")):
            with self.assertRaisesRegex(c.CoreError, "SHA256/size mismatch"):
                c._download("https://example.invalid", 3, "sha256:" + "0" * 64)

    def test_dry_run_never_accesses_network_or_core(self):
        with patch.object(c, "ensure_latest", side_effect=AssertionError("network access")):
            self.assertEqual(c.resolve_core(dry_run=True), "")

    def test_explicit_executable_allowed_for_reproducibility(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "xray"
            path.write_text("#!/bin/sh\nexit 0\n")
            path.chmod(0o700)
            with patch.object(c, "ensure_latest", side_effect=AssertionError("network access")):
                self.assertEqual(c.resolve_core(str(path)), str(path))

    def test_cli_core_manager_prints_clean_path_only(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "xray"
            with patch.object(c, "ensure_latest", return_value=(path, TAG)):
                with patch("builtins.print") as printer:
                    self.assertEqual(c.main(["--ensure"]), 0)
                    printer.assert_called_once_with(path)

if __name__ == "__main__":
    unittest.main()
