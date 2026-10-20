"""Real stable-open boundaries, including precheck-to-open FIFO replacement."""
from __future__ import annotations
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

subprocess_timeout = runpy.run_path(str(Path(__file__).with_name("subprocess_timeout.py")))["subprocess_timeout"]
ROOT = Path(__file__).resolve().parents[1]
MODULE = Path(os.environ.get("AUTORE_BUNDLE_HELPER", ROOT / "skills/auto-re/scripts/verify_bundle.py"))
SPEC = importlib.util.spec_from_file_location("bundle_open_helper", MODULE)
bundle = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bundle)


def fifo_child(root: Path, scenario: str) -> int:
    copies = root / "copies"
    copies.mkdir()
    bundle.tempfile.tempdir = str(copies)
    payload = root / "payload.json"
    content = b'{"static_fixture":true}'
    payload.write_bytes(content)
    manifest = root / "manifest.json"
    manifest.write_text(json.dumps({"schema_version": "0.1.0", "owner": "auto-re-cli", "kind": "context_bundle",
        "files": [{"path": payload.name, "ownership": "command", "bytes": len(content),
                   "sha256": hashlib.sha256(content).hexdigest()}], "next_actions": []}))
    output = root / "receipt.json"
    verified = None
    if scenario in ("receipt", "marker"):
        receipt, _ = bundle.validate_manifest_to_receipt(manifest, output)
        verified = Path(receipt["verified_root"])
        assert Path(receipt["files"][0]["path"]).read_bytes() == content
    source = {"manifest": manifest, "payload": payload, "receipt": output,
              "marker": verified / bundle.VERIFIED_ROOT_MARKER if verified else None}[scenario]
    real_open = bundle.os.open
    reached = []
    def swap_then_open(path, flags, *args, **kwargs):
        if Path(path) == source:
            source.unlink()
            os.mkfifo(source)
            reached.append(flags)
            print("reached_real_open", flush=True)
        return real_open(path, flags, *args, **kwargs)
    argv = [str(MODULE), "--cleanup-receipt", str(output)] if verified else [str(MODULE), str(manifest), "--receipt", str(output)]
    with patch.object(bundle.os, "open", side_effect=swap_then_open), patch.object(sys, "argv", argv):
        status = bundle.main()
    assert status == 1
    assert len(reached) == 1
    for flag in ("O_NONBLOCK", "O_NOFOLLOW", "O_CLOEXEC"):
        assert reached[0] & getattr(os, flag, 0) == getattr(os, flag, 0)
    assert source.is_fifo()
    if verified:
        assert verified.is_dir()
        assert Path(receipt["files"][0]["path"]).read_bytes() == content
        assert payload.read_bytes() == content
    else:
        assert not list(copies.iterdir()), list(copies.iterdir())
        assert not output.exists()
        if scenario == "payload": assert manifest.is_file()
        else: assert payload.read_bytes() == content
    print(json.dumps({"scenario": scenario, "status": "controlled_rejection", "flags": reached[0],
                      "helper_sha256": hashlib.sha256(MODULE.read_bytes()).hexdigest(), "platform": sys.platform}))
    return 0


class BundleOpenTests(unittest.TestCase):
    @unittest.skipUnless(hasattr(os, "mkfifo") and hasattr(os, "O_NONBLOCK"), "POSIX FIFO/nonblocking open required")
    def test_replacement_fifo_all_real_entrypoints(self):
        for scenario in ("manifest", "payload", "receipt", "marker"):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory(prefix="autore-open-") as directory:
                # Parent owns the tree even if old production flags hang at real open.
                try:
                    result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--fifo-child", directory, scenario],
                        env=dict(os.environ, AUTORE_BUNDLE_HELPER=str(MODULE)), capture_output=True, text=True,
                        timeout=subprocess_timeout(3))
                except subprocess.TimeoutExpired as error:
                    output = error.stdout or b""
                    self.assertIn(b"reached_real_open", output, "child did not reach the replacement open")
                    self.fail(f"{scenario}: reached_real_open then hung for {subprocess_timeout(3)} seconds")
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("reached_real_open", result.stdout)
                self.assertIn('"status": "controlled_rejection"', result.stdout)
                self.assertIn("not a direct regular file", result.stderr)
                self.assertNotIn("Traceback", result.stderr)
                print(result.stdout.strip())

    def test_open_ownership_closes_once_on_success_fstat_fdopen_and_read_failure(self):
        for failure in (None, "fstat", "fdopen", "read"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = root / "source.json"
                source.write_bytes(b'{}')
                real_open, real_close = bundle.os.open, bundle.os.close
                opened, closed = [], []
                def track_open(*args, **kwargs):
                    fd = real_open(*args, **kwargs)
                    opened.append(fd)
                    return fd
                def track_close(fd):
                    closed.append(fd)
                    return real_close(fd)
                with patch.object(bundle.os, "open", side_effect=track_open), patch.object(bundle.os, "close", side_effect=track_close):
                    if failure in ("fstat", "fdopen"):
                        owner = bundle.os
                        with patch.object(owner, failure, side_effect=OSError(failure)):
                            with self.assertRaisesRegex(OSError, failure):
                                bundle.open_regular_file_stably(source, root, "source")
                        self.assertEqual(closed, opened)
                    elif failure == "read":
                        with patch.object(bundle, "_read_bounded_control_bytes", side_effect=OSError("read")):
                            with self.assertRaisesRegex(bundle.ValidationError, "read"):
                                bundle.read_json_object_stably(source, root, "source")
                        self.assertEqual(closed, []) # Ownership transferred to file object.
                    else:
                        handle, _ = bundle.open_regular_file_stably(source, root, "source")
                        self.assertEqual(handle.read(), b'{}')
                        handle.close()
                        self.assertEqual(closed, [])
                self.assertEqual(len(opened), 1)
                with self.assertRaises(OSError): os.fstat(opened[0])

    @unittest.skipIf(os.name == "nt", "POSIX replacement identities")
    def test_replacement_regular_symlink_directory_and_initial_fifo(self):
        for kind in ("regular", "symlink", "directory", "initial_fifo"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source, original = root / "source", root / "original"
                source.write_bytes(b'{}')
                if kind == "initial_fifo":
                    if not hasattr(os, "mkfifo"): continue
                    source.unlink()
                    os.mkfifo(source)
                real_open = bundle.os.open
                def replace(path, flags, *args, **kwargs):
                    source.rename(original)
                    if kind == "regular": source.write_bytes(b'{}')
                    elif kind == "symlink": source.symlink_to(original)
                    else: source.mkdir()
                    return real_open(path, flags, *args, **kwargs)
                with patch.object(bundle.os, "open", side_effect=replace) as opened:
                    with self.assertRaises(bundle.ValidationError):
                        bundle.read_json_object_stably(source, root, "source")
                if kind == "initial_fifo": opened.assert_not_called()
                else:
                    self.assertEqual(original.read_bytes(), b'{}')
                    self.assertTrue(source.exists())


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--fifo-child":
        raise SystemExit(fifo_child(Path(sys.argv[2]), sys.argv[3]))
    unittest.main()
