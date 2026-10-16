"""Bundle control-file/writer regressions. Payloads are inert fixture data."""
from __future__ import annotations
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

subprocess_timeout = runpy.run_path(str(Path(__file__).with_name("subprocess_timeout.py")))["subprocess_timeout"]

ROOT = Path(__file__).resolve().parents[1]
MODULE = Path(os.environ.get("AUTORE_BUNDLE_HELPER", ROOT / "skills/auto-re/scripts/verify_bundle.py"))
SPEC = importlib.util.spec_from_file_location("bundle_boundary_helper", MODULE)
bundle = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bundle)


class BundleBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="autore-bundle-boundaries-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.output = self.root / "receipt.json"

    def write(self):
        return bundle.write_json_exclusive(self.output, {"ok": True}, label="test", max_encoded_bytes=1024)

    def test_integer_conversion_is_a_domain_error_for_all_control_policies(self):
        path = self.root / "control.json"
        for policy in (bundle.VERIFIED_BUNDLE_MANIFEST_POLICY,
                       bundle.VERIFICATION_RECEIPT_POLICY, bundle.VERIFIED_ROOT_MARKER_POLICY):
            path.write_text('{}')
            with self.subTest(policy=policy.kind), patch.object(bundle.json, "loads", side_effect=ValueError("integer conversion")):
                with self.assertRaisesRegex(bundle.ValidationError, "integer conversion"):
                    bundle.read_json_object_stably(path, self.root, "control", policy=policy)
        limit = getattr(sys, "get_int_max_str_digits", lambda: 0)()
        if limit:
            path.write_text('{"unknown":' + '7' * (limit + 1) + '}')
            with self.assertRaises(bundle.ValidationError):
                bundle.read_json_object_stably(path, self.root, "control")
        path.write_text('{"unknown": 123}')
        self.assertEqual(bundle.read_json_object_stably(path, self.root, "control"), {"unknown": 123})

    def test_bad_kind_is_rejected_before_materialization(self):
        path = self.root / "manifest.json"
        for kind in ([], {}, True, 12, None):
            path.write_text(json.dumps({"schema_version": "0.1.0", "owner": "auto-re-cli", "kind": kind}))
            with self.subTest(kind=kind), patch.object(bundle.tempfile, "mkdtemp") as mkdtemp:
                with self.assertRaises(bundle.ValidationError):
                    bundle.validate_manifest(path)
                mkdtemp.assert_not_called()

    def test_exclusive_create_collision_preserves_other_writer(self):
        original = bundle.resolve_new_output
        def collide(path, label):
            result = original(path, label)
            result.write_bytes(b"other writer")
            return result
        with patch.object(bundle, "resolve_new_output", side_effect=collide):
            with self.assertRaises(bundle.ValidationError):
                self.write()
        self.assertTrue(self.output.exists())
        self.assertEqual(self.output.read_bytes(), b"other writer")

    def test_collision_symlink_is_preserved(self):
        sentinel = self.root / "sentinel"
        sentinel.write_bytes(b"keep")
        original = bundle.resolve_new_output
        def collide(path, label):
            result = original(path, label)
            result.symlink_to(sentinel)
            return result
        with patch.object(bundle, "resolve_new_output", side_effect=collide):
            with self.assertRaises(bundle.ValidationError):
                self.write()
        self.assertTrue(self.output.is_symlink())
        self.assertEqual(sentinel.read_bytes(), b"keep")

    @unittest.skipIf(os.name == "nt", "POSIX open-file replacement")
    def test_replacement_during_write_is_not_deleted(self):
        def replace_then_fail(fd):
            self.output.rename(self.root / "owned-old")
            self.output.write_bytes(b"replacement")
            raise OSError("primary failure")
        with patch.object(bundle.os, "fsync", side_effect=replace_then_fail):
            with self.assertRaisesRegex(bundle.ValidationError, "primary failure"):
                self.write()
        self.assertTrue(self.output.exists())
        self.assertEqual(self.output.read_bytes(), b"replacement")

    @unittest.skipIf(os.name == "nt", "POSIX permission assertion")
    def test_private_permissions_apply_during_write(self):
        modes = []
        previous = os.umask(0)
        try:
            with patch.object(bundle.os, "fsync", side_effect=lambda fd: modes.append(stat.S_IMODE(os.fstat(fd).st_mode))):
                self.write()
        finally:
            os.umask(previous)
        self.assertEqual(modes, [0o600])
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o400)

    def test_owned_partial_is_removed_but_cleanup_does_not_replace_primary_error(self):
        with patch.object(bundle.os, "fsync", side_effect=OSError("primary fsync")):
            with self.assertRaisesRegex(bundle.ValidationError, "primary fsync"):
                self.write()
        self.assertFalse(self.output.exists())
        with patch.object(bundle.os, "fsync", side_effect=OSError("primary fsync")), \
             patch.object(Path, "unlink", side_effect=PermissionError("secondary cleanup")):
            with self.assertRaisesRegex(bundle.ValidationError, "primary fsync"):
                self.write()
        self.assertTrue(self.output.exists())

    def test_open_failure_has_no_delete_authority(self):
        with patch.object(bundle.os, "open", side_effect=PermissionError("denied")), \
             patch.object(Path, "unlink") as unlink:
            with self.assertRaises(bundle.ValidationError):
                self.write()
        unlink.assert_not_called()

    def test_existing_output_and_oversized_receipt_are_not_modified(self):
        self.output.write_bytes(b"existing")
        with self.assertRaises(bundle.ValidationError):
            self.write()
        self.assertEqual(self.output.read_bytes(), b"existing")
        self.output.unlink()
        with self.assertRaises(bundle.ValidationError):
            bundle.write_json_exclusive(self.output, {"large": "x" * 2000}, label="test", max_encoded_bytes=32)
        self.assertFalse(self.output.exists())

    def test_normal_bundle_materialize_receipt_and_cleanup_preserve_source(self):
        payload = self.root / "payload.json"
        content = b'{"static_fixture":true}'
        payload.write_bytes(content)
        manifest = self.root / "manifest.json"
        manifest.write_text(json.dumps({
            "schema_version": "0.1.0", "owner": "auto-re-cli", "kind": "context_bundle",
            "files": [{"path": payload.name, "ownership": "command", "bytes": len(content),
                       "sha256": hashlib.sha256(content).hexdigest()}], "next_actions": []}))
        receipt, summary = bundle.validate_manifest_to_receipt(manifest, self.output)
        verified = Path(receipt["verified_root"])
        self.addCleanup(lambda: bundle.remove_verified_root(verified) if verified.exists() else None)
        self.assertTrue(summary["ok"])
        self.assertEqual(Path(receipt["files"][0]["path"]).read_bytes(), content)
        self.assertTrue(bundle.cleanup_verified_receipt(self.output)["removed"])
        self.assertFalse(verified.exists())
        self.assertEqual(payload.read_bytes(), content)
        self.assertTrue(self.output.exists())

    def test_workspace_temp_root_survives_processes_and_restricts_cleanup(self):
        workspace = self.root / "workspace"
        workspace.mkdir()
        temp_root = workspace / "verified-copies"
        temp_root.mkdir()
        other_root = workspace / "other-temp"
        other_root.mkdir()
        sentinel = temp_root / "keep"
        sentinel.write_bytes(b"unrelated")
        payload = self.root / "payload.json"
        content = b'{"static_fixture":true}'
        payload.write_bytes(content)
        manifest = self.root / "manifest.json"
        manifest.write_text(json.dumps({
            "schema_version": "0.1.0", "owner": "auto-re-cli", "kind": "context_bundle",
            "files": [{"path": payload.name, "ownership": "command", "bytes": len(content),
                       "sha256": hashlib.sha256(content).hexdigest()}], "next_actions": []}))
        env = dict(os.environ, TMPDIR=str(temp_root), TEMP=str(temp_root), TMP=str(temp_root))
        verified = subprocess.run(
            [sys.executable, "-B", str(MODULE), str(manifest), "--receipt", str(self.output)],
            env=env, capture_output=True, text=True, timeout=subprocess_timeout())
        self.assertEqual(verified.returncode, 0, verified.stderr)
        receipt = json.loads(self.output.read_text())
        verified_root = Path(receipt["verified_root"])
        self.addCleanup(lambda: bundle.remove_verified_root(verified_root) if verified_root.exists() else None)
        self.assertEqual(verified_root.parent, temp_root)
        later_read = subprocess.run(
            [sys.executable, "-B", "-c", "import pathlib,sys; sys.stdout.buffer.write(pathlib.Path(sys.argv[1]).read_bytes())",
             receipt["files"][0]["path"]], env=env, capture_output=True, timeout=subprocess_timeout())
        self.assertEqual(later_read.returncode, 0, later_read.stderr)
        self.assertEqual(later_read.stdout, content)
        cleanup = [sys.executable, "-B", str(MODULE), "--cleanup-receipt", str(self.output)]
        mismatch = subprocess.run(cleanup, env=dict(env, TMPDIR=str(other_root), TEMP=str(other_root), TMP=str(other_root)),
                                  capture_output=True, text=True, timeout=subprocess_timeout())
        self.assertNotEqual(mismatch.returncode, 0)
        self.assertIn("outside temp root", json.loads(mismatch.stderr)["error"])
        self.assertTrue(verified_root.exists())
        matched = subprocess.run(cleanup, env=env, capture_output=True, text=True, timeout=subprocess_timeout())
        self.assertEqual(matched.returncode, 0, matched.stderr)
        self.assertTrue(json.loads(matched.stdout)["removed"])
        self.assertFalse(verified_root.exists())
        self.assertEqual(payload.read_bytes(), content)
        self.assertEqual(sentinel.read_bytes(), b"unrelated")

    def test_cli_errors_are_json_not_tracebacks(self):
        missing = self.root / "missing" / "manifest.json"
        huge = self.root / "huge.json"
        limit = getattr(sys, "get_int_max_str_digits", lambda: 4300)() or 4300
        huge.write_text('{"unknown":' + '7' * (limit + 1) + '}')
        wrong = self.root / "wrong.json"
        wrong.write_text('{"schema_version":"0.1.0","owner":"auto-re-cli","kind":[]}')
        for path in (missing, huge, wrong):
            with self.subTest(path=path.name):
                result = subprocess.run([sys.executable, "-B", str(MODULE), str(path)], capture_output=True, text=True, timeout=subprocess_timeout(10))
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")
                self.assertNotIn("Traceback", result.stderr)
                self.assertFalse(json.loads(result.stderr)["ok"])


class BundleReceiptBudgetTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="autore-receipt-budget-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.output = self.root / "receipt.json"
        self.payload = self.root / "payload.json"
        self.payload.write_bytes(b'{"inert":true}')
        self.manifest = self.root / "manifest.json"
        self.created_roots = []
        self.addCleanup(self.remove_roots)
        original = bundle.tempfile.mkdtemp
        def track_root(*args, **kwargs):
            path = original(*args, **kwargs)
            self.created_roots.append(Path(path))
            return path
        self.patches = [patch.object(bundle.tempfile, "mkdtemp", side_effect=track_root),
                        patch.object(bundle, "utc_now", return_value="2026-10-16T00:00:00Z")]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)

    def remove_roots(self):
        for root in self.created_roots:
            if root.exists():
                bundle.remove_verified_root(root)

    def write_manifest(self, completion):
        content = self.payload.read_bytes()
        self.manifest.write_text(json.dumps({
            "schema_version": "0.1.0", "owner": "auto-re-cli", "kind": "context_bundle",
            "files": [{"path": self.payload.name, "ownership": "command", "bytes": len(content),
                       "sha256": hashlib.sha256(content).hexdigest()}], "completion": completion}), encoding="utf-8")

    def round_trip(self, completion):
        self.write_manifest(completion)
        before = self.manifest.read_bytes(), self.payload.read_bytes()
        receipt, summary = bundle.validate_manifest_to_receipt(self.manifest, self.output)
        self.assertTrue(summary["ok"])
        _, loaded = bundle._read_verification_receipt(self.output)
        self.assertEqual(loaded, receipt)
        self.assertEqual(loaded["completion"], completion)
        self.assertTrue(bundle.cleanup_verified_receipt(self.output)["removed"])
        self.assertFalse(Path(receipt["verified_root"]).exists())
        self.assertEqual((self.manifest.read_bytes(), self.payload.read_bytes()), before)
        size = self.output.stat().st_size
        self.output.unlink()
        return receipt, size

    def rejected(self, completion, pattern):
        self.write_manifest(completion)
        before = self.manifest.read_bytes(), self.payload.read_bytes()
        with self.assertRaisesRegex(bundle.ValidationError, pattern):
            bundle.validate_manifest_to_receipt(self.manifest, self.output)
        self.assertFalse(self.output.exists())
        self.assertFalse(any(root.exists() for root in self.created_roots))
        self.assertEqual((self.manifest.read_bytes(), self.payload.read_bytes()), before)

    @staticmethod
    def count_values(value):
        if isinstance(value, dict):
            return 1 + sum(BundleReceiptBudgetTests.count_values(child) for child in value.values())
        if isinstance(value, list):
            return 1 + sum(BundleReceiptBudgetTests.count_values(child) for child in value)
        return 1

    def test_stop_reason_entries_writer_reader_cleanup(self):
        for count in (0, 1, 2, 1024):
            with self.subTest(count=count):
                self.round_trip({"state": "truncated", "complete": False, "truncated": True,
                                 "stop_reasons": ["function_limit"] * count})
        self.rejected({"stop_reasons": ["function_limit"] * 1025},
                      r"kind=bundle_verification_receipt dimension=container_entries limit=1024 observed_at_least=1025")

    def test_whole_wrapper_values_budget(self):
        baseline, _ = self.round_trip(None)
        # Four short arrays isolate total values from the 1024-entry ceiling.
        leaves = 4096 - self.count_values(baseline) - 4
        completion = [[0] * 1024 for _ in range(3)] + [[0] * (leaves - 3072)]
        receipt, _ = self.round_trip(completion)
        self.assertEqual(self.count_values(receipt), 4096)
        completion[-1].append(0)
        self.rejected(completion, r"dimension=values limit=4096 observed_at_least=4097")

    def test_depth_boundary_and_final_wrapper_gate(self):
        completion = 0
        for _ in range(62):
            completion = [completion]
        self.round_trip(completion)  # receipt root depth 1, completion depth 2, leaf depth 64
        self.rejected([completion], r"kind=verified_bundle_manifest dimension=depth limit=64 observed_at_least=65")
        self.assertEqual(len(self.created_roots), 1)  # input rejection did not materialize
        original = bundle.build_verification_receipt
        def deeper(result):
            receipt = original(result)
            receipt["completion"] = [completion]
            return receipt
        with patch.object(bundle, "build_verification_receipt", side_effect=deeper):
            self.rejected(None, r"kind=bundle_verification_receipt dimension=depth limit=64 observed_at_least=65")

    def test_encoded_boundary_includes_newline_unicode_and_escapes(self):
        _, baseline = self.round_trip("")
        prefix = "é漢😀\n\t\x00\"\\"
        escaped_size = len(json.dumps(prefix).encode("utf-8")) - 2
        completion = prefix + "x" * (bundle.VERIFICATION_RECEIPT_MAX_BYTES - baseline - escaped_size)
        _, size = self.round_trip(completion)
        self.assertEqual(size, bundle.VERIFICATION_RECEIPT_MAX_BYTES)
        self.rejected(completion + "x", r"receipt output exceeds limit: limit=1048576 observed=1048577")

    def test_decoded_utf8_string_and_key_limits_are_shared(self):
        limit = bundle.VERIFICATION_RECEIPT_POLICY.max_string_bytes
        for text in ("é" * (limit // 2), "😀" * (limit // 4)):
            for key in (False, True):
                with self.subTest(key=key, codepoint=ord(text[0])):
                    value = {text: 0} if key else {"completion": text}
                    # A decoded 1 MiB string cannot fit the complete encoded wrapper.
                    bundle._validate_json_shape(value, bundle.VERIFICATION_RECEIPT_POLICY)
                    too_long = text + "x"
                    original = bundle.build_verification_receipt
                    def oversized(result):
                        receipt = original(result)
                        receipt["completion"] = {too_long: 0} if key else too_long
                        return receipt
                    with patch.object(bundle, "build_verification_receipt", side_effect=oversized):
                        self.rejected(None, r"kind=bundle_verification_receipt dimension=string_bytes limit=1048576 observed_at_least=1048577")

    def test_admission_cleanup_failure_preserves_first_error_and_recovery_path(self):
        self.write_manifest({"stop_reasons": ["function_limit"] * 1025})
        with patch.object(bundle, "remove_verified_root", side_effect=OSError("cleanup denied")):
            with self.assertRaises(bundle.ValidationError) as caught:
                bundle.validate_manifest_to_receipt(self.manifest, self.output)
        self.assertIn("cleanup denied", str(caught.exception))
        self.assertIn("dimension=container_entries", str(caught.exception))
        self.assertIn(f"retained recovery path: {self.created_roots[-1]}", str(caught.exception))
        self.assertIn("dimension=container_entries", str(caught.exception.__cause__))
        self.assertTrue(self.created_roots[-1].exists())
        self.assertFalse(self.output.exists())

    def test_stdout_only_keeps_manifest_completion_budget(self):
        completion = {"stop_reasons": ["function_limit"] * 1025}
        self.write_manifest(completion)
        result = subprocess.run([sys.executable, "-B", str(MODULE), str(self.manifest)],
                                capture_output=True, text=True, timeout=subprocess_timeout())
        self.assertEqual(result.returncode, 0, result.stderr)
        document = json.loads(result.stdout)
        verified = Path(document["verified_root"])
        self.created_roots.append(verified)
        self.assertEqual(document["completion"], completion)
        self.assertTrue(verified.exists())
        self.assertFalse(self.output.exists())

if __name__ == "__main__":
    unittest.main()
