"""Read-only views preserve exact JSON evidence and bounded, hash-bound pages."""
import hashlib
import importlib.util
import json
import os
import stat
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'skills/auto-re/scripts/read_result.py'


class ReadResultTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='autore-read-result-')
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.path = self.root / 'analysis.json'

    def write(self, value):
        data = json.dumps(value, ensure_ascii=False).encode('utf-8')
        self.path.write_bytes(data)
        return hashlib.sha256(data).hexdigest()

    def run_helper(self, pointer='', *args, ok=True):
        before = sorted(str(p.relative_to(self.root)) for p in self.root.rglob('*'))
        original = self.path.read_bytes() if self.path.exists() and stat.S_ISREG(self.path.lstat().st_mode) else None
        p = subprocess.run([sys.executable, '-B', str(SCRIPT), str(self.path), '--pointer', pointer, *args],
                           capture_output=True, cwd=self.root, timeout=5)
        self.assertEqual(p.returncode, 0 if ok else 1, p.stderr.decode(errors='replace'))
        self.assertFalse(p.stderr if ok else p.stdout)
        stream = p.stdout if ok else p.stderr
        self.assertLessEqual(len(stream), 16 * 1024)
        result = json.loads(stream)
        self.assertEqual(result['ok'], ok)
        if not ok:
            self.assertNotIn('data', result)
        self.assertEqual(before, sorted(str(p.relative_to(self.root)) for p in self.root.rglob('*')))
        if original is not None:
            self.assertEqual(self.path.read_bytes(), original)
        return result

    def test_pointer_exact_values(self):
        self.write({'': None, 'a/b': {'~1': [1, 2]}, '中文': {'01': {}}, 'empty': []})
        for pointer, value in [('/', None), ('/a~1b/~01/0', 1), ('/中文/01', {}), ('/empty', [])]:
            with self.subTest(pointer=pointer):
                self.assertEqual(self.run_helper(pointer)['data'], value)
        for pointer in ['/missing', '/empty/01', '/empty/-', '/a~2b', '#/empty', '/empty/٠']:
            with self.subTest(pointer=pointer):
                self.run_helper(pointer, ok=False)

    def test_scalar_usage_and_bounds(self):
        digest = self.write({'n': None, 'items': [1, 2]})
        for pointer, args in [('/n', ['--limit', '2']), ('/n', ['--offset', '1', '--expected-sha256', digest]),
                              ('/items', ['--offset', '3', '--expected-sha256', digest]),
                              ('/items', ['--offset', '1']), ('', ['--offset', '-1']), ('', ['--limit', '257'])]:
            with self.subTest(pointer=pointer, args=args):
                self.run_helper(pointer, *args, ok=False)
        terminal = self.run_helper('/items', '--offset', '2', '--expected-sha256', digest)
        self.assertEqual(terminal['data'], [])
        self.assertFalse(terminal['selection']['has_more'])
        self.assertNotIn('next_offset', terminal['selection'])

    def test_pages_follow_actual_next_offset_without_gaps(self):
        items = [{'i': i, 'text': '证据' * 300} for i in range(40)]
        digest = self.write({'items': items, 'unrelated': 'x' * 100000})
        first = self.run_helper('/items', '--limit', '32')
        self.assertLess(first['selection']['returned_items'], 32)
        collected = first['data'][:]
        page = first
        while page['selection']['has_more']:
            offset = page['selection']['next_offset']
            self.assertEqual(offset, len(collected))
            page = self.run_helper('/items', '--offset', str(offset), '--expected-sha256', digest)
            collected.extend(page['data'])
        self.assertEqual(collected, items)
        self.assertEqual(page['analysis_completeness'], 'not_evaluated')
        self.assertNotIn('analysis_complete', page)

    def test_changed_source_same_size_rejects_continuation(self):
        digest = self.write({'items': [1, 2]})
        self.write({'items': [1, 3]})
        result = self.run_helper('/items', '--offset', '1', '--expected-sha256', digest, ok=False)
        self.assertEqual(result['error'], 'source_changed')
        self.run_helper('/items', '--expected-sha256', 'A' * 64, ok=False)

    def test_boundaries_capture_ancestors_and_summary_only(self):
        document = {'schema_version': '0.1.0', 'kind': 'unknown_wrapper', 'warnings': ['root'],
                    'summary': {'completion': {'truncated': True}, 'unrelated': 7},
                    'function': {'status': 'unresolved', 'budget': {'limit': 1},
                                 'items': [{'next_actions': [{'argv': ['never-run']}] }]},
                    'other': {'warnings': ['unrelated']}}
        self.write(document)
        result = self.run_helper('/function/items')
        self.assertEqual(result['kind'], 'auto_re_artifact_view')
        self.assertNotIn('schema_version', result)
        self.assertEqual(result['source']['schema_version'], '0.1.0')
        boundaries = {row['pointer']: row['value'] for row in result['source_boundaries']}
        self.assertEqual(boundaries, {'/warnings': ['root'], '/summary/completion': {'truncated': True},
                                      '/function/status': 'unresolved', '/function/budget': {'limit': 1}})
        self.assertTrue(result['boundary_capture_complete'])
        self.assertNotIn('next_actions', result)
        self.assertEqual(result['data'], document['function']['items'])

    def test_envelope_and_large_first_value_fail_without_skipping(self):
        for value, expected in [({'items': ['中' * 6000, 1]}, 'value_too_large'),
                                ({'items': [], 'warnings': ['中' * 6000]}, 'boundary_too_large'),
                                ({'items': 'x' * 20000}, 'value_too_large')]:
            self.write(value)
            result = self.run_helper('/items', ok=False)
            self.assertEqual(result['error'], expected)
            self.assertNotIn('next_offset', result)

    def test_malformed_json_is_bounded_domain_error(self):
        for data in [b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}', b'{"a":1e999}',
                     b'{"a":"\\ud800"}', b'{"\\udfff":1}', b'{"a":' + b'9' * 5000 + b'}',
                     b'{"a":' + b'[' * 80 + b'0' + b']' * 80 + b'}', b'[]', b'\xff', b'{']:
            with self.subTest(data=data[:30]):
                self.path.write_bytes(data)
                self.run_helper('', ok=False)

    def test_missing_verified_copy_never_uses_source_path(self):
        self.write({'source_path': str(self.root / 'another.json')})
        self.path.unlink()
        self.run_helper('', ok=False)
        self.assertFalse((self.root / 'another.json').exists())

    @unittest.skipUnless(os.name == 'posix', 'POSIX symlink fixture')
    def test_link_and_special_file_rejected(self):
        source = self.root / 'real.json'
        source.write_text('{}')
        self.path.symlink_to(source)
        self.run_helper('', ok=False)
        self.path.unlink()
        os.mkfifo(self.path)
        self.run_helper('', ok=False)

    @unittest.skipUnless(os.name == 'posix', 'POSIX symlink fixture')
    def test_link_before_dotdot_is_not_normalized_to_another_source(self):
        self.write({'source': 'A'})
        (self.root / 'real/deep').mkdir(parents=True)
        (self.root / 'real/analysis.json').write_text('{"source":"B"}')
        (self.root / 'link').symlink_to(self.root / 'real/deep')
        for path, code in [(self.root / 'link/../analysis.json', 1),
                           (self.root / 'real/deep/../analysis.json', 0)]:
            p = subprocess.run([sys.executable, '-B', str(SCRIPT), str(path), '--pointer', '/source'],
                               capture_output=True, timeout=5)
            self.assertEqual(p.returncode, code)
            if not code:
                self.assertEqual(json.loads(p.stdout)['data'], 'B')

    def test_input_limit_pointer_limit_and_bad_digest_before_open(self):
        self.write({})
        self.run_helper('/' + '中' * 400, ok=False)
        with self.path.open('wb') as handle:
            handle.truncate(64 * 1024 * 1024 + 1)
        p = subprocess.run([sys.executable, '-B', str(SCRIPT), str(self.path), '--pointer', ''], capture_output=True, timeout=5)
        self.assertEqual(json.loads(p.stderr)['error'], 'input_too_large')
        self.path.unlink()
        self.assertEqual(self.run_helper('', '--expected-sha256', 'bad', ok=False)['error'], 'invalid_expected_sha256')

    def test_help_and_syntax_remain_argparse(self):
        for args, code in [(['--help'], 0), ([], 2), ([str(self.path)], 2),
                           ([str(self.path), '--pointer', '', '--output', 'new'], 2)]:
            p = subprocess.run([sys.executable, '-B', str(SCRIPT), *args], capture_output=True, cwd=self.root, timeout=5)
            self.assertEqual(p.returncode, code)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_existing_serializer_fixture_and_continuation_rejection(self):
        document = json.loads((ROOT / 'tests/fixtures/data_xrefs_contract.json').read_text())
        self.write(document)
        result = self.run_helper('/records')
        self.assertEqual(result['data'], document['records'])
        runner_spec = importlib.util.spec_from_file_location('read_view_runner', SCRIPT.with_name('run_next_action.py'))
        runner = importlib.util.module_from_spec(runner_spec)
        runner_spec.loader.exec_module(runner)
        with self.assertRaises(runner.ActionError):
            runner.validate_result_contract(result)

    def test_source_change_during_read_and_handle_closed(self):
        spec = importlib.util.spec_from_file_location('read_view', SCRIPT)
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        self.write({'items': [1]})
        original_read = helper.runner._read_bounded_control_bytes
        handles = []
        def mutate(handle, policy):
            handles.append(handle)
            data = original_read(handle, policy)
            self.path.write_bytes(data.replace(b'1', b'2'))
            os.utime(self.path, ns=(1, 1))
            return data
        with patch.object(helper.runner, '_read_bounded_control_bytes', side_effect=mutate):
            with self.assertRaises(helper.ViewError):
                helper.read_source(self.path, None)
        self.assertTrue(handles[0].closed)

    def test_local_modules_ignore_cwd_and_write_no_bytecode(self):
        self.write({'items': []})
        for module in ['verify_bundle', 'run_next_action', 'process_control']:
            (self.root / (module + '.py')).write_text('raise RuntimeError("CWD module injected")')
        self.run_helper('/items')
        self.assertFalse(any(self.root.rglob('*.pyc')))
        self.assertFalse(any(SCRIPT.parent.rglob('*.pyc')))
