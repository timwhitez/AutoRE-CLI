"""Exact bounded recovery; synthetic cases preserve observed blocked task shapes."""
import hashlib
import importlib.util
import json
import subprocess
import sys
import unittest

import test_read_result as baseline_tests

SCRIPT = baseline_tests.SCRIPT

SPEC = importlib.util.spec_from_file_location('recovery_reader', SCRIPT)
reader = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(reader)


class RecoveryViewTests(unittest.TestCase):
    setUp = baseline_tests.ReadResultTests.setUp
    write = baseline_tests.ReadResultTests.write
    run_helper = baseline_tests.ReadResultTests.run_helper

    def string_pages(self, text, length=4096, escaped=False, boundaries=None):
        document = dict(boundaries or {}, text=text)
        data = json.dumps(document, ensure_ascii=escaped).encode('utf-8')
        self.path.write_bytes(data)
        digest = hashlib.sha256(data).hexdigest()
        start, fragments = 0, []
        while True:
            page = self.run_helper('/text', '--mode', 'string', '--start', str(start),
                                   '--length', str(length), '--expected-sha256', digest)
            selection = page['selection']
            self.assertEqual(page['view_schema_version'], 2)
            self.assertEqual(page['source']['sha256'], digest)
            self.assertEqual(selection['start'], start)
            self.assertEqual(selection['total_length'], len(text))
            self.assertEqual(selection['end'], start + len(page['data']))
            self.assertEqual(page['data'], text[start:selection['end']])
            self.assertEqual(page['source']['semantics'], 'not_validated')
            self.assertEqual(page['analysis_completeness'], 'not_evaluated')
            fragments.append(page['data'])
            if not selection['has_more']:
                self.assertNotIn('next_start', selection)
                break
            self.assertEqual(selection['next_start'], selection['end'])
            self.assertGreater(selection['end'], start)
            start = selection['next_start']
        self.assertEqual(''.join(fragments), text)
        return fragments

    def test_captured_blocked_tasks_and_direct_host_read(self):
        # Verified 0.1.10 static analysis of the controlled Go closure fixture:
        # runtime.findRunnable /function/pseudo has 23128 ASCII scalars; the
        # unfamiliar /metadata/language object has six keys and exceeds 16 KiB.
        # Keep generated analysis outside the repo; reproduce shapes synthetically.
        text = ('local_0 = rax;\n' * 2000)[:23128]
        document = {'function': {'name': 'runtime.findRunnable', 'pseudo': text},
                    'metadata': {'language': {f'unknown_{i}': {'text': 'x' * 10000}
                                              for i in range(6)}}}
        digest = self.write(document)
        for pointer in ['/function/pseudo', '/metadata/language']:
            self.assertEqual(self.run_helper(pointer, ok=False)['error'], 'value_too_large')
        self.assertEqual(self.run_helper('/function/pseudo', '--mode', 'string')['data'], text[:1024])
        page = self.run_helper('/metadata/language', '--mode', 'keys')
        self.assertEqual([row['name'] for row in page['data']], list(document['metadata']['language']))
        # A known small field is already usable directly from the original snapshot.
        raw = self.path.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), digest)
        self.assertEqual(json.loads(raw)['function']['name'], 'runtime.findRunnable')

    def test_strings_reconstruct_unicode_and_expanding_escapes(self):
        for text, escaped in [('ascii' * 5000, False), ('汉é😀e\u0301' * 1800, True),
                              ('\x00\n\t"\\' * 1800, False), ('', False)]:
            with self.subTest(escaped=escaped, prefix=text[:8]):
                self.string_pages(text, escaped=escaped)

    def test_escaping_shrinks_requested_range(self):
        fragments = self.string_pages('\x00' * 9000)
        self.assertGreater(len(fragments), 3)
        self.assertLess(len(fragments[0]), 4096)

    def test_keys_cover_document_order_and_pointer_round_trip(self):
        obj = {'a/b': 1, '~1': None, '': True, '汉😀': 'text', 'array': [], 'object': {}}
        obj.update({f'key{i}': i for i in range(75)})
        digest = self.write({'obj': obj, 'warnings': ['root'],
                             'summary': {'completion': {'truncated': True}}})
        offset, collected = 0, []
        while True:
            page = self.run_helper('/obj', '--mode', 'keys', '--offset', str(offset),
                                   '--limit', '7', '--expected-sha256', digest)
            selection = page['selection']
            self.assertEqual(selection['total_items'], len(obj))
            self.assertEqual(selection['returned_items'], len(page['data']))
            self.assertEqual(page['source']['sha256'], digest)
            self.assertEqual(page['view_schema_version'], 2)
            self.assertEqual({r['pointer']: r['value'] for r in page['source_boundaries']},
                             {'/warnings': ['root'], '/summary/completion': {'truncated': True}})
            for row in page['data']:
                self.assertEqual(reader.select_value({'obj': obj}, reader.pointer_tokens(row['pointer']))[0],
                                 obj[row['name']])
            collected.extend(page['data'])
            if not selection['has_more']:
                self.assertNotIn('next_offset', selection)
                break
            offset = selection['next_offset']
            self.assertEqual(offset, len(collected))
        self.assertEqual([row['name'] for row in collected], list(obj))
        self.assertEqual([row['value_type'] for row in collected[:6]],
                         ['number', 'null', 'boolean', 'string', 'array', 'object'])

    def test_keys_byte_budget_shrinks_page_without_skipping(self):
        obj = {str(i) + '汉' * 300: i for i in range(30)}
        digest = self.write({'obj': obj})
        offset, names = 0, []
        while True:
            page = self.run_helper('/obj', '--mode', 'keys', '--offset', str(offset),
                                   '--expected-sha256', digest)
            names.extend(row['name'] for row in page['data'])
            if not page['selection']['has_more']:
                break
            self.assertLess(page['selection']['returned_items'], 32)
            offset = page['selection']['next_offset']
        self.assertEqual(names, list(obj))

    def test_typed_errors_empty_ranges_and_continuation(self):
        digest = self.write({'obj': {'a': 1}, 'text': '😀', 'array': []})
        cases = [('/text', ['--mode', 'keys'], 'mode_type_mismatch'),
                 ('/obj', ['--mode', 'string'], 'mode_type_mismatch'),
                 ('/array', ['--mode', 'keys'], 'mode_type_mismatch'),
                 ('/text', ['--mode', 'string', '--offset', '0'], 'invalid_pagination'),
                 ('/text', ['--mode', 'string', '--limit', '32'], 'invalid_pagination'),
                 ('/obj', ['--mode', 'keys', '--start', '0'], 'invalid_pagination'),
                 ('/obj', ['--mode', 'keys', '--length', '1024'], 'invalid_pagination'),
                 ('/text', ['--start', '0'], 'invalid_pagination'),
                 ('/text', ['--length', '1024'], 'invalid_pagination'),
                 ('/text', ['--mode', 'string', '--start', '-1'], 'invalid_pagination'),
                 ('/obj', ['--mode', 'keys', '--offset', '-1'], 'invalid_pagination'),
                 ('/text', ['--mode', 'string', '--length', '0'], 'invalid_pagination'),
                 ('/text', ['--mode', 'string', '--length', '4097'], 'invalid_pagination'),
                 ('/obj', ['--mode', 'keys', '--limit', '0'], 'invalid_pagination'),
                 ('/obj', ['--mode', 'keys', '--limit', '257'], 'invalid_pagination')]
        for pointer, args, error in cases:
            with self.subTest(args=args):
                self.assertEqual(self.run_helper(pointer, *args, ok=False)['error'], error)
        for mode, pointer, position, next_field, empty in [('keys', '/obj', '--offset', 'next_offset', []),
                                                          ('string', '/text', '--start', 'next_start', '')]:
            self.assertEqual(self.run_helper(pointer, '--mode', mode, position, '1', ok=False)['error'],
                             'expected_sha256_required')
            terminal = self.run_helper(pointer, '--mode', mode, position, '1', '--expected-sha256', digest)
            self.assertEqual(terminal['data'], empty)
            self.assertFalse(terminal['selection']['has_more'])
            self.assertNotIn(next_field, terminal['selection'])
            self.assertEqual(self.run_helper(pointer, '--mode', mode, position, '2',
                                            '--expected-sha256', digest, ok=False)['error'], 'offset_out_of_range')
        self.write({'obj': {'b': 1}, 'text': '😃', 'array': []})
        for mode, pointer, position in [('keys', '/obj', '--offset'), ('string', '/text', '--start')]:
            self.assertEqual(self.run_helper(pointer, '--mode', mode, position, '1',
                                            '--expected-sha256', digest, ok=False)['error'], 'source_changed')

    def test_large_boundaries_keys_and_pointers_fail_closed(self):
        for mode, value in [('keys', {}), ('string', 'x')]:
            self.write({'v': value, 'warnings': ['x' * 20000]})
            self.assertEqual(self.run_helper('/v', '--mode', mode, ok=False)['error'], 'boundary_too_large')
        for key in ['x' * 20000, '~' * 600, '汉' * 400, '~' * 509 + 'aa']:
            self.write({'obj': {key: 1}})
            page = self.run_helper('/obj', '--mode', 'keys', ok=False)
            self.assertEqual(page['error'], 'value_too_large')
            self.assertLess(len(json.dumps(page)), 300)
        # A child exactly at the pointer limit remains usable, including escaping.
        key = '~' * 509 + 'a'
        self.write({'obj': {key: 1}})
        child = self.run_helper('/obj', '--mode', 'keys')['data'][0]['pointer']
        self.assertEqual(len(child.encode()), 1024)
        self.assertEqual(self.run_helper(child)['data'], 1)

    def test_malformed_json_and_pointer_errors_stay_typed(self):
        for mode in ['keys', 'string']:
            for data, expected in [(b'{"x":1,"x":2}', 'duplicate_key'),
                                   (b'{"x":"\\ud800"}', 'invalid_json_or_structure'),
                                   (b'{"\\udfff":1}', 'invalid_json_or_structure'),
                                   (b'{', 'invalid_json_or_structure')]:
                self.path.write_bytes(data)
                self.assertEqual(self.run_helper('/x', '--mode', mode, ok=False)['error'], expected)
            self.write({'x': ''})
            for pointer, expected in [('/x~2', 'invalid_pointer'), ('/missing', 'pointer_missing')]:
                self.assertEqual(self.run_helper(pointer, '--mode', mode, ok=False)['error'], expected)

    def test_v2_views_cannot_be_analysis_roots(self):
        self.write({'obj': {'next_actions': []}, 'text': 'next_actions'})
        for mode, pointer in [('keys', '/obj'), ('string', '/text')]:
            page = self.run_helper(pointer, '--mode', mode)
            with self.assertRaises(reader.runner.ActionError):
                reader.runner.validate_result_contract(page)

    def test_envelope_exact_limit_and_one_scalar_or_key_failure(self):
        source = {'sha256': 'a' * 64, 'semantics': 'not_validated'}
        for mode, value in [('string', '😀'), ('string', 'ab'), ('keys', {'a': 1})]:
            document = {'v': value, 'warnings': ''}
            build = lambda: reader.build_recovery_view(document, source, '/v', ['v'], mode, 0, len(value))
            initial = len(build())
            document['warnings'] = 'x' * (reader.MAX_OUTPUT_BYTES - initial)
            self.assertEqual(len(build()), reader.MAX_OUTPUT_BYTES)
            document['warnings'] = document['warnings'][:-1]
            self.assertEqual(len(build()), reader.MAX_OUTPUT_BYTES - 1)
            document['warnings'] += 'xx'
            with self.assertRaisesRegex(reader.ViewError, '^value_too_large$'):
                build()
            document['warnings'] += 'x' * 200
            with self.assertRaisesRegex(reader.ViewError, '^boundary_too_large$'):
                build()

    def test_value_mode_bytes_match_original(self):
        # Golden bytes from v1, with fixed source metadata and no filesystem path.
        document = {'items': [1, 2], 'warnings': ['bounded']}
        source = {'sha256': 'a' * 64, 'semantics': 'not_validated'}
        expected = (b'{"ok":true,"kind":"auto_re_artifact_view","view_schema_version":1,'
                    b'"source":{"sha256":"' + b'a' * 64 + b'","semantics":"not_validated"},'
                    b'"selection":{"pointer":"/items","value_type":"array","offset":0,'
                    b'"limit":1,"has_more":true,"total_items":2,"returned_items":1,"next_offset":1},'
                    b'"source_boundaries":[{"pointer":"/warnings","value":["bounded"]}],'
                    b'"boundary_capture_complete":true,"analysis_completeness":"not_evaluated","data":[1]}\n')
        self.assertEqual(reader.build_view(document, source, '/items', ['items'], 0, 1), expected)
        self.write(document)
        base = [sys.executable, '-B', str(SCRIPT), str(self.path), '--pointer', '/items']
        self.assertEqual(subprocess.run(base, capture_output=True).stdout,
                         subprocess.run(base + ['--mode', 'value'], capture_output=True).stdout)
