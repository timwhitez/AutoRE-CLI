"""Lossless opt-in context projection; original evidence remains authoritative."""
import copy
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'skills/auto-re/scripts/compact_result.py'
spec = importlib.util.spec_from_file_location('compact_result', SCRIPT)
compact = importlib.util.module_from_spec(spec)
spec.loader.exec_module(compact)


class CompactResultTests(unittest.TestCase):
    def result(self):
        fixture = json.loads((ROOT/'tests/fixtures/result_contract_0_1_10.json').read_bytes())
        full = copy.deepcopy(next(c['result'] for c in fixture['cases'] if c['command']=='report' and 'derived_from' not in c))
        full['functions'] = full['functions'] * 32
        full['summary']['function_count'] = len(full['functions'])
        return full

    def source(self, full):
        raw = compact.encoded(full)
        return {'path': 'full.json', 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}

    def test_material_view_is_lossless_and_c1_rejects_it(self):
        full = self.result(); original = copy.deepcopy(full)
        view = compact.project(full, self.source(full))
        self.assertEqual(view['kind'], 'auto_re_compact_ai_view')
        self.assertEqual(view['compact_version'], 1)
        self.assertEqual(compact.expand_view(view), full)
        self.assertEqual(full, original)
        self.assertEqual(view['summary'], full['summary'])
        self.assertEqual(view['next_actions'], full['next_actions'])
        self.assertLessEqual(len(compact.encoded(view)), len(compact.encoded(full)) * .9)
        self.assertGreaterEqual(len(compact.encoded(full))-len(compact.encoded(view)), 1024)
        with self.assertRaisesRegex(compact.reader.runner.ActionError, '^unsupported_result_kind'):
            compact.reader.runner.validate_result_contract(view)

    def test_small_and_large_string_fallback_keep_every_field(self):
        full = self.result(); full['functions'] = full['functions'][:1]
        for text in ('small', 'é'*100000):
            full['functions'][0]['pseudo'] = text
            self.assertEqual(compact.project(full, self.source(full)), full)

    def test_nested_hint_uncertainty_and_unknown_pass_status_survive(self):
        full = self.result()
        states = [{'field': 'source_semantics', 'state': 'unresolved', 'unresolved_reason': 'hint_not_source_ast'}]*8
        for i, function in enumerate(full['functions']):
            function = copy.deepcopy(function); function['address'] += i
            function['variable_hints'] = {'abi': 'x86_64_win64', 'hints': [
                {'name': 'slot_'+str(i), 'source_addresses': [i], 'field_states': states}]}
            function['hlil_passes'].append({'name': 'future', 'status': 'future', 'note': 'unknown'})
            full['functions'][i] = function
        view = compact.project(full, self.source(full))
        self.assertEqual(compact.expand_view(view), full)
        pointer = compact.support_pointer(view, '/functions/1/variable_hints/hints/0/field_states/0/state')
        self.assertEqual(compact.reader.select_value(view, compact.reader.pointer_tokens(pointer))[0], 'unresolved')

    def test_reserved_fields_and_refs_fail_closed(self):
        full = self.result()
        for field in ('catalog', 'full_view', 'compact_version'):
            with self.assertRaisesRegex(ValueError, 'compact_field_collision'):
                compact.project({**full, field: []}, self.source(full))
        full['functions'][0]['semantic_summary'] = {'$agent_ref': 0}
        with self.assertRaisesRegex(ValueError, 'reserved_reference'):
            compact.project(full, self.source(full))

    def test_real_outputs_complete_round_trip(self):
        fixture = json.loads(gzip.decompress((ROOT/'tests/fixtures/compact_ai_v1.json.gz').read_bytes()))
        self.assertEqual(fixture['kind'], 'auto_re_compact_ai_fixtures')
        for case in fixture['cases']:
            with self.subTest(case=case['id']):
                full = case['result']
                self.assertEqual(hashlib.sha256(compact.encoded(full)).hexdigest(), case['normalized_sha256'])
                compact.reader.runner.validate_result_contract(full)
                view = compact.project(full, self.source(full))
                self.assertEqual(view['kind'], compact.KIND)
                self.assertEqual(compact.expand_view(view), full)
                with self.assertRaisesRegex(compact.reader.runner.ActionError, '^unsupported_result_kind'):
                    compact.reader.runner.validate_result_contract(view)

    def test_versions_and_profiles_fail_closed(self):
        full = self.result()
        for changed in ({'schema_version': '0.2.0'}, {'profile': 'full'}, {'kind': 'future'}):
            with self.assertRaises(ValueError): compact.project({**full, **changed}, self.source(full))
        view = compact.project(full, self.source(full)); view['compact_version'] = 2
        with self.assertRaisesRegex(ValueError, 'unsupported_compact_version'): compact.expand_view(view)

    def test_cli_hash_binding_and_read_only_input(self):
        full = self.result()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'full.json'; raw=compact.encoded(full); path.write_bytes(raw)
            argv=[sys.executable, '-B', str(SCRIPT), str(path), '--expected-sha256', hashlib.sha256(raw).hexdigest()]
            result=subprocess.run(argv, capture_output=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            view=json.loads(result.stdout)
            self.assertEqual(view['full_view']['sha256'], hashlib.sha256(raw).hexdigest())
            self.assertEqual(compact.expand_view(view), full)
            self.assertEqual(path.read_bytes(),raw)
            wrong=subprocess.run([*argv[:-1], '0'*64], capture_output=True, timeout=15)
            self.assertEqual(wrong.returncode, 1)
            self.assertEqual(json.loads(wrong.stderr)['error'], 'source_changed')
            self.assertFalse(wrong.stdout)


if __name__ == '__main__': unittest.main()
