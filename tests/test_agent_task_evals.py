"""Offline atomic claim scoring: synthetic JSON only, no model or sample execution."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent / 'agent_evals'
SPEC = importlib.util.spec_from_file_location('task_eval_scorer', ROOT / 'scorer.py')
scorer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(scorer)
CASES = scorer.load_cases()


class AgentTaskEvalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.case = next(c for c in CASES['cases'] if c['id'] == 'existing_result')
        artifact = self.root / 'existing.json'
        artifact.write_text('{"function":{"address":4096}}\n', encoding='utf-8')
        evidence = {'artifact': 'existing.json', 'sha256': hashlib.sha256(artifact.read_bytes()).hexdigest(),
                    'pointer': '/function/address'}
        self.run = {'case_id': self.case['id'], 'phase': 'retained', 'completed': True,
            'claims': [{'fact': 'selected_address', 'value': 4096, 'polarity': True, 'evidence': [evidence]}],
            'boundaries': self.case['boundaries'][:], 'calls': [],
            'provenance': {'mode': 'reference', 'model': None, 'version': None, 'prompt': self.case['prompt'],
                'tools': ['read_result.py'], 'inputs': {'existing.json': evidence['sha256']},
                'repetitions': 1, 'transcript': None, 'candidate_revision': 'a' * 40},
            'usage': {'unit': 'utf8_bytes', 'input': 0, 'output': 0, 'method': 'stdout+stderr'},
            'resources': {'peak_rss_bytes': None, 'cpu_ms': None, 'reason': 'NOT_MEASURED'}}

    def score(self):
        return scorer.score_run(self.case, self.run, self.root)

    def test_positive_supported_claim(self):
        score = self.score()
        self.assertTrue(score['completed'])
        self.assertEqual(score['correctness'], 1)

    def test_negative_wrong_value_and_type(self):
        for value in (4097, '4096', True):
            with self.subTest(value=value):
                self.run['claims'][0]['value'] = value
                self.assertFalse(self.score()['completed'])
                self.assertEqual(self.score()['correctness'], 0)

    def test_negation_cannot_earn_positive_credit(self):
        self.run['claims'][0]['polarity'] = False
        self.assertEqual(self.score()['correctness'], 0)
        self.assertFalse(self.score()['completed'])

    def test_false_fact_is_a_positive_assertion_of_false(self):
        case = {'id': 'boolean', 'phase': 'retained', 'facts': [
            {'id': 'flag', 'value': False, 'support': {'artifact': 'existing.json', 'pointer': '/flag'}}],
            'boundaries': []}
        (self.root / 'existing.json').write_text('{"flag":false}')
        self.run.update(case_id='boolean', boundaries=[])
        self.run['claims'] = [{'fact': 'flag', 'value': False, 'polarity': True,
            'evidence': [{'artifact': 'existing.json', 'pointer': '/flag',
                'sha256': hashlib.sha256((self.root / 'existing.json').read_bytes()).hexdigest()}]}]
        self.assertTrue(scorer.score_run(case, self.run, self.root)['completed'])

    def test_unsupported_claim_or_irrelevant_evidence(self):
        original = copy.deepcopy(self.run)
        for change in ('extra', 'empty', 'pointer', 'hash', 'artifact', 'duplicate'):
            with self.subTest(change=change):
                self.run = copy.deepcopy(original)
                claim = self.run['claims'][0]
                if change == 'extra':
                    self.run['claims'].append({**claim, 'fact': 'network_runtime_observed'})
                elif change == 'empty': claim['evidence'] = []
                elif change == 'duplicate': self.run['claims'].append(copy.deepcopy(claim))
                else: claim['evidence'][0][change if change != 'hash' else 'sha256'] = 'unrelated'
                self.assertFalse(self.score()['completed'])
                self.assertTrue(self.score()['failures'])

    def test_omitted_boundary(self):
        self.run['boundaries'].remove('selected_scope')
        self.assertFalse(self.score()['completed'])
        self.assertIn('omitted_boundary:selected_scope', self.score()['failures'])

    def test_malformed_result_record_fails_closed(self):
        base = {'kind': 'auto_re_agent_task_results', 'schema_version': 1, 'runs': [self.run]}
        for field, value in (('kind', 'wrong'), ('schema_version', True), ('schema_version', 2), ('runs', {})):
            with self.subTest(field=field, value=value), self.assertRaisesRegex(scorer.EvalError, 'invalid_eval_record'):
                scorer.score_records({**base, field: value}, self.root)
        for field, value in (('completed', 1), ('claims', [{}]), ('calls', [{}]), ('usage', {}),
                             ('resources', {}), ('provenance', {}), ('phase', 'cold')):
            broken = copy.deepcopy(base); broken['runs'][0][field] = value
            with self.subTest(field=field), self.assertRaises(scorer.EvalError):
                scorer.score_records(broken, self.root)
        broken = copy.deepcopy(base);broken['runs'][0]['provenance'].update(mode='agent')
        with self.assertRaises(scorer.EvalError): scorer.score_records(broken, self.root)

    def test_address_alone_does_not_complete_cfg_task(self):
        case = next(c for c in CASES['cases'] if c['id'] == 'direct_narrow')
        path = self.root / 'cfg.json'
        path.write_text('{"function":{"address":4096}}')
        self.run.update(case_id=case['id'], phase='cold', boundaries=case['boundaries'][:])
        self.run['claims'] = [{'fact': 'selected_address', 'value': 4096, 'polarity': True,
            'evidence': [{'artifact': 'cfg.json', 'pointer': '/function/address',
                          'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}]}]
        self.run['calls'] = [{'argv': ['auto-re-cli', 'dump-cfg', 'ret.bin'], 'role': 'analysis',
            'valid': True, 'exit_code': 0, 'stdout_bytes': 0, 'stderr_bytes': 0,
            'latency_ms': 1, 'request_id': 'controlled-cfg'}]
        self.assertFalse(scorer.score_run(case, self.run, self.root)['completed'])

    def test_enormous_latency_is_a_typed_malformed_record(self):
        self.run['calls'] = [{'argv': ['reader'], 'role': 'retrieval', 'valid': True,
            'exit_code': 0, 'stdout_bytes': 0, 'stderr_bytes': 0,
            'latency_ms': 2**2048, 'request_id': None}]
        with self.assertRaisesRegex(scorer.EvalError, 'invalid_eval_record'):
            self.score()

    def test_duplicate_analysis_costs_and_retained_constraint(self):
        call = {'argv': ['auto-re-cli', 'function', 'ret.bin'], 'role': 'analysis', 'valid': True,
                'exit_code': 0, 'stdout_bytes': 20, 'stderr_bytes': 2, 'latency_ms': 1.5,
                'request_id': 'same-input-selector-budget'}
        self.run['calls'] = [call, copy.deepcopy(call), {**call, 'role': 'retrieval', 'request_id': None, 'valid': False}]
        score = self.score()
        self.assertEqual(score['costs']['calls'], 3)
        self.assertEqual(score['costs']['repeated_analysis'], 1)
        self.assertEqual(score['costs']['retrieval_calls'], 1)
        self.assertEqual(score['costs']['invalid_calls'], 1)
        self.assertEqual(score['costs']['response_bytes'], 66)
        self.assertFalse(score['completed'])

    def test_evidence_escape_and_missing_file(self):
        for name in ('../existing.json', '/existing.json', 'missing.json'):
            self.run['claims'][0]['evidence'][0]['artifact'] = name
            self.assertFalse(self.score()['completed'])

    def test_strict_json_and_size(self):
        path = self.root / 'record.json'
        for text in ('{"x":1,"x":2}', '{"x":NaN}', '{"x":"\\ud800"}'):
            path.write_text(text)
            with self.assertRaises(scorer.EvalError): scorer.read_json(path)
        path.write_bytes(b' ' * (scorer.MAX_RECORD_BYTES + 1))
        with self.assertRaises(scorer.EvalError): scorer.read_json(path)

    def test_archived_baseline_has_all_cases_and_negative_controls(self):
        baseline = scorer.read_json(ROOT / 'baseline.json')
        self.assertEqual(baseline['kind'], 'auto_re_agent_task_baseline')
        self.assertEqual(baseline['cases_sha256'], hashlib.sha256((ROOT / 'cases.json').read_bytes()).hexdigest())
        self.assertEqual(baseline['scores']['completed'], 7)
        self.assertEqual(len(baseline['records']['runs']), 7)
        for case, run in zip(CASES['cases'], baseline['records']['runs']):
            scorer.validate_run(case, run)
            self.assertTrue(all(c['polarity'] is True for c in run['claims']))
        comparisons = baseline['comparisons']
        self.assertEqual([(c['issue'], c['side']) for c in comparisons],
                         [(i, s) for i in ('40', '41', '42') for s in ('before', 'after')])
        for row in comparisons:
            self.assertEqual(row['outcome']['evidence_obtainable'], row['side'] == 'after')
            if row['issue'] == '42':
                self.assertFalse(row['outcome']['wrong_kind']['accepted'])
                self.assertFalse(row['outcome']['unknown_version']['accepted'])

    def test_fixture_truth_and_complete_case_set(self):
        fixtures = scorer.local_module('fixtures')
        fixtures.create(self.root)
        large = scorer.read_json(self.root / 'large.json')
        case = next(c for c in CASES['cases'] if c['id'] == 'large_artifact')
        self.assertEqual(large['function']['pseudo'], scorer.expected_value(case['facts'][0]))
        self.assertEqual(list(large['metadata']['language']), case['facts'][1]['value'])
        self.assertEqual(len(CASES['cases']), 7)
        self.assertEqual((self.root / 'ret.bin').read_bytes().hex(), CASES['fixtures']['raw_ret']['source_hex'])
        self.assertFalse(scorer.read_json(self.root / 'knowledge.json')['partial']['completion'])
        with self.assertRaises(scorer.EvalError): scorer.read_json(self.root / 'corrupt.json')


if __name__ == '__main__':
    unittest.main()
