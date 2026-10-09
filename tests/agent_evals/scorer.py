#!/usr/bin/env python3
"""Score atomic factual claims against independent truth and hash-bound JSON evidence."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import re
import stat
import sys

MAX_RECORD_BYTES = 1024 * 1024
MAX_ARTIFACT_BYTES = 4 * MAX_RECORD_BYTES


class EvalError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise EvalError('invalid_eval_record:' + message)


def local_module(name):
    spec = importlib.util.spec_from_file_location('agent_eval_' + name, Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def strict_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate_key')
            result[key] = value
        return result
    def constant(_):
        raise EvalError('invalid_eval_record:non_finite_number')
    try:
        value = json.loads(data.decode('utf-8'), object_pairs_hook=pairs, parse_constant=constant)
        stack = [(value, 0)]
        count = 0
        while stack:
            item, depth = stack.pop(); count += 1
            require(depth <= 32 and count <= 50000, 'shape_limit')
            if isinstance(item, str):
                item.encode('utf-8')
                require('\ufffd' not in item, 'replacement_character')
            elif isinstance(item, float): require(math.isfinite(item), 'non_finite_number')
            elif isinstance(item, dict): stack.extend((v, depth + 1) for v in [*item.keys(), *item.values()])
            elif isinstance(item, list): stack.extend((v, depth + 1) for v in item)
        return value
    except (ValueError, RecursionError) as error:
        raise EvalError('invalid_eval_record:invalid_json') from error


def read_json(path, limit=MAX_RECORD_BYTES):
    try:
        require(stat.S_ISREG(Path(path).lstat().st_mode), 'regular_file_required')
        with Path(path).open('rb') as handle:
            data = handle.read(limit + 1)
        require(len(data) <= limit, 'size_limit')
        return strict_json(data)
    except OSError as error:
        raise EvalError('invalid_eval_record:unreadable') from error


def load_cases():
    cases = read_json(Path(__file__).with_name('cases.json'))
    require(cases.get('kind') == 'auto_re_agent_task_cases' and type(cases.get('schema_version')) is int
            and cases['schema_version'] == 1, 'case_identity')
    return cases


def expected_value(fact):
    value = fact['value']
    if fact.get('value_encoding') == 'repeat':
        return value['repeat'] * value['count']
    return value


def equal(left, right):
    # JSON booleans must never compare equal to integers.
    if type(left) is not type(right): return False
    if isinstance(left, list): return len(left) == len(right) and all(equal(a, b) for a, b in zip(left, right))
    if isinstance(left, dict): return left.keys() == right.keys() and all(equal(left[k], right[k]) for k in left)
    return left == right


def pointer_value(value, pointer):
    require(isinstance(pointer, str) and (pointer == '' or pointer.startswith('/'))
            and re.search(r'~(?:[^01]|$)', pointer) is None, 'pointer')
    for raw in pointer.split('/')[1:] if pointer else []:
        key = raw.replace('~1', '/').replace('~0', '~')
        if isinstance(value, list):
            require(re.fullmatch(r'0|[1-9][0-9]*', key) is not None, 'array_index')
            value = value[int(key)]
        else: value = value[key]
    return value


def supported(fact, claim, root):
    for ref in claim['evidence']:
        support = fact['support']
        if ref['artifact'] != support['artifact'] or ref['pointer'] != support['pointer']: continue
        try:
            path = (root / ref['artifact']).resolve()
            path.relative_to(root.resolve())
            if not stat.S_ISREG(path.lstat().st_mode): continue
            with path.open('rb') as handle: data = handle.read(MAX_ARTIFACT_BYTES + 1)
            if len(data) > MAX_ARTIFACT_BYTES or hashlib.sha256(data).hexdigest() != ref['sha256']: continue
            observed = pointer_value(strict_json(data), ref['pointer'])
            if equal(observed, claim['value']): return True
        except (OSError, ValueError, KeyError, IndexError, TypeError):
            continue
    return False


def text(value):
    return isinstance(value, str) and bool(value.strip())


def counter(value):
    return type(value) is int and 0 <= value <= 2**63 - 1


def duration(value):
    return type(value) in (int, float) and 0 <= value <= 2**63 - 1 and math.isfinite(value)


def validate_run(case, run):
    require(isinstance(run, dict), 'run_object')
    require(run.get('case_id') == case['id'] and run.get('phase') == case['phase'], 'case_or_phase')
    require(type(run.get('completed')) is bool, 'completed')
    claims = run.get('claims'); boundaries = run.get('boundaries'); calls = run.get('calls')
    require(isinstance(claims, list) and isinstance(boundaries, list) and all(text(b) for b in boundaries), 'claims_or_boundaries')
    require(len(set(boundaries)) == len(boundaries), 'duplicate_boundary')
    for claim in claims:
        require(isinstance(claim, dict) and set(claim) == {'fact', 'value', 'polarity', 'evidence'}
                and text(claim['fact']) and type(claim['polarity']) is bool
                and isinstance(claim['evidence'], list), 'claim')
        for ref in claim['evidence']:
            require(isinstance(ref, dict) and set(ref) == {'artifact', 'sha256', 'pointer'}
                    and text(ref['artifact']) and isinstance(ref['sha256'], str)
                    and isinstance(ref['pointer'], str), 'evidence')
    require(isinstance(calls, list), 'calls')
    for call in calls:
        require(isinstance(call, dict) and isinstance(call.get('argv'), list) and bool(call['argv'])
                and all(text(a) for a in call['argv']) and call.get('role') in ('analysis', 'retrieval', 'help', 'admission')
                and type(call.get('valid')) is bool and type(call.get('exit_code')) is int
                and all(counter(call.get(k)) for k in ('stdout_bytes', 'stderr_bytes'))
                and duration(call.get('latency_ms'))
                and (text(call.get('request_id')) if call['role'] == 'analysis' else call.get('request_id') is None), 'call')
    provenance = run.get('provenance')
    require(isinstance(provenance, dict) and provenance.get('mode') in ('reference', 'agent')
            and text(provenance.get('prompt')) and isinstance(provenance.get('tools'), list)
            and bool(provenance['tools']) and all(text(t) for t in provenance['tools'])
            and isinstance(provenance.get('inputs'), dict) and bool(provenance['inputs'])
            and all(text(k) and isinstance(v, str) and re.fullmatch('[0-9a-f]{64}', v)
                    for k, v in provenance['inputs'].items())
            and counter(provenance.get('repetitions')) and provenance['repetitions'] > 0
            and isinstance(provenance.get('candidate_revision'), str)
            and re.fullmatch('[0-9a-f]{40}', provenance['candidate_revision']), 'provenance')
    if provenance['mode'] == 'agent':
        require(all(text(provenance.get(k)) for k in ('model', 'version', 'transcript')), 'agent_provenance')
    else: require(all(provenance.get(k) is None for k in ('model', 'version')), 'reference_provenance')
    usage = run.get('usage'); resources = run.get('resources')
    require(isinstance(usage, dict) and usage.get('unit') in ('tokens', 'utf8_bytes')
            and counter(usage.get('input')) and counter(usage.get('output')) and text(usage.get('method')), 'usage')
    require(isinstance(resources, dict) and 'peak_rss_bytes' in resources and 'cpu_ms' in resources
            and (resources['peak_rss_bytes'] is None or counter(resources['peak_rss_bytes']))
            and (resources['cpu_ms'] is None or duration(resources['cpu_ms']))
            and text(resources.get('reason')), 'resources')


def costs(calls):
    analyses = [c['request_id'] for c in calls if c['role'] == 'analysis']
    return {'calls': len(calls), 'invalid_calls': sum(not c['valid'] for c in calls),
            'analysis_calls': len(analyses), 'repeated_analysis': len(analyses) - len(set(analyses)),
            'retrieval_calls': sum(c['role'] == 'retrieval' for c in calls),
            'response_bytes': sum(c['stdout_bytes'] + c['stderr_bytes'] for c in calls),
            'latency_ms': round(sum(c['latency_ms'] for c in calls), 3)}


def score_run(case, run, root):
    validate_run(case, run)
    facts = {f['id']: f for f in case['facts']}
    credited = set(); seen = set(); failures = []
    for claim in run['claims']:
        name = claim['fact']; fact = facts.get(name)
        if name in seen: failures.append('duplicate_claim:' + name)
        seen.add(name)
        if fact is None: failures.append('unsupported_claim:' + name)
        elif claim['polarity'] is not True or not equal(claim['value'], expected_value(fact)):
            failures.append('incorrect_claim:' + name)
        elif not supported(fact, claim, Path(root)): failures.append('unsupported_evidence:' + name)
        else: credited.add(name)
    failures.extend('missing_fact:' + name for name in facts if name not in credited)
    failures.extend('omitted_boundary:' + name for name in case['boundaries'] if name not in run['boundaries'])
    failures.extend('unknown_boundary:' + name for name in run['boundaries'] if name not in case['boundaries'])
    measured = costs(run['calls'])
    if measured['invalid_calls']: failures.append('invalid_calls')
    if case['phase'] == 'retained' and measured['analysis_calls']: failures.append('retained_reanalysis')
    if case['id'] in ('direct_narrow', 'known_function'):
        if measured['analysis_calls'] != 1 or measured['calls'] != 1: failures.append('direct_call_plan')
    if case['id'] == 'unfamiliar_parameters' and any(c['role'] != 'help' for c in run['calls']):
        failures.append('help_task_analysis')
    if case['id'] == 'corrupted_artifact' and (measured['calls'] != 1 or measured['retrieval_calls'] != 1
            or run['calls'][0]['exit_code'] == 0): failures.append('corrupt_stop_plan')
    return {'case_id': case['id'], 'phase': case['phase'],
            'completed': run['completed'] and not failures,
            'correctness': len(credited) / len(facts) if facts else 0,
            'correct_claims': len(credited), 'required_facts': len(facts),
            'failures': failures, 'costs': measured}


def score_records(records, root):
    require(isinstance(records, dict) and records.get('kind') == 'auto_re_agent_task_results'
            and type(records.get('schema_version')) is int and records['schema_version'] == 1
            and isinstance(records.get('runs'), list) and bool(records['runs']), 'root_identity')
    cases = {c['id']: c for c in load_cases()['cases']}
    results = []
    for run in records['runs']:
        require(isinstance(run, dict) and isinstance(run.get('case_id'), str) and run['case_id'] in cases, 'unknown_case')
        results.append(score_run(cases[run['case_id']], run, root))
    return {'kind': 'auto_re_agent_task_scores', 'schema_version': 1, 'scores': results,
            'completed': sum(s['completed'] for s in results), 'runs': len(results)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('records', type=Path)
    parser.add_argument('--evidence-root', type=Path, required=True)
    args = parser.parse_args()
    try:
        result = score_records(read_json(args.records), args.evidence_root)
    except (EvalError, KeyError, TypeError) as error:
        print(json.dumps({'ok': False, 'reason': 'invalid_eval_record', 'detail': str(error)}), file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, allow_nan=False, indent=2))
    return 0 if result['completed'] == result['runs'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
