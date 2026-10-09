#!/usr/bin/env python3
"""Static-only scripted capability baseline; never invokes a model or target bytes."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def local(name):
    spec = importlib.util.spec_from_file_location('eval_reference_' + name, HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


scorer = local('scorer')
fixtures = local('fixtures')
CANDIDATES = {
    '40': 'f50615cdac586b7e1aac2a0bb0a767139458a4df',
    '41': '93f3dcae9985d4f2a0f96fe1ed318830ee6c477d',
    '42': '7e6d6065b8128f070a5330684a802ab2ed5c7093'}


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def git(root, *args):
    return subprocess.run(['git', '-C', str(root), *args], check=True, capture_output=True).stdout


def measured(argv, calls, role, request_id=None):
    start = time.monotonic()
    process = subprocess.run([str(a) for a in argv], capture_output=True, timeout=60)
    calls.append({'argv': [str(a) for a in argv], 'role': role, 'valid': True,
                  'exit_code': process.returncode, 'stdout_bytes': len(process.stdout),
                  'stderr_bytes': len(process.stderr), 'latency_ms': round((time.monotonic() - start) * 1000, 3),
                  'request_id': request_id})
    return process


def decoded(process):
    if process.returncode != 0: raise ValueError('reference_call_failed:' + process.stderr.decode('utf-8')[:256])
    return scorer.strict_json(process.stdout)


def read(scripts, artifact, pointer, calls, *options):
    argv = [sys.executable, '-B', scripts / 'read_result.py', artifact, '--pointer', pointer,
            '--expected-sha256', digest(artifact), *options]
    return measured(argv, calls, 'retrieval')


def recover(scripts, root, calls, recovery):
    artifact = root / 'large.json'
    expected = scorer.read_json(artifact)
    if not recovery:
        values = [read(scripts, artifact, p, calls) for p in ('/function/pseudo', '/metadata/language')]
        return {'evidence_obtainable': False, 'safe_failures': [scorer.strict_json(p.stderr)['error'] for p in values]}
    parts = []; start = 0
    while True:
        value = decoded(read(scripts, artifact, '/function/pseudo', calls,
                             '--mode', 'string', '--start', str(start), '--length', '4096'))
        assert value['boundary_capture_complete'] and value['analysis_completeness'] == 'not_evaluated'
        boundaries = {b['pointer']: b['value'] for b in value['source_boundaries']}
        assert boundaries['/completion'] is False and boundaries['/stop_reasons'] == ['fixture_partial']
        assert value['selection']['start'] == start
        parts.append(value['data']); end = value['selection']['end']
        if not value['selection']['has_more']: break
        assert end > start and value['selection']['next_start'] == end
        start = end
    names = []; offset = 0
    while True:
        value = decoded(read(scripts, artifact, '/metadata/language', calls,
                             '--mode', 'keys', '--offset', str(offset), '--limit', '32'))
        assert value['boundary_capture_complete']
        names.extend(item['name'] for item in value['data'])
        if not value['selection']['has_more']: break
        next_offset = value['selection']['next_offset']; assert next_offset > offset; offset = next_offset
    text = ''.join(parts)
    assert text == expected['function']['pseudo'] and names == list(expected['metadata']['language'])
    fixtures.write_json(root / 'recovered.json', {'pseudo': text, 'keys': names})
    return {'evidence_obtainable': True, 'exact_string': True, 'complete_keys': True,
            'reconstruction_sha256': hashlib.sha256(text.encode('utf-8')).hexdigest()}


def reference_cases(public, cli, root, cli_hash, revision):
    scripts = public / 'skills/auto-re/scripts'
    records = []; outcomes = {}
    for case in scorer.load_cases()['cases']:
        calls = []; name = case['id']
        if name in ('direct_narrow', 'known_function'):
            command = 'dump-cfg' if name == 'direct_narrow' else 'function'
            argv = [cli, command, root / 'ret.bin', '--raw-shellcode', '--arch', 'x86-64',
                    '--base-address', '0x1000', '--addr', '0x1000', '--format', 'json']
            process = measured(argv, calls, 'analysis', digest(root / 'ret.bin') + ':' + command + ':0x1000:default')
            value = decoded(process)
            assert value['function']['address'] == 4096
            if command == 'function': assert value['function']['warnings'] and value['function']['string_references'] == []
            (root / ('cfg.json' if command == 'dump-cfg' else 'function.json')).write_bytes(process.stdout)
        elif name == 'unfamiliar_parameters':
            process = measured([cli, 'dump-il', '--help'], calls, 'help')
            assert process.returncode == 0
            help_text = process.stdout.decode('utf-8')
            required = 'Usage: auto-re-cli dump-il [OPTIONS] --level <LEVEL> <PATH>' in help_text
            assert required
            fixtures.write_json(root / 'help.json', {'required_level': required,
                'help_sha256': hashlib.sha256(process.stdout).hexdigest()})
        elif name == 'large_artifact':
            outcomes[name] = recover(scripts, root, calls, True)
        elif name == 'absent_vs_unknown':
            for p in ('/complete', '/partial'):
                value = decoded(read(scripts, root / 'knowledge.json', p, calls))
                assert value['data']['entries'] == []
                assert value['data']['completion'] is (p == '/complete')
                assert value['boundary_capture_complete']
        elif name == 'existing_result':
            value = decoded(read(scripts, root / 'existing.json', '/function/address', calls))
            assert value['data'] == 4096
        else:
            process = read(scripts, root / 'corrupt.json', '/function/address', calls)
            reason = scorer.strict_json(process.stderr)['error']
            assert process.returncode != 0 and not process.stdout and reason == 'invalid_json_or_structure'
            fixtures.write_json(root / 'stop.json', {'stopped': True, 'reason': reason})
        claims = []
        for fact in case['facts']:
            support = fact['support']; path = root / support['artifact']
            claims.append({'fact': fact['id'], 'value': scorer.expected_value(fact), 'polarity': True,
                'evidence': [{**support, 'sha256': digest(path)}]})
        records.append({'case_id': name, 'phase': case['phase'], 'completed': True, 'claims': claims,
            'boundaries': case['boundaries'], 'calls': calls,
            'provenance': {'mode': 'reference', 'model': None, 'version': None, 'prompt': case['prompt'],
                'tools': [str(cli), str(scripts / 'read_result.py')],
                'inputs': {p: digest(root / p) for p in ('ret.bin', 'large.json', 'knowledge.json', 'existing.json', 'corrupt.json')},
                'repetitions': 1, 'transcript': 'records.json:calls', 'candidate_revision': revision},
            'usage': {'unit': 'utf8_bytes', 'input': 0,
                'output': sum(c['stdout_bytes'] + c['stderr_bytes'] for c in calls),
                'method': 'complete stdout+stderr; response-byte proxy, no model input'},
            'resources': {'peak_rss_bytes': None, 'cpu_ms': None, 'reason': 'NOT_MEASURED; response bytes measured'}})
    return {'kind': 'auto_re_agent_task_results', 'schema_version': 1, 'runs': records}, outcomes


def history_scripts(history, revision, destination):
    prefix = 'skills/auto-re/scripts/'
    paths = git(history, 'ls-tree', '-r', '--name-only', revision, '--', prefix).decode().splitlines()
    destination.mkdir()
    for path in paths:
        if path.endswith('.py'):
            (destination / Path(path).name).write_bytes(git(history, 'show', revision + ':' + path))
    return destination


def compare(history, root, cli_hash):
    rows = []
    with tempfile.TemporaryDirectory(prefix='history-', dir=root.parent) as temporary:
        for issue, after in CANDIDATES.items():
            before = git(history, 'rev-parse', after + '^1').decode().strip()
            for side, revision in (('before', before), ('after', after)):
                scripts = history_scripts(history, revision, Path(temporary) / (issue + '-' + side))
                calls = []
                if issue == '40':
                    result = decoded(measured([sys.executable, '-B', HERE / 'probe.py', scripts, 'identity',
                        root / 'ret.bin', '--program-sha256', cli_hash], calls, 'admission'))
                    result['evidence_obtainable'] = result['identity_available'] and result['duplicate_blocked']
                elif issue == '41':
                    result = recover(scripts, root, calls, side == 'after')
                else:
                    base = scorer.read_json(root / 'function.json')
                    result = {}
                    for name, mutation in (('selected', {'kind': 'function_detail'}),
                            ('wrong_kind', {'kind': 'function_cfg'}), ('unknown_version', {'schema_version': 'future'})):
                        fixtures.write_json(root / 'contract-probe.json', {**base, **mutation})
                        observed = decoded(measured([sys.executable, '-B', HERE / 'probe.py', scripts,
                            'contract', root / 'contract-probe.json'], calls, 'admission'))
                        result[name] = observed
                    result['evidence_obtainable'] = result['selected']['accepted']
                    assert not result['wrong_kind']['accepted'] and not result['unknown_version']['accepted']
                rows.append({'issue': issue, 'side': side, 'revision': revision,
                             'outcome': result, 'costs': scorer.costs(calls), 'calls': calls})
    return rows


def portable(value, replacements):
    if isinstance(value, str):
        for old, new in replacements: value = value.replace(old, new)
        return value
    if isinstance(value, list): return [portable(v, replacements) for v in value]
    if isinstance(value, dict): return {k: portable(v, replacements) for k, v in value.items()}
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--public-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--history-root', type=Path)
    args = parser.parse_args()
    public = args.public_root.resolve(); output = args.output.resolve()
    if platform.system() != 'Linux' or platform.machine() != 'x86_64':
        parser.error('reference baseline requires Linux x86-64')
    cli = public / 'bin/linux-x86_64/auto-re-cli'; cli_hash = digest(cli)
    rows = dict(line.split('  ', 1)[::-1] for line in (public / 'SHA256SUMS').read_text().splitlines())
    if rows.get('bin/linux-x86_64/auto-re-cli') != cli_hash: parser.error('binary hash mismatch')
    version = subprocess.run([str(cli), '--version'], capture_output=True, check=True).stdout.decode().strip()
    if version != 'auto-re-cli 0.1.10': parser.error('unsupported CLI version')
    output.mkdir()  # Fresh directory only; never overwrite an accepted run.
    root = output / 'evidence'; root.mkdir(); fixtures.create(root)
    revision = git(public, 'rev-parse', 'HEAD').decode().strip()
    records, outcomes = reference_cases(public, cli, root, cli_hash, revision)
    fixtures.write_json(output / 'records.json', records)
    scores = scorer.score_records(records, root)
    assert scores['completed'] == 7
    comparisons = compare(args.history_root.resolve(), root, cli_hash) if args.history_root else []
    summary = {'kind': 'auto_re_agent_task_baseline', 'schema_version': 1,
        'cli': {'version': version, 'sha256': cli_hash}, 'real_agent': 'NOT_RUN; no model calls authorized',
        'resources': 'NOT_MEASURED; latency is host-load dependent',
        'cases_sha256': digest(HERE / 'cases.json'), 'scores': scores, 'outcomes': outcomes,
        'records': records, 'comparisons': comparisons}
    # Durable records contain known fixture claims/costs, never full analyzer payloads or host paths.
    replacements = [(str(root), '<evidence>'), (str(public), '<public>'), (str(HERE), '<evals>'),
                    (sys.executable, '<python>')]
    for row in comparisons:
        replacements.extend((c['argv'][3], '<revision-scripts>') for c in row['calls'] if 'probe.py' in c['argv'][2])
        if row['issue'] == '41':
            replacements.extend((c['argv'][2], '<revision-scripts>/read_result.py') for c in row['calls'])
    fixtures.write_json(output / 'baseline.json', portable(summary, replacements))
    print(json.dumps({'completed': scores['completed'], 'cases': scores['runs'], 'comparisons': len(comparisons),
                      'output': str(output)}))


if __name__ == '__main__':
    main()
