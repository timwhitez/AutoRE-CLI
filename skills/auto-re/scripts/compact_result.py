#!/usr/bin/env python3
"""Opt-in lossless context projection of retained report/decompile AI JSON."""
from __future__ import annotations

import argparse
import copy
import json
import sys
import importlib.util
from pathlib import Path

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('auto_re_compact_reader', Path(__file__).with_name('read_result.py'))
reader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reader)
KIND = 'auto_re_compact_ai_view'
VERSION = 1
FIELDS = ('variable_hints', 'semantic_summary', 'field_states')


class ExactFloat(float):
    """Keep the source token while retaining the shared reader's numeric admission."""
    def __new__(cls, token):
        value = super().__new__(cls, token)
        value.token = token
        return value

    def __deepcopy__(self, memo):
        return self


def encoded(value, *, sort_keys=False):
    def emit(item):
        if isinstance(item, ExactFloat):
            return item.token
        if isinstance(item, dict):
            keys = sorted(item) if sort_keys else item
            return '{' + ','.join(emit(key) + ':' + emit(item[key]) for key in keys) + '}'
        if isinstance(item, list):
            return '[' + ','.join(emit(child) for child in item) + ']'
        return json.dumps(item, ensure_ascii=False, allow_nan=False, separators=(',', ':'))
    return emit(value).encode('utf-8')


def project(full, source):
    if full.get('profile') != 'ai' or not isinstance(full.get('functions'), list):
        raise ValueError('unsupported_ai_root')
    reader.runner.validate_result_contract(full, command='report' if 'sections' in full else 'decompile')
    if any(key in full for key in ('compact_version', 'catalog', 'full_view')):
        raise ValueError('compact_field_collision')
    counts = {}

    def eligible(path):
        return len(path) > 2 and path[0] == 'functions' and (
            path[-1] in FIELDS or path[-2] == 'hlil_passes')

    def walk(item, path, collect):
        if isinstance(item, dict) and set(item) == {'$agent_ref'}:
            raise ValueError('reserved_reference')
        if eligible(path):
            blob = encoded(item)
            if collect:
                counts[blob] = counts.get(blob, 0) + 1
            elif blob in indexes:
                return {'$agent_ref': indexes[blob]}
        if isinstance(item, dict):
            return {k: walk(v, path + [k], collect) for k, v in item.items()}
        if isinstance(item, list):
            return [walk(v, path + [str(i)], collect) for i, v in enumerate(item)]
        return item

    walk(full, [], True)
    indexes, catalog = {}, []
    for blob, count in counts.items():
        reference = encoded({'$agent_ref': len(catalog)})
        if count > 1 and count * (len(blob) - len(reference)) > len(blob) + 1:
            indexes[blob] = len(catalog)
            catalog.append(json.loads(blob, parse_float=ExactFloat, parse_int=reader._bounded_int))
    view = walk(full, [], False)
    view.update(kind=KIND, compact_version=VERSION, catalog=catalog,
                full_view={'artifact': source['path'], 'bytes': source['bytes'],
                           'sha256': source['sha256'], 'original_kind': full.get('kind')})
    baseline, candidate = len(encoded(full)), len(encoded(view))
    # A new wrapper is emitted only when it clears the measured compatibility gate.
    if baseline - candidate < 1024 or (baseline - candidate) * 10 < baseline:
        return copy.deepcopy(full)
    try:
        reader.runner._validate_json_shape(view, reader.runner.ACTION_RESULT_POLICY)
        if candidate > reader.runner.ACTION_RESULT_POLICY.max_encoded_bytes:
            return copy.deepcopy(full)
    except reader.runner.ActionError:
        return copy.deepcopy(full)
    # Compare canonical text containing original numerals, never rounded float equality.
    assert encoded(expand_view(view), sort_keys=True) == encoded(full, sort_keys=True)
    return view


def expand(value, catalog):
    if isinstance(value, dict):
        if set(value) == {'$agent_ref'}:
            index = value['$agent_ref']
            if type(index) is not int or not 0 <= index < len(catalog):
                raise ValueError('invalid_catalog_reference')
            return copy.deepcopy(catalog[index])
        return {k: expand(v, catalog) for k, v in value.items()}
    if isinstance(value, list):
        return [expand(v, catalog) for v in value]
    return value


def expand_view(view):
    if view.get('kind') != KIND or view.get('schema_version') != '0.1.0' or type(view.get('compact_version')) is not int or view['compact_version'] != VERSION:
        raise ValueError('unsupported_compact_version')
    catalog = view.get('catalog')
    if not isinstance(catalog, list):
        raise ValueError('invalid_catalog')
    payload = {k: v for k, v in view.items() if k not in ('kind', 'compact_version', 'catalog', 'full_view')}
    original_kind = view['full_view']['original_kind']
    if original_kind is not None:
        payload['kind'] = original_kind
    return expand(payload, catalog)


def support_pointer(view, pointer):
    item, support = view, ''
    for key in reader.pointer_tokens(pointer):
        if isinstance(item, dict) and set(item) == {'$agent_ref'}:
            index = item['$agent_ref']
            item, support = view['catalog'][index], '/catalog/' + str(index)
        item = item[int(key)] if isinstance(item, list) else item[key]
        support += '/' + key.replace('~', '~0').replace('/', '~1')
    if isinstance(item, dict) and set(item) == {'$agent_ref'}:
        support = '/catalog/' + str(item['$agent_ref'])
    return support


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('path', type=Path)
    parser.add_argument('--expected-sha256')
    args = parser.parse_args()
    try:
        full, source = reader.read_source(args.path, args.expected_sha256, parse_float=ExactFloat)
        sys.stdout.buffer.write(encoded(project(full, source)))
    except (ValueError, reader.runner.ActionError) as error:
        sys.stderr.buffer.write(encoded({'ok': False, 'kind': KIND, 'compact_version': VERSION,
                                        'error': str(error).split(':', 1)[0]}) + b'\n')
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
