#!/usr/bin/env python3
"""Optionally read a bounded, hash-bound view of existing JSON; never reanalyze."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import os
import pathlib
import re
import sys

sys.dont_write_bytecode = True


def _local_module(name):
    spec = importlib.util.spec_from_file_location('auto_re_view_' + name,
                                                pathlib.Path(__file__).with_name(name + '.py'))
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


verifier = _local_module('verify_bundle')
runner = _local_module('run_next_action')
MAX_OUTPUT_BYTES = 16 * 1024
DEFAULT_LIMIT = 32
BOUNDARY_FIELDS = ('warnings', 'completion', 'budget', 'slice_budget', 'stop_reasons', 'status', 'reason')


class ViewError(ValueError):
    pass


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ViewError('duplicate_key')
        value[key] = item
    return value


def _reject_constant(value):
    raise ViewError('non_finite_number')


def _bounded_int(value):
    if len(value.lstrip('-')) > 4300:
        raise ViewError('integer_too_large')
    return int(value)


def read_source(path, expected, *, parse_float=float):
    if expected is not None and not re.fullmatch(r'[0-9a-f]{64}', expected):
        raise ViewError('invalid_expected_sha256')
    path = pathlib.Path(path)
    if not path.is_absolute():
        path = pathlib.Path.cwd() / path  # Do not collapse symlink/../ components before inspection.
    try:
        handle, opened = verifier.open_regular_file_stably(path, pathlib.Path(path.anchor), 'result')
        with handle:
            if opened.st_size > runner.ACTION_RESULT_POLICY.max_encoded_bytes:
                raise ViewError('input_too_large')
            data = runner._read_bounded_control_bytes(handle, runner.ACTION_RESULT_POLICY)
            after = os.fstat(handle.fileno())
            current = verifier.regular_file_without_links(path, pathlib.Path(path.anchor))
            for metadata in (after, current):
                if (not verifier.metadata_matches_opened(opened, metadata, 'result')
                        or metadata.st_size != opened.st_size
                        or getattr(metadata, 'st_mtime_ns', metadata.st_mtime) != getattr(opened, 'st_mtime_ns', opened.st_mtime)):
                    raise ViewError('source_changed')
            if len(data) != opened.st_size:
                raise ViewError('source_changed')
    except (OSError, verifier.ValidationError) as error:
        raise ViewError('source_unavailable') from error
    except runner.ActionError as error:
        raise ViewError('input_too_large') from error
    digest = hashlib.sha256(data).hexdigest()
    if expected is not None and expected != digest:
        raise ViewError('source_changed')
    try:
        document = json.loads(data.decode('utf-8'), object_pairs_hook=_unique_object,
                              parse_constant=_reject_constant, parse_int=_bounded_int, parse_float=parse_float)
        runner._validate_json_shape(document, runner.ACTION_RESULT_POLICY)
        # The shared shape policy bounds size but does not reject lone surrogates or float overflow.
        stack = [document]
        while stack:
            item = stack.pop()
            if isinstance(item, str):
                item.encode('utf-8')
            elif isinstance(item, float) and not math.isfinite(item):
                raise ViewError('non_finite_number')
            elif isinstance(item, dict):
                stack.extend(item.keys())
                stack.extend(item.values())
            elif isinstance(item, list):
                stack.extend(item)
        if not isinstance(document, dict):
            raise ViewError('root_must_be_object')
    except ViewError:
        raise
    except (ValueError, RecursionError, runner.ActionError) as error:
        raise ViewError('invalid_json_or_structure') from error
    source = {'path': str(path), 'bytes': len(data), 'sha256': digest,
              'integrity': 'expected_sha256_matched' if expected else 'current_snapshot_only',
              'semantics': 'not_validated'}
    for field in ('schema_version', 'kind', 'profile'):
        if field in document:
            source[field] = document[field]
    return document, source


def pointer_tokens(pointer):
    try:
        if len(pointer.encode('utf-8')) > 1024:
            raise ViewError('pointer_too_large')
    except UnicodeEncodeError as error:
        raise ViewError('invalid_pointer') from error
    if pointer == '':
        return []
    if not pointer.startswith('/') or re.search(r'~(?:[^01]|$)', pointer):
        raise ViewError('invalid_pointer')
    return [token.replace('~1', '/').replace('~0', '~') for token in pointer[1:].split('/')]


def select_value(document, tokens):
    value = document
    ancestors = [('', value)]
    location = ''
    for token in tokens:
        if isinstance(value, dict) and token in value:
            value = value[token]
        elif isinstance(value, list):
            if not re.fullmatch(r'0|[1-9][0-9]*', token):
                raise ViewError('invalid_array_index')
            index = int(token)
            if index >= len(value):
                raise ViewError('pointer_missing')
            value = value[index]
        else:
            raise ViewError('pointer_missing')
        location += '/' + token.replace('~', '~0').replace('/', '~1')
        ancestors.append((location, value))
    if isinstance(document.get('summary'), dict):
        ancestors.append(('/summary', document['summary']))
    boundaries = {}
    for location, ancestor in ancestors:
        if isinstance(ancestor, dict):
            for field in BOUNDARY_FIELDS:
                if field in ancestor:
                    boundaries[location + '/' + field] = ancestor[field]
    return value, [{'pointer': key, 'value': item} for key, item in boundaries.items()]


def _encoded(value):
    try:
        return (json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(',', ':')) + '\n').encode('utf-8')
    except (ValueError, UnicodeEncodeError, RecursionError) as error:
        raise ViewError('invalid_output_value') from error


def build_view(document, source, pointer, tokens, offset, limit):
    if offset < 0 or not 1 <= limit <= 256:
        raise ViewError('invalid_pagination')
    value, boundaries = select_value(document, tokens)
    is_array = isinstance(value, list)
    if is_array:
        if offset > len(value):
            raise ViewError('offset_out_of_range')
        value_type = 'array'
    else:
        if offset or limit != DEFAULT_LIMIT:
            raise ViewError('non_array_pagination')
        value_type = ('null' if value is None else 'object' if isinstance(value, dict)
                      else 'boolean' if isinstance(value, bool) else 'string' if isinstance(value, str) else 'number')
    selection = {'pointer': pointer, 'value_type': value_type, 'offset': offset,
                 'limit': limit, 'has_more': False}
    result = {'ok': True, 'kind': 'auto_re_artifact_view', 'view_schema_version': 1,
              'source': source, 'selection': selection, 'source_boundaries': boundaries,
              'boundary_capture_complete': True, 'analysis_completeness': 'not_evaluated'}
    if is_array:
        selection.update(total_items=len(value), returned_items=0)
        if offset < len(value):
            selection.update(has_more=True, next_offset=offset + 1)
    if len(_encoded(result)) > MAX_OUTPUT_BYTES:
        raise ViewError('boundary_too_large')
    if not is_array:
        result['data'] = value
        encoded = _encoded(result)
        if len(encoded) > MAX_OUTPUT_BYTES:
            raise ViewError('value_too_large')
        return encoded
    result['data'] = []
    encoded = None
    for index in range(offset, min(len(value), offset + limit)):
        result['data'].append(value[index])
        next_offset = index + 1
        selection.update(returned_items=next_offset - offset, has_more=next_offset < len(value))
        if selection['has_more']:
            selection['next_offset'] = next_offset
        else:
            selection.pop('next_offset', None)
        candidate = _encoded(result)
        if len(candidate) > MAX_OUTPUT_BYTES:
            if encoded is None:
                raise ViewError('value_too_large')
            return encoded
        encoded = candidate
    if encoded is None:
        selection.update(has_more=False)
        selection.pop('next_offset', None)
        encoded = _encoded(result)
        if len(encoded) > MAX_OUTPUT_BYTES:
            raise ViewError('boundary_too_large')
    return encoded


def _value_type(value):
    return ('null' if value is None else 'object' if isinstance(value, dict)
            else 'array' if isinstance(value, list) else 'boolean' if isinstance(value, bool)
            else 'string' if isinstance(value, str) else 'number')


def build_recovery_view(document, source, pointer, tokens, mode, position, limit):
    if position < 0 or not 1 <= limit <= (256 if mode == 'keys' else 4096):
        raise ViewError('invalid_pagination')
    value, boundaries = select_value(document, tokens)
    if not isinstance(value, dict if mode == 'keys' else str):
        raise ViewError('mode_type_mismatch')
    total = len(value)
    if position > total:
        raise ViewError('offset_out_of_range')
    selection = {'pointer': pointer, 'mode': mode, 'value_type': _value_type(value),
                 'has_more': False}
    if mode == 'keys':
        selection.update(offset=position, limit=limit, total_items=total, returned_items=0)
        next_field = 'next_offset'
    else:
        selection.update(start=position, length=limit, end=position, total_length=total)
        next_field = 'next_start'
    result = {'ok': True, 'kind': 'auto_re_artifact_view', 'view_schema_version': 2,
              'source': source, 'selection': selection, 'source_boundaries': boundaries,
              'boundary_capture_complete': True, 'analysis_completeness': 'not_evaluated',
              'data': [] if mode == 'keys' else ''}
    encoded = _encoded(result)
    if len(encoded) > MAX_OUTPUT_BYTES:
        raise ViewError('boundary_too_large')
    if position == total:
        return encoded

    def advance(end):
        selection['has_more'] = end < total
        if end < total:
            selection[next_field] = end
        else:
            selection.pop(next_field, None)
        if mode == 'keys':
            selection['returned_items'] = end - position
        else:
            selection['end'] = end
            result['data'] = value[position:end]
        return _encoded(result)

    end = min(total, position + limit)
    if mode == 'string':
        candidate = advance(end)
        if len(candidate) <= MAX_OUTPUT_BYTES:
            return candidate
        # Test the terminal candidate first: removing continuation metadata can
        # make it smaller than a preceding fragment. Interior sizes are monotone.
        low, high, encoded = position + 1, end - 1, None
        while low <= high:
            middle = (low + high) // 2
            candidate = advance(middle)
            if len(candidate) <= MAX_OUTPUT_BYTES:
                encoded = candidate
                low = middle + 1
            else:
                high = middle - 1
        if encoded is None:
            raise ViewError('value_too_large')
        return encoded

    encoded = None
    for index, name in enumerate(list(value)[position:end], position):
        child = pointer + '/' + name.replace('~', '~0').replace('/', '~1')
        if len(child.encode('utf-8')) > 1024:
            if encoded is None:
                raise ViewError('value_too_large')
            return encoded
        result['data'].append({'name': name, 'value_type': _value_type(value[name]), 'pointer': child})
        candidate = advance(index + 1)
        if len(candidate) > MAX_OUTPUT_BYTES:
            if encoded is None:
                raise ViewError('value_too_large')
            return encoded
        encoded = candidate
    return encoded


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('path', type=pathlib.Path)
    parser.add_argument('--pointer', required=True, help='RFC 6901 string pointer; empty string selects root')
    parser.add_argument('--mode', choices=('value', 'keys', 'string'), default='value')
    parser.add_argument('--offset', type=int)
    parser.add_argument('--limit', type=int)
    parser.add_argument('--start', type=int)
    parser.add_argument('--length', type=int)
    parser.add_argument('--expected-sha256')
    args = parser.parse_args()
    try:
        tokens = pointer_tokens(args.pointer)
        if ((args.mode == 'string' and (args.offset is not None or args.limit is not None))
                or (args.mode != 'string' and (args.start is not None or args.length is not None))):
            raise ViewError('invalid_pagination')
        if args.mode == 'string':
            position = args.start if args.start is not None else 0
            limit = args.length if args.length is not None else 1024
        else:
            position = args.offset if args.offset is not None else 0
            limit = args.limit if args.limit is not None else DEFAULT_LIMIT
        if position > 0 and args.expected_sha256 is None:
            raise ViewError('expected_sha256_required')
        if position < 0 or not 1 <= limit <= (4096 if args.mode == 'string' else 256):
            raise ViewError('invalid_pagination')
        document, source = read_source(args.path, args.expected_sha256)
        if args.mode == 'value':
            encoded = build_view(document, source, args.pointer, tokens, position, limit)
        else:
            encoded = build_recovery_view(document, source, args.pointer, tokens, args.mode, position, limit)
        sys.stdout.buffer.write(encoded)
    except ViewError as error:
        # Domain diagnostics never echo unbounded parser errors or source content.
        diagnostic = {'ok': False, 'kind': 'auto_re_artifact_view', 'view_schema_version': 1 if args.mode == 'value' else 2,
                      'error': str(error), 'pointer': args.pointer[:128]}
        sys.stderr.write(json.dumps(diagnostic, ensure_ascii=True, separators=(',', ':')) + '\n')
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
