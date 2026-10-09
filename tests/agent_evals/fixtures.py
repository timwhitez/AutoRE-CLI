"""Independent deterministic fixture definitions; never execute the raw bytes."""
import json
from pathlib import Path


def write_json(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(',', ':')) + '\n', encoding='utf-8')


def create(root):
    root = Path(root)
    (root / 'ret.bin').write_bytes(bytes.fromhex('909090c3'))
    write_json(root / 'large.json', {
        'schema_version': '0.1.0', 'warnings': ['synthetic fixture; not recovered program semantics'],
        'completion': False, 'stop_reasons': ['fixture_partial'],
        'function': {'pseudo': 'A雪\\"\n' * 6000},
        'metadata': {'language': {'go': 'X' * 20000, 'rust': None, 'c': False, 'unknown': [], '~/': {}, 'empty': ''}}})
    write_json(root / 'knowledge.json', {
        'warnings': ['synthetic fixture; not recovered program semantics'],
        'complete': {'entries': [], 'completion': True},
        'partial': {'entries': [], 'completion': False, 'stop_reasons': ['fixture_budget']}})
    write_json(root / 'existing.json', {'function': {'address': 4096},
        'warnings': ['synthetic selected-scope fixture'], 'completion': False})
    (root / 'corrupt.json').write_bytes(b'{"function":')
