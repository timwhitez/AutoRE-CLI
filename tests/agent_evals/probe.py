#!/usr/bin/env python3
"""Trusted adapter for historical helper APIs; emits passive evaluation data only."""
import argparse
import importlib.util
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('scripts', type=Path)
    parser.add_argument('mode', choices=('identity', 'contract'))
    parser.add_argument('input', type=Path)
    parser.add_argument('--program-sha256')
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('eval_revision_runner', args.scripts / 'run_next_action.py')
    runner = importlib.util.module_from_spec(spec); spec.loader.exec_module(runner)
    if args.mode == 'identity':
        argv = ['auto-re-cli', 'dump-cfg', str(args.input), '--raw-shellcode', '--arch', 'x86-64',
                '--base-address', '0x1000', '--addr', '0x1000', '--format', 'json']
        identity = runner.request_identity(argv, args.program_sha256)
        prior = {'request_identity': identity, 'execution_status': 'completed', 'timeout_seconds': 30,
                 'leader_reaped': True}
        blocked = False
        try: reason = runner.assess_continuation(prior, identity, 30)
        except runner.ActionError as error:
            reason = str(error).split(':', 1)[0]; blocked = reason == 'no_progress'
        result = {'identity_available': identity is not None, 'duplicate_blocked': blocked, 'reason': reason}
    else:
        value = json.loads(args.input.read_text(encoding='utf-8'))
        try:
            label = runner.validate_result_contract(value)
            result = {'accepted': True, 'label': label, 'reason': None}
        except runner.ActionError as error:
            result = {'accepted': False, 'reason': str(error).split(':', 1)[0]}
    print(json.dumps(result, separators=(',', ':')))


if __name__ == '__main__':
    main()
