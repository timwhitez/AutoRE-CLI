"""Snapshot input admission and descriptor ownership; only inert temporary files."""
from __future__ import annotations

import errno
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from test_release_assets_safety import builder, MODULE


class SnapshotDescriptorTests(unittest.TestCase):
    @unittest.skipUnless(os.name == 'posix', 'POSIX FIFO admission')
    def test_initial_checksum_fifo_is_rejected_without_writer(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / 'repository'; repository.mkdir()
            os.mkfifo(repository / 'SHA256SUMS')
            code = '''import importlib.util, pathlib, sys
spec = importlib.util.spec_from_file_location('builder', sys.argv[1])
builder = importlib.util.module_from_spec(spec); spec.loader.exec_module(builder)
builder.ROOT = pathlib.Path(sys.argv[2])
try:
    builder.build_assets(builder.ROOT.parent / 'output')
except builder.ReleaseAssetError as error:
    print(error)
    sys.exit(2)
'''
            result = subprocess.run([sys.executable, '-B', '-c', code, str(MODULE), str(repository)],
                                    capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn('not a stable regular file', result.stdout)
            self.assertFalse((root / 'output').exists())

    def test_successful_open_is_closed_once_on_every_failure(self):
        for failure in ('fstat', 'mkdir', 'fdopen', 'read', None):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source = root / 'source'; source.write_bytes(b'controlled data')
                destination = root / 'new' / 'copy'
                opened = []; closed = []
                real_open, real_close = os.open, os.close
                real_fdopen, real_fstat = os.fdopen, os.fstat

                def tracked_open(*args, **kwargs):
                    descriptor = real_open(*args, **kwargs)
                    opened.append(descriptor)
                    return descriptor

                def tracked_close(descriptor):
                    closed.append(descriptor)
                    return real_close(descriptor)

                class Reader:
                    def __init__(self, descriptor, mode):
                        self.descriptor = descriptor
                        self.handle = real_fdopen(descriptor, mode)
                    def __enter__(self):
                        return self
                    def __exit__(self, *args):
                        closed.append(self.descriptor)
                        return self.handle.__exit__(*args)
                    def fileno(self):
                        return self.handle.fileno()
                    def read(self, size):
                        if failure == 'read':
                            raise OSError('injected read')
                        return self.handle.read(size)

                def fdopen(descriptor, mode):
                    if failure == 'fdopen':
                        raise OSError('injected fdopen')
                    return Reader(descriptor, mode)

                def fstat(descriptor):
                    if failure == 'fstat':
                        raise OSError('injected fstat')
                    return real_fstat(descriptor)

                try:
                    with mock.patch.object(builder.os, 'open', side_effect=tracked_open), \
                         mock.patch.object(builder.os, 'close', side_effect=tracked_close), \
                         mock.patch.object(builder.os, 'fdopen', side_effect=fdopen), \
                         mock.patch.object(builder.os, 'fstat', side_effect=fstat):
                        with mock.patch.object(Path, 'mkdir', side_effect=OSError('injected mkdir')) \
                                if failure == 'mkdir' else mock.patch.object(builder, 'ROOT', builder.ROOT):
                            if failure:
                                with self.assertRaisesRegex(OSError, 'injected ' + failure):
                                    builder.copy_file(source, destination)
                            else:
                                builder.copy_file(source, destination)
                    self.assertEqual(len(opened), 1)
                    self.assertEqual(closed, opened, 'each successful open must close exactly once')
                    with self.assertRaises(OSError) as caught:
                        real_fstat(opened[0])
                    self.assertEqual(caught.exception.errno, errno.EBADF)
                    if failure is None:
                        self.assertEqual(destination.read_bytes(), b'controlled data')
                finally:
                    for descriptor in opened:
                        try:
                            real_fstat(descriptor)
                        except OSError:
                            pass
                        else:
                            real_close(descriptor)
