"""Bounded lifecycle for a trusted CLI. Never use this to execute a target sample.

No communicate()/capture_output buffering or blocking reader-thread joins. The
controller polls both pipes, bounds retained bytes, and owns only the process
session/job it creates. This is orchestration, not a hostile-process sandbox.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import math
import os
import signal
import sys
import subprocess
import threading
import time
from typing import NamedTuple, Optional

DEFAULT_TIMEOUT_SECONDS = 900.0
READ_CHUNK_BYTES = 64 * 1024
POLL_SECONDS = 0.01


class ProcessError(ValueError):
    pass


class CapturedStream(NamedTuple):
    tail: bytes
    bytes_total: int
    sha256: str
    complete: bool = True


class ProcessResult(NamedTuple):
    returncode: Optional[int]
    status: str
    stdout: CapturedStream
    stderr: CapturedStream
    diagnostics: tuple[str, ...]
    leader_reaped: bool


class _Stream:
    def __init__(self, handle):
        self.handle = handle
        self.tail = bytearray()
        self.total = 0
        self.digest = hashlib.sha256()
        self.complete = handle is None

    def feed(self, data: bytes, tail_bytes: int, keep_bytes: int) -> None:
        self.total += len(data)
        self.digest.update(data)
        if tail_bytes:
            self.tail.extend(data[:keep_bytes])
            if len(self.tail) > tail_bytes:
                del self.tail[:-tail_bytes]

    def snapshot(self) -> CapturedStream:
        return CapturedStream(bytes(self.tail), self.total, self.digest.hexdigest(), self.complete)


def validate_seconds(value: float, name: str = "timeout_seconds") -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ProcessError(f"{name} must be a positive finite number")
    try:
        number = float(value)
    except OverflowError as error:
        raise ProcessError(f"{name} must be a positive finite number") from error
    if not math.isfinite(number) or number <= 0:
        raise ProcessError(f"{name} must be a positive finite number")
    return number


class _WindowsJob:
    """Native kill-on-close job for the trusted child; no process-name searches."""
    def __init__(self):
        import ctypes as C
        from ctypes import wintypes as W

        class BasicLimits(C.Structure):
            _fields_ = [("process_time", C.c_int64), ("job_time", C.c_int64),
                        ("flags", C.c_uint32), ("min_working_set", C.c_size_t),
                        ("max_working_set", C.c_size_t), ("active_limit", C.c_uint32),
                        ("affinity", C.c_size_t), ("priority", C.c_uint32),
                        ("scheduling", C.c_uint32)]

        class IoCounters(C.Structure):
            _fields_ = [(name, C.c_uint64) for name in
                        ("read_ops", "write_ops", "other_ops", "read_bytes", "write_bytes", "other_bytes")]

        class ExtendedLimits(C.Structure):
            _fields_ = [("basic", BasicLimits), ("io", IoCounters),
                        ("process_memory", C.c_size_t), ("job_memory", C.c_size_t),
                        ("peak_process_memory", C.c_size_t), ("peak_job_memory", C.c_size_t)]

        self.api = C.WinDLL("kernel32", use_last_error=True)
        self.api.CreateJobObjectW.argtypes = [C.c_void_p, W.LPCWSTR]
        self.api.CreateJobObjectW.restype = W.HANDLE
        self.api.SetInformationJobObject.argtypes = [W.HANDLE, C.c_int, C.c_void_p, W.DWORD]
        self.api.SetInformationJobObject.restype = W.BOOL
        self.api.AssignProcessToJobObject.argtypes = [W.HANDLE, W.HANDLE]
        self.api.AssignProcessToJobObject.restype = W.BOOL
        self.api.TerminateJobObject.argtypes = [W.HANDLE, W.UINT]
        self.api.TerminateJobObject.restype = W.BOOL
        self.api.CloseHandle.argtypes = [W.HANDLE]
        self.api.CloseHandle.restype = W.BOOL
        self.handle = self.api.CreateJobObjectW(None, None)
        if not self.handle:
            raise C.WinError(C.get_last_error())
        limits = ExtendedLimits()
        limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not self.api.SetInformationJobObject(self.handle, 9, C.byref(limits), C.sizeof(limits)):
            error = C.WinError(C.get_last_error())
            self.close()
            raise error

    def assign(self, process) -> None:
        import ctypes as C
        # CPython keeps this native handle alive for the Popen lifetime. Using
        # it avoids a PID lookup/reuse race; fail explicitly on other runtimes.
        handle = getattr(process, "_handle", None)
        if handle is None:
            raise ProcessError("Windows process handle is unavailable for job ownership")
        if not self.api.AssignProcessToJobObject(self.handle, int(handle)):
            raise C.WinError(C.get_last_error())

    def terminate(self) -> None:
        import ctypes as C
        if self.handle and not self.api.TerminateJobObject(self.handle, 125):
            raise C.WinError(C.get_last_error())

    def close(self) -> None:
        import ctypes as C
        if self.handle:
            handle, self.handle = self.handle, None
            if not self.api.CloseHandle(handle):
                raise C.WinError(C.get_last_error())


def _read_pipe(handle, limit: int) -> Optional[bytes]:
    if os.name == "nt":
        import ctypes as C
        from ctypes import wintypes as W
        import msvcrt
        api = C.WinDLL("kernel32", use_last_error=True)
        peek = api.PeekNamedPipe
        peek.argtypes = [W.HANDLE, C.c_void_p, W.DWORD, C.c_void_p,
                         C.POINTER(W.DWORD), C.c_void_p]
        peek.restype = W.BOOL
        available = W.DWORD()
        if not peek(msvcrt.get_osfhandle(handle.fileno()), None, 0, None, C.byref(available), None):
            error = C.get_last_error()
            if error in (109, 232):  # ERROR_BROKEN_PIPE / ERROR_NO_DATA
                return b""
            raise C.WinError(error)
        if not available.value:
            return None
        limit = min(limit, available.value)
    try:
        return os.read(handle.fileno(), limit)
    except BlockingIOError:
        return None


def _pump(streams, tail_bytes: int, max_output_bytes: Optional[int]) -> tuple[bool, bool]:
    progressed = False
    for stream in streams:
        if stream.complete:
            continue
        total = sum(item.total for item in streams)
        remaining = None if max_output_bytes is None else max_output_bytes - total
        limit = READ_CHUNK_BYTES if remaining is None else min(READ_CHUNK_BYTES, remaining + 1)
        if limit <= 0:
            return progressed, True
        data = _read_pipe(stream.handle, limit)
        if data is None:
            continue
        progressed = True
        if not data:
            stream.complete = True
            continue
        stream.feed(data, tail_bytes, len(data) if remaining is None else max(0, remaining))
        if remaining is not None and len(data) > remaining:
            return progressed, True
    return progressed, False


@contextmanager
def _signals(cleanup: bool = False):
    previous = {}
    if threading.current_thread() is threading.main_thread():
        def cancelled(signum, frame):
            raise KeyboardInterrupt(f"signal {signum}")
        for number in (signal.SIGINT, signal.SIGTERM):
            previous[number] = signal.signal(number, signal.SIG_IGN if cleanup else cancelled)
    try:
        yield
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


def _group_exists(process) -> bool:
    if os.name != "posix":
        return process.poll() is None
    try:
        os.killpg(process.pid, 0)
        return True
    except ProcessLookupError:
        return False


def _cleanup(process, job, grace_seconds: float, reap_seconds: float) -> list[str]:
    errors = []
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGTERM)
        elif process.poll() is None:
            process.send_signal(signal.CTRL_BREAK_EVENT)
    except ProcessLookupError:
        pass
    except OSError as error:
        errors.append(f"terminate_failed: {str(error)[:256]}")
    deadline = time.monotonic() + grace_seconds
    while time.monotonic() < deadline:
        process.poll()
        try:
            if not _group_exists(process):
                break
        except OSError as error:
            errors.append(f"group_check_failed: {str(error)[:256]}")
            break
        time.sleep(POLL_SECONDS)
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        elif job is not None:
            job.terminate()
        elif process.poll() is None:
            process.kill()  # job setup failed: reap the known child, do not run on
    except ProcessLookupError:
        pass
    except OSError as error:
        errors.append(f"kill_failed: {str(error)[:256]}")
    try:
        process.wait(timeout=reap_seconds)
    except (OSError, subprocess.TimeoutExpired) as error:
        errors.append(f"reap_failed: {str(error)[:256]}")
    return errors


def run_process(
    argv: list[str], *, timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    tail_bytes: int = 1024 * 1024, max_output_bytes: Optional[int] = None,
    drain_seconds: float = 2.0, grace_seconds: float = 2.0, reap_seconds: float = 2.0,
    capture: bool = True, cancel_event: Optional[threading.Event] = None,
) -> ProcessResult:
    """Run exactly one trusted argv, with bounded capture and owned cleanup.

    max_output_bytes is a combined stdout/stderr budget; no more than budget+1
    bytes are consumed, and no more than budget bytes are retained. Without a
    total budget, all observed bytes are hashed, with a per-stream bounded tail.
    """
    for value, name in ((timeout_seconds, "timeout_seconds"), (drain_seconds, "drain_seconds"),
                        (grace_seconds, "grace_seconds"), (reap_seconds, "reap_seconds")):
        validate_seconds(value, name)
    for value, name in ((tail_bytes, "tail_bytes"), (max_output_bytes, "max_output_bytes")):
        if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value < 0):
            raise ProcessError(f"{name} must be a nonnegative integer")
    if tail_bytes is None or (max_output_bytes is not None and not capture):
        raise ProcessError("output byte budgets require captured streams")
    process = None
    job = None
    streams = []
    pipes_ready = False
    status = "completed"
    diagnostics = []
    deadline = time.monotonic() + timeout_seconds
    with _signals():
        try:
            if os.name == "nt":
                job = _WindowsJob()
            # On Windows the trusted Python bootstrap blocks on a one-byte gate.
            # Assign it to the job BEFORE allowing it to launch the analyzer;
            # assigning an already-running analyzer has a child-escape race.
            command = ([sys.executable, os.path.abspath(__file__), "--job-worker", *argv]
                       if os.name == "nt" else argv)
            process = subprocess.Popen(
                command, shell=False, stdin=subprocess.PIPE if os.name == "nt" else subprocess.DEVNULL,
                stdout=subprocess.PIPE if capture else None,
                stderr=subprocess.PIPE if capture else None,
                bufsize=0, start_new_session=os.name == "posix",
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0,
            )
            streams = [_Stream(process.stdout), _Stream(process.stderr)]
            if capture and os.name == "posix":
                for stream in streams:
                    os.set_blocking(stream.handle.fileno(), False)
            pipes_ready = True
            if job is not None:
                job.assign(process)
                assert process.stdin is not None
                process.stdin.write(b"1")
                process.stdin.close()
            drain_deadline = None
            while True:
                if cancel_event is not None and cancel_event.is_set():
                    status = "cancelled"
                    break
                if time.monotonic() >= deadline:
                    status = "timed_out"
                    break
                progressed, exceeded = _pump(streams, tail_bytes, max_output_bytes)
                if exceeded:
                    status = "output_limit"
                    break
                if process.poll() is not None:
                    if all(stream.complete for stream in streams):
                        break
                    if drain_deadline is None:
                        drain_deadline = time.monotonic() + drain_seconds
                    elif time.monotonic() >= drain_deadline:
                        status = "capture_failed"
                        diagnostics.append("pipe_drain_timeout")
                        break
                if not progressed:
                    time.sleep(POLL_SECONDS)
        except KeyboardInterrupt:
            status = "cancelled"
        except (OSError, ProcessError) as error:
            if process is None:
                raise ProcessError(f"cannot launch trusted program: {str(error)[:256]}") from error
            status = "capture_failed"
            diagnostics.append(f"capture_or_setup_failed: {str(error)[:256]}")
        finally:
            with _signals(cleanup=True):
                if process is not None:
                    cleanup_errors = _cleanup(process, job, grace_seconds, reap_seconds)
                    diagnostics.extend(cleanup_errors)
                    if cleanup_errors and status == "completed":
                        status = "cleanup_failed"
                if job is not None:
                    try:
                        job.close()
                    except OSError as error:
                        diagnostics.append(f"job_close_failed: {str(error)[:256]}")
                        if status == "completed":
                            status = "cleanup_failed"
                # No reader threads exist. Even escaped descendants cannot force
                # an unbounded join or prevent us from closing our own pipe ends.
                finish = time.monotonic() + drain_seconds
                try:
                    while pipes_ready and streams and not all(item.complete for item in streams):
                        if status == "output_limit" or time.monotonic() >= finish:
                            break
                        progressed, exceeded = _pump(streams, tail_bytes, max_output_bytes)
                        if exceeded:
                            if status == "completed":
                                status = "output_limit"
                            break
                        if not progressed:
                            time.sleep(POLL_SECONDS)
                except OSError as error:
                    diagnostics.append(f"capture_finish_failed: {str(error)[:256]}")
                    if status == "completed":
                        status = "capture_failed"
                finally:
                    for stream in streams:
                        if stream.handle is not None:
                            stream.handle.close()
                    if process is not None and process.stdin is not None:
                        process.stdin.close()
    if process is None:
        raise ProcessError("trusted program launch was cancelled before a child was available")
    if len(streams) != 2:
        streams = [_Stream(None), _Stream(None)]
        for stream in streams:
            stream.complete = False
    return ProcessResult(process.returncode, status, streams[0].snapshot(), streams[1].snapshot(),
                         tuple(diagnostics[:8]), process.returncode is not None)


def probe_output(executable, *, max_bytes: int = 4096, timeout_seconds: float = 10.0) -> bytes:
    result = run_process([str(executable), "--version"], timeout_seconds=timeout_seconds,
                         max_output_bytes=max_bytes, tail_bytes=max_bytes)
    if result.status != "completed":
        raise ProcessError(
            f"probe_{result.status}: limit={max_bytes} "
            f"observed={result.stdout.bytes_total + result.stderr.bytes_total}; "
            + "; ".join(result.diagnostics)
        )
    if result.returncode != 0:
        raise ProcessError(f"probe_nonzero_exit: exit code {result.returncode}")
    return result.stdout.tail + result.stderr.tail


def _job_worker(argv: list[str]) -> int:
    """Internal Windows bootstrap: do not launch before job-assignment ACK.

    The child inherits the worker's Job Object and standard handles. The owning
    controller is responsible for termination. EOF/invalid gate fails closed.
    This is never a target-analysis or dynamic-execution entrypoint.
    """
    if not argv or sys.stdin.buffer.read(1) != b"1":
        return 125
    try:
        return subprocess.call(argv, shell=False, stdin=subprocess.DEVNULL)
    except KeyboardInterrupt:
        return 130
    except OSError as error:
        print(f"trusted CLI launch failed: {str(error)[:256]}", file=sys.stderr)
        return 125


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] != "--job-worker":
        raise SystemExit("internal process controller; use the Skill entrypoints")
    raise SystemExit(_job_worker(sys.argv[2:]))
