#!/usr/bin/env python3
"""sshctx remote agent. Python 3.9+, standard library only, no listening socket."""

from __future__ import annotations

import argparse
import concurrent.futures
import fnmatch
import hashlib
import json
import os
import pathlib
import re
import signal
import struct
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import uuid
from typing import Any, BinaryIO, Dict, Iterable, List, Tuple

MAGIC = b"SCX1"
MAX_HEADER = 8 * 1024 * 1024
MAX_PAYLOAD = 256 * 1024 * 1024
AGENT_VERSION = "0.1.0"


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(8 * 1024 * 1024)
            if not chunk: break
            digest.update(chunk)
    return digest.hexdigest()


def _read_exact(stream: BinaryIO, size: int) -> bytes:
    chunks: List[bytes] = []
    remaining = size
    while remaining:
        chunk = stream.read(remaining)
        if not chunk:
            raise EOFError("unexpected end of stream")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_frame(stream: BinaryIO) -> Tuple[Dict[str, Any], bytes]:
    if _read_exact(stream, 4) != MAGIC:
        raise ValueError("invalid frame magic")
    header_len, payload_len = struct.unpack(">IQ", _read_exact(stream, 12))
    if header_len > MAX_HEADER or payload_len > MAX_PAYLOAD:
        raise ValueError("frame exceeds size limit")
    return json.loads(_read_exact(stream, header_len)), _read_exact(stream, payload_len)


def write_frame(stream: BinaryIO, header: Dict[str, Any], payload: bytes = b"") -> None:
    encoded = json.dumps(header, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    stream.write(MAGIC + struct.pack(">IQ", len(encoded), len(payload)) + encoded + payload)
    stream.flush()


class Agent:
    def __init__(self, allowed_roots: Iterable[str]):
        self.roots = tuple(pathlib.Path(root).resolve(strict=False) for root in allowed_roots)
        if not self.roots:
            raise ValueError("allowed_roots cannot be empty")

    def path(self, raw: str, *, may_not_exist: bool = False) -> pathlib.Path:
        candidate = pathlib.Path(raw)
        if not candidate.is_absolute():
            raise PermissionError("remote path must be absolute")
        if may_not_exist:
            parent = candidate.parent.resolve(strict=False)
            resolved = parent / candidate.name
        else:
            resolved = candidate.resolve(strict=True)
        if not any(resolved == root or root in resolved.parents for root in self.roots):
            raise PermissionError("path is outside allowed_roots")
        return resolved

    def dispatch(self, method: str, params: Dict[str, Any], payload: bytes) -> Tuple[Any, bytes]:
        handler = getattr(self, "op_" + method, None)
        if handler is None:
            raise ValueError("unknown method: " + method)
        return handler(params, payload)

    def op_ping(self, params: Dict[str, Any], payload: bytes) -> Tuple[Any, bytes]:
        return {"version": AGENT_VERSION, "pid": os.getpid()}, b""

    def op_stat(self, params: Dict[str, Any], payload: bytes) -> Tuple[Any, bytes]:
        path = self.path(params["path"])
        stat = path.stat()
        return {"path": str(path), "kind": "dir" if path.is_dir() else "file", "size": stat.st_size,
                "mtime_ns": stat.st_mtime_ns, "mode": oct(stat.st_mode & 0o7777)}, b""

    def op_read(self, params: Dict[str, Any], payload: bytes) -> Tuple[Any, bytes]:
        path = self.path(params["path"])
        offset = max(0, int(params.get("byte_offset", 0)))
        limit = min(MAX_PAYLOAD, max(1, int(params.get("byte_limit", 4 * 1024 * 1024))))
        with path.open("rb") as handle:
            handle.seek(offset)
            data = handle.read(limit)
            more = bool(handle.read(1))
        return {"path": str(path), "byte_offset": offset, "bytes": len(data), "next_byte_offset": offset + len(data) if more else None}, data

    def op_grep(self, params: Dict[str, Any], payload: bytes) -> Tuple[Any, bytes]:
        root = self.path(params["path"])
        regex = re.compile(params["pattern"], re.IGNORECASE if params.get("case_insensitive") else 0)
        limit = min(10000, max(1, int(params.get("match_limit", 1000))))
        matches: List[Dict[str, Any]] = []
        files = [root] if root.is_file() else (p for p in root.rglob("*") if p.is_file())
        for file_path in files:
            try:
                with file_path.open("r", encoding=params.get("encoding", "utf-8"), errors="strict") as handle:
                    for number, line in enumerate(handle, 1):
                        if regex.search(line):
                            matches.append({"path": str(file_path), "line": number, "text": line.rstrip("\r\n")})
                            if len(matches) >= limit:
                                return {"matches": matches, "truncated": True}, b""
            except (UnicodeError, OSError):
                continue
        return {"matches": matches, "truncated": False}, b""

    def op_glob(self, params: Dict[str, Any], payload: bytes) -> Tuple[Any, bytes]:
        root = self.path(params["path"])
        pattern = params["pattern"]
        limit = min(10000, max(1, int(params.get("match_limit", 1000))))
        paths = []
        for candidate in root.rglob("*"):
            relative = candidate.relative_to(root).as_posix()
            if fnmatch.fnmatch(relative, pattern):
                paths.append(str(candidate))
                if len(paths) >= limit:
                    return {"paths": sorted(paths), "truncated": True}, b""
        return {"paths": sorted(paths), "truncated": False}, b""

    def op_exec(self, params: Dict[str, Any], payload: bytes) -> Tuple[Any, bytes]:
        cwd = str(self.path(params["cwd"]))
        argv = params.get("argv")
        command = params.get("command")
        if bool(argv) == bool(command):
            raise ValueError("provide exactly one of argv or command")
        args = [str(item) for item in argv] if argv else ["/bin/bash", "-lc", str(command)]
        env = os.environ.copy()
        env.update({str(k): str(v) for k, v in params.get("env", {}).items()})
        timeout_s = max(0.001, int(params.get("timeout_ms", 120000)) / 1000.0)
        try:
            completed = subprocess.run(args, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       timeout=timeout_s, start_new_session=True, check=False)
            return {"exit_code": completed.returncode, "signal": -completed.returncode if completed.returncode < 0 else None,
                    "timed_out": False, "stdout": completed.stdout.decode("utf-8", "replace"),
                    "stderr": completed.stderr.decode("utf-8", "replace")}, b""
        except subprocess.TimeoutExpired as error:
            return {"exit_code": None, "signal": None, "timed_out": True,
                    "stdout": (error.stdout or b"").decode("utf-8", "replace"),
                    "stderr": (error.stderr or b"").decode("utf-8", "replace")}, b""

    def op_manifest(self, params: Dict[str, Any], payload: bytes) -> Tuple[Any, bytes]:
        root = self.path(params["path"], may_not_exist=True)
        entries = {}
        if root.exists():
            for path in root.rglob("*"):
                if path.is_file():
                    digest = sha256_file(path)
                    entries[path.relative_to(root).as_posix()] = {"sha256": digest, "size": path.stat().st_size}
        return {"entries": entries}, b""

    def op_write_atomic(self, params: Dict[str, Any], payload: bytes) -> Tuple[Any, bytes]:
        destination = self.path(params["path"], may_not_exist=True)
        destination.parent.mkdir(parents=True, exist_ok=True)
        expected = params.get("sha256")
        actual = hashlib.sha256(payload).hexdigest()
        if expected and actual != expected:
            raise ValueError("payload SHA-256 mismatch")
        fd, temporary = tempfile.mkstemp(prefix=".sshctx-", dir=str(destination.parent))
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, destination)
        except BaseException:
            try: os.unlink(temporary)
            except OSError: pass
            raise
        return {"path": str(destination), "bytes": len(payload), "sha256": actual}, b""

    def op_write_chunk(self, params: Dict[str, Any], payload: bytes) -> Tuple[Any, bytes]:
        destination = self.path(params["path"], may_not_exist=True)
        destination.parent.mkdir(parents=True, exist_ok=True)
        part = destination.parent / (destination.name + ".sshctx-part")
        offset = max(0, int(params.get("offset", 0)))
        if params.get("reset"):
            if offset != 0: raise ValueError("reset requires offset=0")
            try: part.unlink()
            except FileNotFoundError: pass
        mode = "r+b" if part.exists() else "w+b"
        with part.open(mode) as handle:
            handle.seek(0, os.SEEK_END)
            current = handle.tell()
            if current != offset:
                raise ValueError("chunk offset mismatch: remote=%d request=%d" % (current, offset))
            handle.write(payload); handle.flush(); os.fsync(handle.fileno())
        return {"path": str(destination), "next_offset": offset + len(payload)}, b""

    def op_chunk_status(self, params: Dict[str, Any], payload: bytes) -> Tuple[Any, bytes]:
        destination = self.path(params["path"], may_not_exist=True)
        part = destination.parent / (destination.name + ".sshctx-part")
        return {"path": str(destination), "offset": part.stat().st_size if part.exists() else 0}, b""

    def op_commit_chunks(self, params: Dict[str, Any], payload: bytes) -> Tuple[Any, bytes]:
        destination = self.path(params["path"], may_not_exist=True)
        part = destination.parent / (destination.name + ".sshctx-part")
        actual = sha256_file(part)
        if actual != params["sha256"]: raise ValueError("assembled file SHA-256 mismatch")
        os.replace(part, destination)
        return {"path": str(destination), "sha256": actual, "bytes": destination.stat().st_size}, b""

    def op_processes(self, params: Dict[str, Any], payload: bytes) -> Tuple[Any, bytes]:
        completed = subprocess.run(["ps", "-eo", "pid=,ppid=,etimes=,stat=,args="], stdout=subprocess.PIPE, check=False)
        lines = completed.stdout.decode("utf-8", "replace").splitlines()
        pattern = params.get("pattern")
        if pattern: lines = [line for line in lines if pattern in line]
        return {"processes": lines[:2000]}, b""

    def op_gpu_status(self, params: Dict[str, Any], payload: bytes) -> Tuple[Any, bytes]:
        query = "index,name,uuid,memory.total,memory.used,utilization.gpu,temperature.gpu"
        completed = subprocess.run(["nvidia-smi", "--query-gpu=" + query, "--format=csv,noheader,nounits"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        if completed.returncode:
            raise RuntimeError(completed.stderr.decode("utf-8", "replace").strip() or "nvidia-smi failed")
        gpus = []
        for line in completed.stdout.decode().splitlines():
            values = [part.strip() for part in line.split(",")]
            gpus.append(dict(zip(["index", "name", "uuid", "memory_total_mib", "memory_used_mib", "utilization_percent", "temperature_c"], values)))
        apps = subprocess.run(["nvidia-smi", "--query-compute-apps=gpu_uuid,pid,process_name,used_memory", "--format=csv,noheader,nounits"], stdout=subprocess.PIPE, check=False)
        return {"gpus": gpus, "compute_processes": apps.stdout.decode("utf-8", "replace").splitlines()}, b""

    def jobs_root(self) -> pathlib.Path:
        root = pathlib.Path.home() / ".sshctx" / "jobs"
        root.mkdir(parents=True, exist_ok=True)
        return root

    def op_job_start(self, params: Dict[str, Any], payload: bytes) -> Tuple[Any, bytes]:
        self.path(params["cwd"])
        if bool(params.get("argv")) == bool(params.get("command")):
            raise ValueError("provide exactly one of argv or command")
        job_id = str(uuid.uuid4())
        job_dir = self.jobs_root() / job_id
        job_dir.mkdir(mode=0o700)
        request_path = job_dir / "request.json"
        request_path.write_text(json.dumps(params, ensure_ascii=False), encoding="utf-8")
        (job_dir / "state.json").write_text(json.dumps({"job_id": job_id, "state": "starting", "supervisor_pid": None, "created_at": time.time()}), encoding="utf-8")
        process = subprocess.Popen([sys.executable, str(pathlib.Path(__file__).resolve()), "job-run", str(job_dir)],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   start_new_session=True, close_fds=True)
        state = json.loads((job_dir / "state.json").read_text(encoding="utf-8"))
        if state.get("state") == "starting":
            state["supervisor_pid"] = process.pid
            (job_dir / "state.json").write_text(json.dumps(state), encoding="utf-8")
        return {"job_id": job_id, "state": state.get("state", "starting"), "supervisor_pid": process.pid}, b""

    def _job_dir(self, job_id: str) -> pathlib.Path:
        if not re.fullmatch(r"[0-9a-f-]{36}", job_id):
            raise ValueError("invalid sshctx job id")
        directory = self.jobs_root() / job_id
        if not directory.is_dir(): raise FileNotFoundError("unknown sshctx job id")
        return directory

    def op_job_output(self, params: Dict[str, Any], payload: bytes) -> Tuple[Any, bytes]:
        directory = self._job_dir(params["job_id"])
        offset = max(0, int(params.get("offset", 0)))
        limit = min(4 * 1024 * 1024, max(1, int(params.get("limit", 1024 * 1024))))
        def chunk(name: str) -> Tuple[str, int]:
            path = directory / name
            if not path.exists(): return "", offset
            with path.open("rb") as handle:
                handle.seek(offset); data = handle.read(limit)
            return data.decode("utf-8", "replace"), offset + len(data)
        stdout, stdout_next = chunk("stdout.log")
        stderr, stderr_next = chunk("stderr.log")
        state = json.loads((directory / "state.json").read_text(encoding="utf-8"))
        if (directory / "exit.json").exists(): state.update(json.loads((directory / "exit.json").read_text(encoding="utf-8")))
        return {"state": state, "stdout": stdout, "stderr": stderr, "offset": offset,
                "stdout_next_offset": stdout_next, "stderr_next_offset": stderr_next}, b""

    def op_job_kill(self, params: Dict[str, Any], payload: bytes) -> Tuple[Any, bytes]:
        directory = self._job_dir(params["job_id"])
        state = json.loads((directory / "state.json").read_text(encoding="utf-8"))
        pid = int(state["supervisor_pid"])
        os.killpg(pid, signal.SIGTERM)
        return {"job_id": params["job_id"], "signal": "SIGTERM"}, b""

    def op_query(self, params: Dict[str, Any], payload: bytes) -> Tuple[Any, bytes]:
        results = []
        for operation in params.get("operations", []):
            method = operation["method"]
            if method not in {"stat", "read", "grep", "glob", "processes", "gpu_status", "job_output"}:
                raise PermissionError("remote_query only permits read-only operations")
            result, data = self.dispatch(method, operation.get("params", {}), b"")
            if data: result["text"] = data.decode("utf-8", "replace")
            results.append({"method": method, "result": result})
        return {"results": results}, b""


def serve(allowed_roots: Iterable[str]) -> int:
    agent = Agent(allowed_roots)
    source, sink = sys.stdin.buffer, sys.stdout.buffer
    sink_lock = threading.Lock()
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=32, thread_name_prefix="sshctx")

    def respond(request: Dict[str, Any], payload: bytes) -> None:
        try:
            result, response_payload = agent.dispatch(request["method"], request.get("params", {}), payload)
            response = {"id": request["id"], "ok": True, "result": result, "error": None, "metadata": {"agent_version": AGENT_VERSION}}
        except BaseException as error:
            response_payload = b""
            response = {"id": request.get("id", ""), "ok": False, "result": None, "error": str(error),
                        "metadata": {"error_type": type(error).__name__}}
        with sink_lock:
            write_frame(sink, response, response_payload)

    while True:
        try:
            request, payload = read_frame(source)
        except EOFError:
            executor.shutdown(wait=False)
            return 0
        executor.submit(respond, request, payload)


def run_job(job_dir_raw: str) -> int:
    job_dir = pathlib.Path(job_dir_raw).resolve(strict=True)
    request = json.loads((job_dir / "request.json").read_text(encoding="utf-8"))
    argv = request.get("argv") or ["/bin/bash", "-lc", request["command"]]
    env = os.environ.copy(); env.update({str(k): str(v) for k, v in request.get("env", {}).items()})
    with (job_dir / "stdout.log").open("ab", buffering=0) as stdout, (job_dir / "stderr.log").open("ab", buffering=0) as stderr:
        child = subprocess.Popen(argv, cwd=request["cwd"], env=env, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr)
        state = {"job_id": job_dir.name, "state": "running", "supervisor_pid": os.getpid(), "pid": child.pid, "started_at": time.time()}
        (job_dir / "state.json").write_text(json.dumps(state), encoding="utf-8")
        code = child.wait()
    exit_state = {"state": "exited", "exit_code": code, "signal": -code if code < 0 else None, "finished_at": time.time()}
    temporary = job_dir / "exit.json.tmp"; temporary.write_text(json.dumps(exit_state), encoding="utf-8"); os.replace(temporary, job_dir / "exit.json")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    serve_parser = sub.add_parser("serve")
    serve_parser.add_argument("--allowed-roots-json", required=True)
    job_parser = sub.add_parser("job-run")
    job_parser.add_argument("job_dir")
    args = parser.parse_args()
    if args.command == "serve": return serve(json.loads(args.allowed_roots_json))
    if args.command == "job-run": return run_job(args.job_dir)
    return 2


if __name__ == "__main__":
    try: raise SystemExit(main())
    except KeyboardInterrupt: raise SystemExit(130)
