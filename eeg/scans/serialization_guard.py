"""Model and artifact serialization guard — the canonical EEG implementation.

In-process pickle opcode inspection for unsafe global imports without executing
payloads. Handles pickle, torch, keras, numpy, and zip-archived model formats.

This is the **sole** implementation for model serialization scanning in EEG.
All other modules (secfeature, tenant_platform.apps.scans) should import from here.
"""

from __future__ import annotations

import ast
import io
import pickletools  # nosec B403 — inspection only; never calls pickle.load
import re
import struct
import zipfile
from pathlib import Path
from typing import Any, BinaryIO, Dict, List, Optional, Set, Tuple

_TORCH_ZIP_MAGIC = [b"P", b"K", b"\x03", b"\x04"]
_MAGIC_NUMBER = 0x1950A86A20F9469CFC6C

_UNSAFE_GLOBALS: Dict[str, Dict[str, Any]] = {
    "CRITICAL": {
        "__builtin__": ["eval", "compile", "getattr", "apply", "exec", "open", "breakpoint", "__import__"],
        "builtins": ["eval", "compile", "getattr", "apply", "exec", "open", "breakpoint", "__import__"],
        "runpy": "*",
        "os": "*",
        "nt": "*",
        "posix": "*",
        "socket": "*",
        "subprocess": "*",
        "sys": "*",
        "operator": ["attrgetter"],
        "pty": "*",
        "pickle": "*",
        "_pickle": "*",
        "bdb": "*",
        "pdb": "*",
        "shutil": "*",
        "asyncio": "*",
    },
    "HIGH": {
        "webbrowser": "*",
        "httplib": "*",
        "requests.api": "*",
        "aiohttp.client": "*",
    },
    "MEDIUM": {},
    "LOW": {},
}


class _GenOpsError(Exception):
    def __init__(self, msg: str, globals_opt: Optional[Set[Tuple[str, str]]]):
        self.msg = msg
        self.globals = globals_opt
        super().__init__(msg)


def _get_magic_int_from_pickle_stream(data: BinaryIO) -> Optional[int]:
    try:
        for opcode, args, _pos in pickletools.genops(data):
            if "INT" in opcode.name or "LONG" in opcode.name:
                data.seek(0)
                return int(args)
    except ValueError:
        return None
    return None


def _list_global_imports(data: BinaryIO, *, multiple_pickles: bool = True) -> Set[Tuple[str, str]]:
    found: Set[Tuple[str, str]] = set()
    memo: Dict[Any, str] = {}
    last_byte = b"dummy"
    while last_byte != b"":
        try:
            ops: List[Tuple[Any, Any, Optional[int]]] = list(pickletools.genops(data))
        except Exception as exc:
            globals_opt = found if len(found) > 0 else None
            raise _GenOpsError(str(exc), globals_opt) from exc

        last_byte = data.read(1)
        data.seek(-1, 1)

        for n in range(len(ops)):
            op = ops[n]
            op_name = op[0].name
            op_value: str = str(op[1])

            if op_name == "MEMOIZE" and n > 0:
                memo[len(memo)] = str(ops[n - 1][1])
            elif op_name in ("PUT", "BINPUT", "LONG_BINPUT") and n > 0:
                memo[op_value] = str(ops[n - 1][1])
            elif op_name in ("GLOBAL", "INST"):
                parts = op_value.split(" ", 1)
                if len(parts) == 2:
                    found.add((parts[0], parts[1]))
            elif op_name == "STACK_GLOBAL":
                values: List[str] = []
                for offset in range(1, n):
                    if ops[n - offset][0].name in ("MEMOIZE", "PUT", "BINPUT", "LONG_BINPUT"):
                        continue
                    if ops[n - offset][0].name in ("GET", "BINGET", "LONG_BINGET"):
                        values.append(memo[int(ops[n - offset][1])])
                    elif ops[n - offset][0].name not in (
                        "SHORT_BINUNICODE", "UNICODE", "BINUNICODE", "BINUNICODE8"
                    ):
                        values.append("unknown")
                    else:
                        values.append(str(ops[n - offset][1]))
                    if len(values) == 2:
                        break
                if len(values) != 2:
                    raise ValueError(f"Found {len(values)} values for STACK_GLOBAL at {n} instead of 2.")
                found.add((values[1], values[0]))

        if not multiple_pickles:
            break

    return found


def _globals_to_issues(raw_globals: Set[Tuple[str, str]], source: str) -> List[Dict[str, Any]]:
    issues: List[Dict[str, Any]] = []
    severity_rank = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    for mod, name in raw_globals:
        matched: Optional[str] = None
        for sev in severity_rank:
            policies = _UNSAFE_GLOBALS.get(sev) or {}
            if mod not in policies:
                continue
            filt = policies[mod]
            if filt == "*":
                matched = sev
                break
            if isinstance(filt, list):
                for token in filt:
                    if token in name:
                        matched = sev
                        break
            if matched:
                break
        if "unknown" in mod or "unknown" in name:
            matched = "CRITICAL"
        if matched:
            issues.append({
                "severity": matched,
                "operator": {"module": mod, "operator": name, "source": source},
            })
    return issues


def _scan_pickle_stream(stream: BinaryIO, *, source: str, multiple_pickles: bool) -> Tuple[List[Dict[str, Any]], List[str]]:
    issues: List[Dict[str, Any]] = []
    errors: List[str] = []
    try:
        raw = _list_global_imports(stream, multiple_pickles=multiple_pickles)
    except _GenOpsError as exc:
        if exc.globals is not None:
            issues.extend(_globals_to_issues(exc.globals, source))
        else:
            errors.append(exc.msg)
        return issues, errors
    issues.extend(_globals_to_issues(raw, source))
    return issues, errors


def _is_torch_zip(data: BinaryIO) -> bool:
    start = data.tell()
    read_bytes = []
    byte = data.read(1)
    while byte != b"":
        read_bytes.append(byte)
        if len(read_bytes) == 4:
            break
        byte = data.read(1)
    data.seek(start)
    return read_bytes == _TORCH_ZIP_MAGIC


def _scan_zip_pickles(path: Path, *, max_member_bytes: int = 20_000_000) -> Tuple[List[Dict[str, Any]], List[str]]:
    issues: List[Dict[str, Any]] = []
    errors: List[str] = []
    try:
        with zipfile.ZipFile(path, "r") as zf:
            for name in zf.namelist():
                if name.endswith("/") or ".." in name:
                    continue
                low = name.lower()
                if not (low.endswith(".pkl") or low.endswith(".pickle") or low.endswith("data.pkl") or "/data/" in low.replace("\\", "/")):
                    continue
                try:
                    raw = zf.read(name)
                except zipfile.BadZipFile as exc:
                    errors.append(f"bad_zip:{exc}")
                    break
                if len(raw) > max_member_bytes:
                    errors.append(f"skipped_oversized_member:{name}")
                    continue
                bio = io.BytesIO(raw)
                part_issues, part_errs = _scan_pickle_stream(bio, source=f"{path.name}!{name}", multiple_pickles=True)
                issues.extend(part_issues)
                errors.extend(part_errs)
    except zipfile.BadZipFile as exc:
        errors.append(f"zip_error:{exc}")
    return issues, errors


def _scan_numpy_npy(path: Path) -> Tuple[List[Dict[str, Any]], List[str]]:
    issues: List[Dict[str, Any]] = []
    errors: List[str] = []
    raw = path.read_bytes()
    if len(raw) < 10 or raw[:6] != b"\x93NUMPY":
        return issues, errors
    ver_major, ver_minor = raw[6], raw[7]
    if ver_major == 1:
        hdr_len = struct.unpack("<H", raw[8:10])[0]
        header_start = 10
    elif ver_major == 2:
        hdr_len = struct.unpack("<I", raw[8:12])[0]
        header_start = 12
    else:
        errors.append("npy_unsupported_version")
        return issues, errors
    header_end = header_start + hdr_len
    if header_end > len(raw):
        errors.append("npy_truncated")
        return issues, errors
    header_bytes = raw[header_start:header_end]
    try:
        header = ast.literal_eval(header_bytes.decode("latin1").strip().replace("False", "False"))
    except (SyntaxError, ValueError, UnicodeDecodeError):
        errors.append("npy_header_parse_failed")
        return issues, errors
    if not isinstance(header, dict):
        return issues, errors
    descr = str(header.get("descr", ""))
    if "object" in descr.lower() or "|O" in descr or descr == "O":
        stream = io.BytesIO(raw[header_end:])
        return _scan_pickle_stream(stream, source=str(path), multiple_pickles=True)
    return issues, errors


def _scan_h5_lambda_heuristic(path: Path, *, max_read: int = 8_000_000) -> List[Dict[str, Any]]:
    issues: List[Dict[str, Any]] = []
    blob = path.read_bytes()[:max_read]
    if b"\x89HDF\r\n\x1a\n" not in blob[:16]:
        return issues
    if re.search(br'"class_name"\s*:\s*"Lambda"', blob) or re.search(br"'class_name'\s*:\s*'Lambda'", blob):
        issues.append({
            "severity": "MEDIUM",
            "operator": {"module": "keras_h5", "operator": "Lambda", "source": str(path)},
        })
    return issues


def scan_path(path: Path | str) -> Dict[str, Any]:
    """Scan a single file on disk; returns EEG-native report envelope."""
    path = Path(path) if isinstance(path, str) else path
    suffix = path.suffix.lower()
    issues: List[Dict[str, Any]] = []
    errors: List[str] = []

    try:
        if suffix in (".h5", ".keras"):
            issues.extend(_scan_h5_lambda_heuristic(path))
        elif suffix == ".npy":
            i2, e2 = _scan_numpy_npy(path)
            issues.extend(i2)
            errors.extend(e2)
        elif suffix in (".pkl", ".pickle", ".joblib", ".dill", ".dat", ".data"):
            data = path.read_bytes()
            stream = io.BytesIO(data)
            i2, e2 = _scan_pickle_stream(stream, source=str(path), multiple_pickles=True)
            issues.extend(i2)
            errors.extend(e2)
        elif suffix in (".pt", ".pth", ".ckpt", ".bin"):
            with path.open("rb") as fh:
                if _is_torch_zip(fh):
                    i2, e2 = _scan_zip_pickles(path)
                else:
                    fh.seek(0)
                    magic = _get_magic_int_from_pickle_stream(fh)
                    fh.seek(0)
                    if magic == _MAGIC_NUMBER:
                        i2, e2 = _scan_pickle_stream(fh, source=str(path), multiple_pickles=False)
                    else:
                        probe = fh.read(1)
                        fh.seek(0)
                        if probe == b"\x80":
                            i2, e2 = _scan_pickle_stream(fh, source=str(path), multiple_pickles=True)
                        else:
                            i2, e2 = [], ["pytorch_or_pickle_format_unrecognized"]
                issues.extend(i2)
                errors.extend(e2)
        else:
            raw_head = path.read_bytes()[:1]
            if raw_head == b"\x80":
                stream = io.BytesIO(path.read_bytes())
                i2, e2 = _scan_pickle_stream(stream, source=str(path), multiple_pickles=True)
                issues.extend(i2)
                errors.extend(e2)
            else:
                errors.append(f"extension_not_scanned:{suffix or 'none'}")
    except OSError as exc:
        errors.append(f"io_error:{exc}")

    if issues:
        exit_code = 1
    elif errors:
        exit_code = 2
    else:
        exit_code = 0
    stderr_tail = "; ".join(errors) if errors else ""
    report = {"issues": issues, "errors": errors, "source": str(path)}
    return {
        "exit_code": exit_code,
        "stderr_tail": stderr_tail[-4000:],
        "report": report,
        "issues": issues,
    }


def scan_pickle_bytes_for_issues(data: bytes, *, source_label: str = "inline") -> List[Dict[str, Any]]:
    """Scan raw pickle bytes; used by unit tests mirroring unsafe-operator fixtures."""
    stream = io.BytesIO(data)
    issues, _errs = _scan_pickle_stream(stream, source=source_label, multiple_pickles=True)
    return issues
