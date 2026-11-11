"""Bounded regular-file stream I/O, JSON tree validation, and RFC3339 helpers for wellmanifest/jsonl."""

from __future__ import annotations

import errno
import hashlib
import json
import math
import os
import re
import stat
from datetime import datetime
from pathlib import Path
from typing import Any

MAX_LINE_BYTES = 1_048_576
MAX_STREAM_BYTES = 16 * 1_048_576
MAX_JSON_DEPTH = 64
RFC3339_TIMESTAMP = re.compile(
    r"\A\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.(\d{1,9}))?(?:[Zz]|[+-]\d{2}:\d{2})\Z"
)
_PATH_TRAVERSAL_RE = re.compile(r"(?:^|[/\\])\.\.(?:[/\\]|\Z)")

__all__ = [
    "MAX_JSON_DEPTH",
    "MAX_LINE_BYTES",
    "MAX_STREAM_BYTES",
    "RFC3339_TIMESTAMP",
    "JsonlError",
    "_check_no_symlink_ancestors",
    "_check_utf8_str",
    "_has_control_or_traversal",
    "_no_duplicates",
    "_parse_finite_float",
    "_parse_finite_int",
    "_read_regular_stream_bytes",
    "_reject_constant",
    "_validate_json_tree",
    "_validate_rfc3339",
    "canonical_bytes",
    "sha256",
]


class JsonlError(ValueError):
    def __init__(self, code: str, message: str, line: int | None = None):
        self.code = code
        self.line = line
        where = f"line {line}: " if line is not None else ""
        super().__init__(f"{code}: {where}{message}")


def _check_utf8_str(value: str) -> None:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise JsonlError("JSONL-UTF8", "lone UTF-16 surrogate is forbidden") from None


def _has_control_or_traversal(value: str) -> bool:
    if any(ord(ch) < 0x20 or 0x7F <= ord(ch) <= 0x9F for ch in value):
        return True
    return bool(_PATH_TRAVERSAL_RE.search(value))


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise JsonlError("JSONL-DUPLICATE-KEY", f"duplicate object key {key!r}")
        result[key] = value
    return result


def _reject_constant(token: str) -> Any:
    raise JsonlError("JSONL-NUMBER", f"non-finite number {token}")


def _parse_finite_float(token: str) -> float:
    parsed = float(token)
    if not math.isfinite(parsed):
        raise JsonlError("JSONL-NUMBER", f"non-finite number {token}")
    return parsed


def _parse_finite_int(token: str) -> int:
    digits = token.removeprefix("-")
    if len(digits) > 309:
        raise JsonlError("JSONL-NUMBER", "integer magnitude exceeds finite range")
    parsed = int(token)
    try:
        ok = math.isfinite(float(parsed))
    except OverflowError:
        ok = False
    if not ok:
        raise JsonlError("JSONL-NUMBER", "integer magnitude exceeds finite range")
    return parsed


def _validate_json_tree(root: Any) -> None:
    stack: list[tuple[Any, int]] = [(root, 0)]
    while stack:
        cur, depth = stack.pop()
        if depth > MAX_JSON_DEPTH:
            raise JsonlError(
                "JSONL-DEPTH", f"JSON nesting depth exceeds {MAX_JSON_DEPTH}"
            )
        if isinstance(cur, dict):
            for key, nested in cur.items():
                if not isinstance(key, str):
                    raise JsonlError("JSONL-SYNTAX", "JSON object keys must be strings")
                _check_utf8_str(key)
                stack.append((nested, depth + 1))
        elif isinstance(cur, list):
            for nested in cur:
                stack.append((nested, depth + 1))
        elif isinstance(cur, str):
            _check_utf8_str(cur)
        elif isinstance(cur, float):
            if not math.isfinite(cur):
                raise JsonlError("JSONL-NUMBER", "non-finite float is forbidden")
        elif isinstance(cur, int) and not isinstance(cur, bool):
            try:
                ok = math.isfinite(float(cur))
            except OverflowError:
                ok = False
            if not ok:
                raise JsonlError(
                    "JSONL-NUMBER", "integer magnitude exceeds finite range"
                )


def _check_no_symlink_ancestors(path: str | Path) -> None:
    raw_path = os.fspath(path)
    path_obj = Path(raw_path)
    raw_parts = path_obj.parts[:-1]
    if path_obj.is_absolute():
        cur = Path(path_obj.anchor)
        walk_parts = raw_parts[1:]
    else:
        cwd = Path.cwd()
        if len(cwd.parts) > 2 and cwd.is_symlink():
            raise JsonlError("JSONL-IO", f"symlink ancestor is forbidden: {cwd}")
        for anc in cwd.parents:
            if len(anc.parts) > 2 and anc.is_symlink():
                raise JsonlError("JSONL-IO", f"symlink ancestor is forbidden: {anc}")
        cur = cwd
        walk_parts = raw_parts
    for part in walk_parts:
        if part in ("", "."):
            continue
        cur = cur / part
        if part != ".." and len(cur.parts) > 2 and cur.is_symlink():
            raise JsonlError("JSONL-IO", f"symlink ancestor is forbidden: {cur}")
    abs_path = Path(os.path.abspath(raw_path))
    if any(anc.is_symlink() for anc in abs_path.parents if len(anc.parts) > 2):
        raise JsonlError("JSONL-IO", f"symlink ancestor is forbidden: {path_obj}")


def _read_regular_stream_bytes(path: Path) -> bytes:
    raw_path = os.fspath(path)
    _check_no_symlink_ancestors(raw_path)
    try:
        lst = os.lstat(raw_path)
    except OSError as exc:
        raise JsonlError("JSONL-IO", f"cannot stat stream: {exc}") from None
    if stat.S_ISLNK(lst.st_mode):
        raise JsonlError("JSONL-IO", "symlink JSONL input is forbidden")
    if not stat.S_ISREG(lst.st_mode):
        raise JsonlError("JSONL-IO", "JSONL input must be a regular file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(raw_path, flags)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise JsonlError("JSONL-IO", "symlink JSONL input is forbidden") from None
        raise JsonlError("JSONL-IO", f"cannot open stream: {exc}") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise JsonlError("JSONL-IO", "JSONL input must be a regular file")
        if (st.st_dev, st.st_ino) != (lst.st_dev, lst.st_ino):
            raise JsonlError("JSONL-IO", "JSONL input inode changed during open")
        if st.st_size > MAX_STREAM_BYTES:
            raise JsonlError("JSONL-LIMIT", "stream exceeds 16 MiB")
        chunks = bytearray()
        while True:
            chunk = os.read(fd, min(65536, MAX_STREAM_BYTES + 1 - len(chunks)))
            if not chunk:
                break
            chunks.extend(chunk)
            if len(chunks) > MAX_STREAM_BYTES:
                raise JsonlError("JSONL-LIMIT", "stream exceeds 16 MiB")
        return bytes(chunks)
    finally:
        os.close(fd)


def canonical_bytes(value: Any) -> bytes:
    _validate_json_tree(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def sha256(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _validate_rfc3339(value: Any) -> None:
    if not isinstance(value, str):
        raise JsonlError("JSONL-TIME", "occurredAt must be RFC3339 date-time")
    match = RFC3339_TIMESTAMP.fullmatch(value)
    if match is None:
        raise JsonlError("JSONL-TIME", "occurredAt must be RFC3339 date-time")
    normalized = value[:-1] + "+00:00" if value.endswith(("Z", "z")) else value
    frac = match.group(1)
    if frac is not None and len(frac) > 6:
        dot_idx = normalized.index(".")
        tz_idx = dot_idx + 1 + len(frac)
        normalized = f"{normalized[:dot_idx]}.{frac[:6]}{normalized[tz_idx:]}"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        raise JsonlError("JSONL-TIME", "occurredAt must be RFC3339 date-time") from None
    if parsed.tzinfo is None:
        raise JsonlError("JSONL-TIME", "occurredAt must be RFC3339 date-time")
