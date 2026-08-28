#!/usr/bin/env python3
"""Dependency-free Wellmanifest JSONL framing validator and deterministic sealer."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

ZERO_HASH = "0" * 64
MAX_LINE_BYTES = 1_048_576
HEX64 = re.compile(r"^[a-f0-9]{64}$")
TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,159}$")
RECORD_TYPE = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)+$")
PRODUCER = re.compile(r"^(human|agent|service):[A-Za-z0-9._:-]+$")
CANDIDATE_KEYS = {"schema", "recordType", "sequence", "dsl", "correlationId", "payload"}
RECORD_KEYS = CANDIDATE_KEYS | {
    "recordId", "producer", "occurredAt", "inputHash", "previousHash",
    "recordHash", "receiptRef",
}
DSL_KEYS = {"manifestId", "schemaRef", "grammarRef"}
RUNTIME_OWNED = RECORD_KEYS - CANDIDATE_KEYS


class JsonlError(ValueError):
    def __init__(self, code: str, message: str, line: int | None = None):
        self.code = code
        self.line = line
        where = f"line {line}: " if line is not None else ""
        super().__init__(f"{code}: {where}{message}")


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise JsonlError("JSONL-DUPLICATE-KEY", f"duplicate object key {key!r}")
        result[key] = value
    return result


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def sha256(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _require_exact_keys(value: dict[str, Any], expected: set[str], code: str) -> None:
    missing = sorted(expected - value.keys())
    extra = sorted(value.keys() - expected)
    if missing or extra:
        raise JsonlError(code, f"envelope keys differ; missing={missing}, extra={extra}")


def _validate_common(value: dict[str, Any], sequence: int) -> None:
    if value["sequence"] != sequence or isinstance(value["sequence"], bool):
        raise JsonlError("JSONL-SEQUENCE", f"expected sequence {sequence}")
    if not isinstance(value["recordType"], str) or not RECORD_TYPE.fullmatch(value["recordType"]):
        raise JsonlError("JSONL-RECORD-TYPE", "recordType is not a namespaced token")
    if not isinstance(value["correlationId"], str) or not TOKEN.fullmatch(value["correlationId"]):
        raise JsonlError("JSONL-CORRELATION", "correlationId is invalid")
    if not isinstance(value["payload"], dict):
        raise JsonlError("JSONL-PAYLOAD", "payload must be an object")
    dsl = value["dsl"]
    if not isinstance(dsl, dict) or set(dsl) != DSL_KEYS:
        raise JsonlError("JSONL-DSL-BINDING", "dsl must contain exactly manifestId, schemaRef and grammarRef")
    if not all(isinstance(dsl[key], str) and dsl[key] for key in DSL_KEYS):
        raise JsonlError("JSONL-DSL-BINDING", "dsl references must be non-empty strings")


def validate_candidate(value: Any, sequence: int) -> None:
    if not isinstance(value, dict):
        raise JsonlError("JSONL-TOPLEVEL", "each line must contain one JSON object")
    _require_exact_keys(value, CANDIDATE_KEYS, "JSONL-CANDIDATE-FIELDS")
    if value["schema"] != "wellmanifest.jsonl/candidate/v1":
        raise JsonlError("JSONL-SCHEMA", "candidate schema is unsupported")
    if RUNTIME_OWNED.intersection(value):
        raise JsonlError("JSONL-MODEL-AUTHORITY", "candidate contains runtime-owned fields")
    _validate_common(value, sequence)


def validate_record(value: Any, sequence: int, previous_hash: str) -> None:
    if not isinstance(value, dict):
        raise JsonlError("JSONL-TOPLEVEL", "each line must contain one JSON object")
    _require_exact_keys(value, RECORD_KEYS, "JSONL-RECORD-FIELDS")
    if value["schema"] != "wellmanifest.jsonl/record/v1":
        raise JsonlError("JSONL-SCHEMA", "record schema is unsupported")
    _validate_common(value, sequence)
    if not isinstance(value["recordId"], str) or not value["recordId"].startswith("record:"):
        raise JsonlError("JSONL-RECORD-ID", "recordId must use record: namespace")
    if not isinstance(value["producer"], str) or not PRODUCER.fullmatch(value["producer"]):
        raise JsonlError("JSONL-PRODUCER", "producer identity is invalid")
    try:
        datetime.fromisoformat(value["occurredAt"].replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        raise JsonlError("JSONL-TIME", "occurredAt must be RFC3339 date-time") from None
    for key in ("inputHash", "previousHash", "recordHash"):
        if not isinstance(value[key], str) or not HEX64.fullmatch(value[key]):
            raise JsonlError("JSONL-HASH", f"{key} must be lowercase SHA-256")
    if value["previousHash"] != previous_hash:
        raise JsonlError("JSONL-CHAIN", "previousHash does not bind the prior record")
    candidate = {key: value[key] for key in CANDIDATE_KEYS}
    candidate["schema"] = "wellmanifest.jsonl/candidate/v1"
    if value["inputHash"] != sha256(candidate):
        raise JsonlError("JSONL-INPUT-HASH", "inputHash does not bind the candidate")
    unhashed = dict(value)
    unhashed.pop("recordHash")
    if value["recordHash"] != sha256(unhashed):
        raise JsonlError("JSONL-RECORD-HASH", "recordHash does not bind the canonical record")
    receipt = value["receiptRef"]
    if receipt is not None and (not isinstance(receipt, str) or not receipt.startswith("receipt://")):
        raise JsonlError("JSONL-RECEIPT", "receiptRef must be null or receipt:// URI")


def read_stream(path: Path, profile: str) -> list[dict[str, Any]]:
    raw = path.read_bytes()
    if raw.startswith(b"\xef\xbb\xbf"):
        raise JsonlError("JSONL-BOM", "UTF-8 BOM is forbidden")
    if raw and not raw.endswith(b"\n"):
        raise JsonlError("JSONL-TRUNCATED", "stream must end with LF")
    if b"\r" in raw:
        raise JsonlError("JSONL-LINE-END", "CR and CRLF are forbidden")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise JsonlError("JSONL-UTF8", f"invalid UTF-8: {exc}") from None
    records: list[dict[str, Any]] = []
    previous_hash = ZERO_HASH
    for line_number, line in enumerate(text.splitlines(), 1):
        encoded = line.encode("utf-8")
        if not line:
            raise JsonlError("JSONL-BLANK", "blank lines are forbidden", line_number)
        if len(encoded) > MAX_LINE_BYTES:
            raise JsonlError("JSONL-LIMIT", "line exceeds 1 MiB", line_number)
        try:
            value = json.loads(line, object_pairs_hook=_no_duplicates, parse_constant=lambda token: (_ for _ in ()).throw(JsonlError("JSONL-NUMBER", f"non-finite number {token}")))
        except JsonlError as exc:
            exc.line = line_number
            raise
        except json.JSONDecodeError as exc:
            raise JsonlError("JSONL-SYNTAX", exc.msg, line_number) from None
        try:
            if profile == "candidate":
                validate_candidate(value, line_number)
            else:
                validate_record(value, line_number, previous_hash)
                previous_hash = value["recordHash"]
        except JsonlError as exc:
            raise JsonlError(exc.code, str(exc).split(": ", 1)[-1], line_number) from None
        records.append(value)
    return records


def seal(candidates: list[dict[str, Any]], producer: str, occurred_at: str) -> list[dict[str, Any]]:
    if not PRODUCER.fullmatch(producer):
        raise JsonlError("JSONL-PRODUCER", "producer identity is invalid")
    datetime.fromisoformat(occurred_at.replace("Z", "+00:00"))
    result: list[dict[str, Any]] = []
    previous_hash = ZERO_HASH
    for sequence, candidate in enumerate(candidates, 1):
        validate_candidate(candidate, sequence)
        input_hash = sha256(candidate)
        record_seed = f"{candidate['correlationId']}:{sequence}:{input_hash}"
        record = dict(candidate)
        record["schema"] = "wellmanifest.jsonl/record/v1"
        record.update({
            "recordId": f"record:{hashlib.sha256(record_seed.encode()).hexdigest()[:32]}",
            "producer": producer,
            "occurredAt": occurred_at,
            "inputHash": input_hash,
            "previousHash": previous_hash,
            "receiptRef": None,
        })
        record["recordHash"] = sha256(record)
        previous_hash = record["recordHash"]
        result.append(record)
    return result


def _write(records: list[dict[str, Any]]) -> None:
    for record in records:
        print(canonical_bytes(record).decode("utf-8"))


def self_test() -> None:
    candidate = {
        "schema": "wellmanifest.jsonl/candidate/v1", "recordType": "test.item", "sequence": 1,
        "dsl": {"manifestId": "test.dsl", "schemaRef": "schema://test/v1", "grammarRef": "grammar://test/v1"},
        "correlationId": "cycle:test", "payload": {"ok": True},
    }
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        candidate_path = root / "candidate.jsonl"
        candidate_path.write_bytes(canonical_bytes(candidate) + b"\n")
        candidates = read_stream(candidate_path, "candidate")
        records = seal(candidates, "service:self-test", "2026-08-28T00:00:00Z")
        record_path = root / "record.jsonl"
        record_path.write_bytes(b"".join(canonical_bytes(item) + b"\n" for item in records))
        read_stream(record_path, "record")
        cases = {
            "truncated": canonical_bytes(candidate),
            "blank": canonical_bytes(candidate) + b"\n\n",
            "array": b"[]\n",
            "duplicate": b'{"schema":"x","schema":"y"}\n',
            "bom": b"\xef\xbb\xbf" + canonical_bytes(candidate) + b"\n",
        }
        for name, content in cases.items():
            bad = root / f"{name}.jsonl"
            bad.write_bytes(content)
            try:
                read_stream(bad, "candidate")
            except JsonlError:
                continue
            raise AssertionError(f"negative case passed: {name}")
    print(json.dumps({"schema": "wellmanifest.jsonl/self-test/v1", "ok": True, "cases": 7}))


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    validate_parser = sub.add_parser("validate")
    validate_parser.add_argument("--profile", choices=("candidate", "record"), required=True)
    validate_parser.add_argument("--file", type=Path, required=True)
    seal_parser = sub.add_parser("seal")
    seal_parser.add_argument("--file", type=Path, required=True)
    seal_parser.add_argument("--producer", required=True)
    seal_parser.add_argument("--occurred-at", required=True)
    sub.add_parser("self-test")
    args = parser.parse_args()
    try:
        if args.command == "self-test":
            self_test()
        elif args.command == "validate":
            records = read_stream(args.file, args.profile)
            print(json.dumps({"schema": "wellmanifest.jsonl/validation/v1", "ok": True, "profile": args.profile, "records": len(records)}))
        else:
            _write(seal(read_stream(args.file, "candidate"), args.producer, args.occurred_at))
        return 0
    except (JsonlError, OSError, ValueError) as exc:
        print(json.dumps({"schema": "wellmanifest.jsonl/validation/v1", "ok": False, "error": str(exc)}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
