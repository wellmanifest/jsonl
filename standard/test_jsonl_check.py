"""Comprehensive unit and CLI tests for Wellmanifest JSONL framing and sealing."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import jsonl_check
import pytest


def _sample_candidate(sequence: int = 1, **overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "schema": "wellmanifest.jsonl/candidate/v1",
        "recordType": "status.transition",
        "sequence": sequence,
        "dsl": {
            "manifestId": "wellmanifest.status",
            "schemaRef": "https://wellmanifest.com/schemas/status/candidate.v1.json",
            "grammarRef": "https://github.com/wellmanifest/status/blob/main/grammars/status-candidate.gbnf",
        },
        "correlationId": "cycle:test-001",
        "payload": {"ok": True},
    }
    base.update(overrides)
    return base


def test_candidate_rejects_runtime_owned_fields_with_model_authority(
    tmp_path: Path,
) -> None:
    for runtime_field in sorted(jsonl_check.RUNTIME_OWNED):
        smuggled = _sample_candidate(**{runtime_field: "forged"})
        with pytest.raises(jsonl_check.JsonlError) as exc_info:
            jsonl_check.validate_candidate(smuggled, 1)
        assert exc_info.value.code == "JSONL-MODEL-AUTHORITY"

    # Even when a runtime-owned field replaces a required candidate key, model-authority wins.
    replaced = _sample_candidate()
    replaced.pop("payload")
    replaced["recordHash"] = "a" * 64
    path = tmp_path / "forged.jsonl"
    path.write_bytes(jsonl_check.canonical_bytes(replaced) + b"\n")
    with pytest.raises(jsonl_check.JsonlError) as exc_info:
        jsonl_check.read_stream(path, "candidate")
    assert exc_info.value.code == "JSONL-MODEL-AUTHORITY"
    assert exc_info.value.line == 1


def test_read_stream_splits_strictly_on_lf_preserving_unicode_separators(
    tmp_path: Path,
) -> None:
    # U+2028 (LS), U+2029 (PS), U+0085 (NEL), and U+000C inside JSON strings must NOT split lines.
    c1 = _sample_candidate(1, payload={"text": "alpha\u2028beta\u2029gamma\u0085delta"})
    c2 = _sample_candidate(2, payload={"text": "second line"})
    stream = tmp_path / "unicode_sep.jsonl"
    stream.write_bytes(
        jsonl_check.canonical_bytes(c1)
        + b"\n"
        + jsonl_check.canonical_bytes(c2)
        + b"\n"
    )

    parsed = jsonl_check.read_stream(stream, "candidate")
    assert len(parsed) == 2
    assert parsed[0]["payload"]["text"] == "alpha\u2028beta\u2029gamma\u0085delta"
    assert parsed[1]["sequence"] == 2


def test_framing_errors_bom_crlf_truncated_blank_limit_utf8_duplicates_nan(
    tmp_path: Path,
) -> None:
    valid_bytes = jsonl_check.canonical_bytes(_sample_candidate(1))

    cases: list[tuple[str, bytes, str, int | None]] = [
        ("bom", b"\xef\xbb\xbf" + valid_bytes + b"\n", "JSONL-BOM", None),
        ("truncated", valid_bytes, "JSONL-TRUNCATED", None),
        ("crlf", valid_bytes + b"\r\n", "JSONL-LINE-END", None),
        ("leading_blank", b"\n" + valid_bytes + b"\n", "JSONL-BLANK", 1),
        ("trailing_blank", valid_bytes + b"\n\n", "JSONL-BLANK", 2),
        ("bad_utf8", valid_bytes + b"\n\xff\xfe\n", "JSONL-UTF8", 2),
        ("duplicate_key", b'{"a":1,"a":2}\n', "JSONL-DUPLICATE-KEY", 1),
        ("nan_constant", b'{"a":NaN}\n', "JSONL-NUMBER", 1),
        (
            "oversize",
            b'{"pad":"' + (b"x" * jsonl_check.MAX_LINE_BYTES) + b'"}\n',
            "JSONL-LIMIT",
            1,
        ),
    ]
    for name, raw, expected_code, expected_line in cases:
        file_path = tmp_path / f"{name}.jsonl"
        file_path.write_bytes(raw)
        with pytest.raises(jsonl_check.JsonlError) as exc_info:
            jsonl_check.read_stream(file_path, "candidate")
        assert exc_info.value.code == expected_code
        assert exc_info.value.line == expected_line


def test_strict_rfc3339_in_seal_and_validate_record() -> None:
    candidates = [_sample_candidate(1)]
    invalid_timestamps = [
        "2026-08-28",
        "2026-08-28T00:00:00",
        "2026-08-28 00:00:00Z",
        "2026-02-30T00:00:00Z",
        "not-a-date",
    ]
    for bad_ts in invalid_timestamps:
        with pytest.raises(jsonl_check.JsonlError) as exc_info:
            jsonl_check.seal(candidates, "service:sealer", bad_ts)
        assert exc_info.value.code == "JSONL-TIME"

    records = jsonl_check.seal(
        candidates, "service:sealer", "2026-08-28T12:34:56.789+02:00"
    )
    assert len(records) == 1
    jsonl_check.validate_record(records[0], 1, jsonl_check.ZERO_HASH)

    for bad_ts in invalid_timestamps:
        tampered = dict(records[0], occurredAt=bad_ts)
        unhashed = dict(tampered)
        unhashed.pop("recordHash")
        tampered["recordHash"] = jsonl_check.sha256(unhashed)
        with pytest.raises(jsonl_check.JsonlError) as exc_info:
            jsonl_check.validate_record(tampered, 1, jsonl_check.ZERO_HASH)
        assert exc_info.value.code == "JSONL-TIME"


def test_record_id_receipt_ref_and_hash_chain_validation() -> None:
    candidates = [_sample_candidate(1), _sample_candidate(2)]
    sealed = jsonl_check.seal(candidates, "agent:validator", "2026-11-11T00:00:00Z")
    jsonl_check.validate_record(sealed[0], 1, jsonl_check.ZERO_HASH)
    jsonl_check.validate_record(sealed[1], 2, sealed[0]["recordHash"])

    # Empty record: prefix must fail JSONL-RECORD-ID
    bad_id = dict(sealed[0], recordId="record:")
    unhashed = {k: v for k, v in bad_id.items() if k != "recordHash"}
    bad_id["recordHash"] = jsonl_check.sha256(unhashed)
    with pytest.raises(jsonl_check.JsonlError) as exc_info:
        jsonl_check.validate_record(bad_id, 1, jsonl_check.ZERO_HASH)
    assert exc_info.value.code == "JSONL-RECORD-ID"

    # Empty or whitespace receipt:// URI must fail JSONL-RECEIPT
    for invalid_receipt in ("receipt://", "receipt://bad space", "http://example.com"):
        bad_receipt = dict(sealed[0], receiptRef=invalid_receipt)
        unhashed = {k: v for k, v in bad_receipt.items() if k != "recordHash"}
        bad_receipt["recordHash"] = jsonl_check.sha256(unhashed)
        with pytest.raises(jsonl_check.JsonlError) as exc_info:
            jsonl_check.validate_record(bad_receipt, 1, jsonl_check.ZERO_HASH)
        assert exc_info.value.code == "JSONL-RECEIPT"

    # Valid receipt:// URI passes when hash-bound
    good_receipt = dict(sealed[0], receiptRef="receipt://validator/run-001")
    unhashed = {k: v for k, v in good_receipt.items() if k != "recordHash"}
    good_receipt["recordHash"] = jsonl_check.sha256(unhashed)
    jsonl_check.validate_record(good_receipt, 1, jsonl_check.ZERO_HASH)

    # Chain tamper on record 2 fails JSONL-CHAIN
    with pytest.raises(jsonl_check.JsonlError) as exc_info:
        jsonl_check.validate_record(sealed[1], 2, jsonl_check.ZERO_HASH)
    assert exc_info.value.code == "JSONL-CHAIN"


def test_generation_request_profile_and_cli(tmp_path: Path) -> None:
    req = {
        "schema": "wellmanifest.jsonl/generation-request/v1",
        "targetDsl": "wellmanifest.status",
        "sourceDigest": "sha256:" + ("b" * 64),
        "maxRecords": 25,
    }
    req_path = tmp_path / "req.jsonl"
    req_path.write_bytes(jsonl_check.canonical_bytes(req) + b"\n")

    proc = subprocess.run(
        [
            sys.executable,
            str(Path(jsonl_check.__file__).resolve()),
            "validate",
            "--profile",
            "generation-request",
            "--file",
            str(req_path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload == {
        "schema": "wellmanifest.jsonl/validation/v1",
        "ok": True,
        "profile": "generation-request",
        "records": 1,
    }

    # Boolean maxRecords or forged runtime field rejected
    with pytest.raises(jsonl_check.JsonlError) as exc_info:
        jsonl_check.validate_generation_request(dict(req, maxRecords=True), 1)
    assert exc_info.value.code == "JSONL-MAX-RECORDS"

    with pytest.raises(jsonl_check.JsonlError) as exc_info:
        jsonl_check.validate_generation_request(dict(req, producer="agent:llm"), 1)
    assert exc_info.value.code == "JSONL-MODEL-AUTHORITY"


def test_symlink_traversal_number_surrogate_depth_rfc3339_and_uri_hardening(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    stream_path = real_dir / "valid.jsonl"
    stream_path.write_bytes(jsonl_check.canonical_bytes(_sample_candidate(1)) + b"\n")

    sym_file = tmp_path / "sym.jsonl"
    sym_file.symlink_to(stream_path)
    with pytest.raises(jsonl_check.JsonlError) as exc_info:
        jsonl_check.read_stream(sym_file, "candidate")
    assert exc_info.value.code == "JSONL-IO"

    sym_dir = tmp_path / "sym_dir"
    sym_dir.symlink_to(real_dir)
    with pytest.raises(jsonl_check.JsonlError) as exc_info:
        jsonl_check.read_stream(Path(f"{sym_dir}/../real/valid.jsonl"), "candidate")
    assert exc_info.value.code == "JSONL-IO"

    sub = tmp_path / "sub"
    sub.mkdir()
    monkeypatch.chdir(sub)
    with pytest.raises(jsonl_check.JsonlError) as exc_info:
        jsonl_check.read_stream(Path("../sym_dir/valid.jsonl"), "candidate")
    assert exc_info.value.code == "JSONL-IO"

    # Huge ints, overflow floats, lone surrogates, and excessive depth fail closed
    adversarial_lines = [
        ("huge_int", b'{"n":' + (b"9" * 5000) + b"}\n", "JSONL-NUMBER"),
        ("inf_float", b'{"n":1e999}\n', "JSONL-NUMBER"),
        (
            "surrogate",
            (
                json.dumps(_sample_candidate(1, payload={"bad": "__SURR__"})).replace(
                    "__SURR__", "\\ud800"
                )
                + "\n"
            ).encode("utf-8"),
            "JSONL-UTF8",
        ),
        (
            "deep",
            (("{" + '"a":') * 70 + "1" + ("}" * 70) + "\n").encode("utf-8"),
            "JSONL-DEPTH",
        ),
    ]
    for name, payload_bytes, expected_code in adversarial_lines:
        bad_file = real_dir / f"{name}.jsonl"
        bad_file.write_bytes(payload_bytes)
        with pytest.raises(jsonl_check.JsonlError) as exc_info:
            jsonl_check.read_stream(bad_file, "candidate")
        assert exc_info.value.code == expected_code

    # Programmatic lone surrogate in validate_candidate / seal also fails with JSONL-UTF8
    with pytest.raises(jsonl_check.JsonlError) as exc_info:
        jsonl_check.seal(
            [_sample_candidate(1, payload={"s": "\ud800"})],
            "service:s",
            "2026-11-11T00:00:00Z",
        )
    assert exc_info.value.code == "JSONL-UTF8"

    # 9-digit RFC3339 nanosecond accepted; 10-digit fractional rejected
    sealed_nano = jsonl_check.seal(
        [_sample_candidate(1)], "service:s", "2026-11-11T00:00:00.123456789Z"
    )
    jsonl_check.validate_record(sealed_nano[0], 1, jsonl_check.ZERO_HASH)
    with pytest.raises(jsonl_check.JsonlError) as exc_info:
        jsonl_check.seal(
            [_sample_candidate(1)], "service:s", "2026-11-11T00:00:00.1234567890Z"
        )
    assert exc_info.value.code == "JSONL-TIME"

    # Path traversal in receiptRef and dsl schemaRef rejected
    trav_rec = dict(sealed_nano[0], receiptRef="receipt://validator/../../etc/passwd")
    unhashed = {k: v for k, v in trav_rec.items() if k != "recordHash"}
    trav_rec["recordHash"] = jsonl_check.sha256(unhashed)
    with pytest.raises(jsonl_check.JsonlError) as exc_info:
        jsonl_check.validate_record(trav_rec, 1, jsonl_check.ZERO_HASH)
    assert exc_info.value.code == "JSONL-RECEIPT"

    trav_cand = _sample_candidate(
        1,
        dsl={
            "manifestId": "wellmanifest.status",
            "schemaRef": "schema://status/../../secret",
            "grammarRef": "grammar://status/v1",
        },
    )
    with pytest.raises(jsonl_check.JsonlError) as exc_info:
        jsonl_check.validate_candidate(trav_cand, 1)
    assert exc_info.value.code == "JSONL-DSL-BINDING"

    for py_file in sorted(Path(jsonl_check.__file__).resolve().parent.glob("*.py")):
        assert sum(1 for _ in py_file.open("r", encoding="utf-8")) < 500
