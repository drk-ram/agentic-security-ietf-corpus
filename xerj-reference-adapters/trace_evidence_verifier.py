"""Reference Version-Pinned Trace-to-Evidence & Calibrated Abstention Verifier.

Bridges xerj-org/xerj#1789 (Version-Pinned Answers + Trace-to-Evidence Report) and
#1786 (Calibrated Confidence / Abstain / Escalate) with IETF Internet-Draft
draft-durga-agenttrust-trace-verification-00.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any


def jcs_canonical_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def verify_pinned_claim_and_calibrate(
    *,
    claim_id: str,
    claim_text: str,
    corpus_slug: str,
    commit_or_pack_sha: str,
    file_path: str,
    byte_start: int,
    byte_end: int,
    source_bytes: bytes,
    expected_span_sha256: str,
    calibrated_confidence: float,
    abstain_threshold: float = 0.80,
) -> dict[str, Any]:
    """Verifies exact byte-span evidence and emits an explicit abstain/escalate envelope."""
    if len(commit_or_pack_sha) != 40:
        return {
            "claim_id": claim_id,
            "decision": "ABSTAIN",
            "escalate": True,
            "evidence_gap": "invalid_or_unpinned_commit_sha",
        }

    if byte_start < 0 or byte_end > len(source_bytes) or byte_start >= byte_end:
        return {
            "claim_id": claim_id,
            "decision": "ABSTAIN",
            "escalate": True,
            "evidence_gap": "byte_span_out_of_bounds",
        }

    span = source_bytes[byte_start:byte_end]
    actual_sha256 = hashlib.sha256(span).hexdigest()
    if actual_sha256 != expected_span_sha256.lower():
        return {
            "claim_id": claim_id,
            "decision": "ABSTAIN",
            "escalate": True,
            "evidence_gap": "byte_span_digest_mismatch",
            "expected_sha256": expected_span_sha256.lower(),
            "actual_sha256": actual_sha256,
        }

    receipt_body = {
        "claim_id": claim_id,
        "claim_text": claim_text,
        "corpus_slug": corpus_slug,
        "commit_or_pack_sha": commit_or_pack_sha.lower(),
        "file_path": file_path,
        "byte_span": [byte_start, byte_end],
        "span_sha256": actual_sha256,
        "hash_alg": "sha-256",
    }
    receipt_digest = hashlib.sha256(jcs_canonical_bytes(receipt_body)).hexdigest()

    if calibrated_confidence < abstain_threshold:
        return {
            "claim_id": claim_id,
            "decision": "ABSTAIN",
            "escalate": True,
            "calibrated_confidence": round(calibrated_confidence, 4),
            "evidence_gap": "calibrated_confidence_below_threshold",
            "trace_receipt": receipt_body,
            "receipt_digest_sha256": receipt_digest,
        }

    return {
        "claim_id": claim_id,
        "decision": "ANSWER",
        "escalate": False,
        "calibrated_confidence": round(calibrated_confidence, 4),
        "evidence_gap": None,
        "trace_receipt": receipt_body,
        "receipt_digest_sha256": receipt_digest,
    }
