"""Reference Pre-Release Transactional Compensation Lease & CAS Fencing Verifier.

Implements IETF Internet-Draft draft-durga-agent-tx-compensation-lease-00 for
autonomous agents executing state-mutating tool calls over systems of record.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

VALID_MODES = {"INVERSE_OP", "SAGA_STEP", "SNAPSHOT_RESTORE", "ESCROW_HOLD"}


def verify_compensation_lease(
    *,
    lease_id: str,
    mode: str,
    t_req_ms: int,
    t_granted_ms: int,
    expected_cas_epoch: int,
    current_cas_epoch: int,
    now_epoch_ms: int,
    lease_expires_epoch_ms: int,
) -> dict[str, Any]:
    """Fail-closed verifier for Pre-Release Transactional Compensation Leases."""
    if mode not in VALID_MODES:
        return {"status": "ABORT", "reason_code": "ERR_INVALID_COMPENSATION_MODE"}
    if now_epoch_ms > lease_expires_epoch_ms:
        return {"status": "ABORT", "reason_code": "ERR_LEASE_EXPIRED"}
    if t_req_ms <= 0 or t_granted_ms <= 0 or t_req_ms > t_granted_ms:
        return {
            "status": "ABORT",
            "reason_code": "ERR_RECOVERY_WINDOW_EXCEEDED",
            "t_req_ms": t_req_ms,
            "t_granted_ms": t_granted_ms,
        }
    if expected_cas_epoch != current_cas_epoch:
        return {
            "status": "ABORT",
            "reason_code": "ERR_CAS_FENCE_CONFLICT",
            "expected_cas_epoch": expected_cas_epoch,
            "current_cas_epoch": current_cas_epoch,
        }

    fenced_receipt = {
        "lease_id": lease_id,
        "mode": mode,
        "t_req_ms": t_req_ms,
        "t_granted_ms": t_granted_ms,
        "committed_cas_epoch": current_cas_epoch + 1,
        "lease_expires_epoch_ms": lease_expires_epoch_ms,
    }
    digest = hashlib.sha256(
        json.dumps(fenced_receipt, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {
        "status": "COMMIT_ALLOWED",
        "reason_code": "OK_LEASE_AND_CAS_VERIFIED",
        "fenced_receipt": fenced_receipt,
        "receipt_sha256": digest,
    }
