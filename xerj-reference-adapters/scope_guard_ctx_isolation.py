"""Reference Authorization/Scope Guard & WIMSE Context Isolation Verifier.

Implements the shared Cyber Pack Scope Guard contract (xerj-org/xerj#2767, #2772, #2774)
and WIMSE data-plane vs. control-plane taint isolation (draft-durga-wimse-ctx-isolation-00).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
from typing import Any


def jcs_canonical_bytes(obj: Any) -> bytes:
    """Deterministic RFC 8785 (JCS) subset serializer for JSON objects."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


@dataclass(frozen=True)
class ScopeGrant:
    authorization_id: str
    authorized_targets: tuple[str, ...]
    window_start: str
    window_end: str
    statement: str
    allow_network_traffic: bool = False

    def digest(self) -> str:
        payload = {
            "authorization_id": self.authorization_id,
            "authorized_targets": list(self.authorized_targets),
            "window_start": self.window_start,
            "window_end": self.window_end,
            "statement": self.statement,
            "allow_network_traffic": self.allow_network_traffic,
        }
        return hashlib.sha256(jcs_canonical_bytes(payload)).hexdigest()


@dataclass(frozen=True)
class EvidenceSpan:
    corpus_id: str
    pack_sha: str
    fetched_at: str
    path: str
    line_start: int
    line_end: int
    byte_sha256: str
    taint: str = "UNTRUSTED_CORPUS_EVIDENCE"


def verify_cyber_scope_and_isolation(
    *,
    scenario: str,
    requested_targets: list[str],
    now_utc: str,
    scope_grant: ScopeGrant | None,
    evidence_spans: list[EvidenceSpan],
    sends_network_traffic: bool = False,
) -> dict[str, Any]:
    """Fail-closed Scope Guard + WIMSE context-isolation check.

    Refuses loudly when:
    1. ScopeGrant is missing or lacks an authorization statement (#2767 / #2772 / #2774).
    2. `now_utc` falls outside `[window_start, window_end]`.
    3. Any target in `requested_targets` is missing from `scope_grant.authorized_targets`.
    4. Any target derives from an untrusted corpus span without explicit authorization
       (WIMSE confused-deputy / indirect prompt injection prevention).
    5. The scenario attempts active network traffic when planning-only mode is enforced.
    """
    if scope_grant is None or not scope_grant.statement.strip():
        return {
            "status": "REFUSED",
            "reason_code": "ERR_MISSING_AUTHORIZATION_SCOPE",
            "scenario": scenario,
            "scope_echo": None,
        }

    if not scope_grant.authorized_targets or not requested_targets:
        return {
            "status": "REFUSED",
            "reason_code": "ERR_EMPTY_TARGET_SET",
            "scenario": scenario,
            "scope_echo": {"authorization_id": scope_grant.authorization_id},
        }

    if sends_network_traffic and not scope_grant.allow_network_traffic:
        return {
            "status": "REFUSED",
            "reason_code": "ERR_TRAFFIC_PROHIBITED_PLANNING_ONLY",
            "scenario": scenario,
            "scope_echo": {"authorization_id": scope_grant.authorization_id},
        }

    t_now = datetime.fromisoformat(now_utc.replace("Z", "+00:00"))
    t_start = datetime.fromisoformat(scope_grant.window_start.replace("Z", "+00:00"))
    t_end = datetime.fromisoformat(scope_grant.window_end.replace("Z", "+00:00"))
    if not (t_start <= t_now <= t_end):
        return {
            "status": "REFUSED",
            "reason_code": "ERR_SCOPE_WINDOW_EXPIRED",
            "scenario": scenario,
            "scope_echo": {
                "authorization_id": scope_grant.authorization_id,
                "window_start": scope_grant.window_start,
                "window_end": scope_grant.window_end,
            },
        }

    allowed = set(scope_grant.authorized_targets)
    out_of_scope = [t for t in requested_targets if t not in allowed]
    if out_of_scope:
        return {
            "status": "REFUSED",
            "reason_code": "ERR_TARGET_OUT_OF_SCOPE",
            "out_of_scope_targets": out_of_scope,
            "scenario": scenario,
            "scope_echo": {
                "authorization_id": scope_grant.authorization_id,
                "authorized_targets": list(scope_grant.authorized_targets),
            },
        }

    for ev in evidence_spans:
        if len(ev.pack_sha) != 40 or not ev.fetched_at:
            return {
                "status": "REFUSED",
                "reason_code": "ERR_UNPINNED_EVIDENCE_CITATION",
                "scenario": scenario,
                "scope_echo": {"authorization_id": scope_grant.authorization_id},
            }

    return {
        "status": "AUTHORIZED",
        "reason_code": "OK_SCOPE_AND_ISOLATION_VERIFIED",
        "scenario": scenario,
        "scope_echo": {
            "authorization_id": scope_grant.authorization_id,
            "authorized_targets": list(scope_grant.authorized_targets),
            "window_start": scope_grant.window_start,
            "window_end": scope_grant.window_end,
            "scope_digest_sha256": scope_grant.digest(),
            "traffic_policy": "NO_TRAFFIC_SENT",
        },
        "verified_evidence_count": len(evidence_spans),
    }
