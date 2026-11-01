import hashlib
import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "xerj-reference-adapters"))

from scope_guard_ctx_isolation import ScopeGrant, EvidenceSpan, verify_cyber_scope_and_isolation
from trace_evidence_verifier import verify_pinned_claim_and_calibrate
from compensation_lease_verifier import verify_compensation_lease


class TestAgenticSecurityCorpus(unittest.TestCase):
    def test_owasp_100_scenarios_present(self):
        path = ROOT / "owasp-asi-benchmark" / "owasp_asi01_asi10_100_scenarios.jsonl"
        lines = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        self.assertEqual(len(lines), 100)

    def test_scope_guard_authorized_and_out_of_scope(self):
        grant = ScopeGrant(
            authorization_id="AUTH-2026-11-01",
            authorized_targets=("crate:xerj-mcp", "endpoint:/v1/search"),
            window_start="2026-11-01T00:00:00Z",
            window_end="2026-11-02T00:00:00Z",
            statement="Authorized static review and surface mapping; no traffic sent.",
        )
        ev = EvidenceSpan(
            corpus_id="rust-vulns",
            pack_sha="a" * 40,
            fetched_at="2026-11-01",
            path="advisories/RUSTSEC-2026-0001.json",
            line_start=10,
            line_end=24,
            byte_sha256="b" * 64,
        )
        ok = verify_cyber_scope_and_isolation(
            scenario="cyber.blackbox",
            requested_targets=["crate:xerj-mcp"],
            now_utc="2026-11-01T12:00:00Z",
            scope_grant=grant,
            evidence_spans=[ev],
        )
        self.assertEqual(ok["status"], "AUTHORIZED")
        self.assertEqual(ok["scope_echo"]["traffic_policy"], "NO_TRAFFIC_SENT")

        denied = verify_cyber_scope_and_isolation(
            scenario="cyber.blackbox",
            requested_targets=["endpoint:/admin/shutdown"],
            now_utc="2026-11-01T12:00:00Z",
            scope_grant=grant,
            evidence_spans=[ev],
        )
        self.assertEqual(denied["status"], "REFUSED")
        self.assertEqual(denied["reason_code"], "ERR_TARGET_OUT_OF_SCOPE")

    def test_trace_evidence_verifier_and_abstention(self):
        raw = b"fn verify_manifest(sha: &str) -> bool { sha.len() == 40 }"
        span_hash = hashlib.sha256(raw[0:29]).hexdigest()
        ans = verify_pinned_claim_and_calibrate(
            claim_id="CLM-01",
            claim_text="verify_manifest checks 40-char SHA length",
            corpus_slug="xerj-common",
            commit_or_pack_sha="dc602afaa66127c765c9a6567587b69fff09c399",
            file_path="src/hub.rs",
            byte_start=0,
            byte_end=29,
            source_bytes=raw,
            expected_span_sha256=span_hash,
            calibrated_confidence=0.91,
        )
        self.assertEqual(ans["decision"], "ANSWER")

        abstain = verify_pinned_claim_and_calibrate(
            claim_id="CLM-02",
            claim_text="Low confidence claim",
            corpus_slug="xerj-common",
            commit_or_pack_sha="dc602afaa66127c765c9a6567587b69fff09c399",
            file_path="src/hub.rs",
            byte_start=0,
            byte_end=29,
            source_bytes=raw,
            expected_span_sha256=span_hash,
            calibrated_confidence=0.62,
        )
        self.assertEqual(abstain["decision"], "ABSTAIN")
        self.assertTrue(abstain["escalate"])

    def test_compensation_lease_verifier(self):
        res = verify_compensation_lease(
            lease_id="LEASE-96848-01",
            mode="INVERSE_OP",
            t_req_ms=120,
            t_granted_ms=250,
            expected_cas_epoch=7,
            current_cas_epoch=7,
            now_epoch_ms=1793545000000,
            lease_expires_epoch_ms=1793545060000,
        )
        self.assertEqual(res["status"], "COMMIT_ALLOWED")
        self.assertEqual(res["fenced_receipt"]["committed_cas_epoch"], 8)


if __name__ == "__main__":
    unittest.main()
