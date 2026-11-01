# Agentic Security IETF Corpus & Reference Adapters (`agentic-security-ietf-corpus`)

[![DOI](https://img.shields.io/badge/DOI-10.57967%2Fhf%2F11352-blue)](https://doi.org/10.57967/hf/11352)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-green.svg)](LICENSE)

Clause-level **IETF Internet-Draft specifications**, **100-scenario OWASP ASI01–ASI10 adversarial benchmark vectors** (`DOI: 10.57967/hf/11352`), and **reference verification adapters** for autonomous AI agent governance, MCP tool execution, and reference-coding corpora such as the **XERJ Corpus Hub** (`xerj-org/xerj`).

## 1. Live IETF Internet-Drafts Included (`ietf-drafts/`)

1. **`draft-durga-agenttrust-trace-verification-00`** — *Cryptographic Execution-Trace Verification, JCS Canonicalization, and Fail-Closed Delegation Attestation for Autonomous AI Agents* ([IETF Datatracker](https://datatracker.ietf.org/doc/draft-durga-agenttrust-trace-verification/))
   - Defines RFC 8785 (JCS) canonical JSON serialization, Merkle-chained execution receipts, and fail-closed verification of claim-to-evidence bindings.
2. **`draft-durga-wimse-ctx-isolation-00`** — *WIMSE Cryptographic Context Isolation and Taint-Tracking Envelopes for Multi-Tenant AI Agents* ([IETF Datatracker](https://datatracker.ietf.org/doc/draft-durga-wimse-ctx-isolation/))
   - Defines strict separation between untrusted retrieved data-plane spans (`evidence_spans[]`) and authorized control-plane tool parameters (`authorized_targets[]`) to prevent confused-deputy and cross-tool indirect prompt injection.
3. **`draft-durga-pquip-pqc-agentic-delegation-00`** — *Post-Quantum Hybrid Cryptographic Delegation Chains and Merkle-Aggregated Execution Receipts for Autonomous AI Agents* ([IETF Datatracker](https://datatracker.ietf.org/doc/draft-durga-pquip-pqc-agentic-delegation/))
   - Defines algorithm-agile (`Ed25519` + `ML-DSA-65` FIPS 204) composite delegation tokens and strict non-escalation scope lattices.
4. **`draft-durga-agent-tx-compensation-lease-00`** — *Pre-Release Transactional Compensation Leases and CAS Fencing Receipts for Autonomous Agents Over Systems of Record* ([IETF Datatracker](https://datatracker.ietf.org/doc/draft-durga-agent-tx-compensation-lease/))
   - Defines 4-mode pre-release recovery reservation leases, composite rollback windows (`T_req <= T_granted`), and Compare-And-Swap (`CAS`) epoch fencing across state-mutating tool invocations.

## 2. OWASP Agentic Security Top 10 (ASI01–ASI10) 100-Scenario Benchmark (`owasp-asi-benchmark/`)

- **`owasp_asi01_asi10_100_scenarios.jsonl`** — 100 deterministic adversarial and compliance test vectors (10 scenarios per category across `ASI01` through `ASI10`), permanently archived on Hugging Face under **DataCite DOI [`10.57967/hf/11352`](https://doi.org/10.57967/hf/11352)**.

## 3. XERJ Reference Adapters (`xerj-reference-adapters/`)

- **`scope_guard_ctx_isolation.py`** — Reference verifier for XERJ Cyber Pack (`#2767`, `#2771`, `#2772`, `#2774`) implementing fail-closed Authorization/Scope Guard validation (`authorized_targets`, `window_start`/`window_end`, mandatory `scope_echo`) and WIMSE data-plane vs. control-plane taint isolation (`draft-durga-wimse-ctx-isolation-00`).
- **`trace_evidence_verifier.py`** — Reference verifier for XERJ Version-Pinned Trace-to-Evidence Reports (`#1789`) and Calibrated Abstention Envelopes (`#1786`), implementing RFC 8785 JCS canonicalization, SHA-256 byte-span digest verification, and calibrated abstain/escalate gating (`draft-durga-agenttrust-trace-verification-00`).
- **`compensation_lease_verifier.py`** — Reference verifier for pre-release transactional compensation leases and CAS epoch fencing (`draft-durga-agent-tx-compensation-lease-00`) prior to state-mutating MCP/A2A tool calls.

## 4. Running the Verification Suite

```bash
python -m unittest discover -s tests -p "test_*.py" -v
```
