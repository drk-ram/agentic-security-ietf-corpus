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

---

## Archival DOIs, IETF Internet-Drafts & BibTeX Citations

This repository includes machine-readable citation metadata in [`CITATION.cff`](CITATION.cff), [`BIBLIOGRAPHY.bib`](BIBLIOGRAPHY.bib), and [`codemeta.json`](codemeta.json) (ORCID: [`0009-0003-7014-355X`](https://orcid.org/0009-0003-7014-355X), Web of Science ResearcherID: `RJT-9755-2026`).

### 1. IETF Internet-Draft Specifications (`ietf-drafts/`)
| Draft Identifier | Title | IETF Datatracker / Spec |
| :--- | :--- | :--- |
| **`draft-durga-agenttrust-trace-verification-00`** | *Cryptographic Execution-Trace Verification, JCS Canonicalization, and Fail-Closed Delegation Attestation for Autonomous AI Agents* | [Datatracker](https://datatracker.ietf.org/doc/draft-durga-agenttrust-trace-verification/) |
| **`draft-durga-wimse-ctx-isolation-00`** | *Cryptographic Context Isolation and Taint-Tracked Tool Invocation for Agentic Workloads* | [Datatracker](https://datatracker.ietf.org/doc/draft-durga-wimse-ctx-isolation/) |
| **`draft-durga-pquip-pqc-agentic-delegation-00`** | *Post-Quantum Hybrid Cryptographic Delegation Chains (Ed25519 + ML-DSA-65) and Merkle-Aggregated Execution Receipts* | [Datatracker](https://datatracker.ietf.org/doc/draft-durga-pquip-pqc-agentic-delegation/) |
| **`draft-durga-agent-tx-compensation-lease-00`** | *Pre-Release Transactional Compensation Leases and CAS Fencing Receipts for Autonomous Agents Over Systems of Record* | [Datatracker](https://datatracker.ietf.org/doc/draft-durga-agent-tx-compensation-lease/) |
| **`draft-durga-scitt-model-activation-binding-00`** | *SCITT Transparency Statement Profile for Cryptographic Model Weight Custody and Runtime Activation Binding* | [`ietf-drafts/`](ietf-drafts/) |
| **`draft-durga-mcp-a2a-semantic-metering-00`** | *Cross-Protocol Semantic Equivalence and Commit-Bound Settlement Receipts for MCP and A2A Exchanges* | [`ietf-drafts/`](ietf-drafts/) |
| **`draft-durga-agent-clear-revocation-00`** | *Sub-Second Broadcast Ephemeral Key Revocation (CLEAR) for Multi-Agent Delegations* | [`ietf-drafts/`](ietf-drafts/) |

### 2. CERN Zenodo / OpenAIRE Technical Reports & Benchmark Dataset DOIs
| Report / Dataset ID | Title | Permanent DOI |
| :--- | :--- | :--- |
| **Dataset (`N = 100`)** | *OWASP ASI01-ASI10 Enterprise Agentic AI Security Regression Benchmark (100 Scenarios)* | [`10.57967/hf/11352`](https://doi.org/10.57967/hf/11352) |
| **`TR-2026-01`** | *Deterministic Control-Plane Governance and Lease-Bounded Recovery for Enterprise Agentic AI Systems* | [`10.5281/zenodo.23735274`](https://doi.org/10.5281/zenodo.23735274) |
| **`TR-2026-02`** | *Adversarial Regression Benchmarking for Agentic AI Security Controls Across OWASP ASI01--ASI10* | [`10.5281/zenodo.23735497`](https://doi.org/10.5281/zenodo.23735497) |
| **`TR-2026-03`** | *Cryptographic Weight-Custody Manifests, JCS Canonicalization, and Two-Plane Edge Fleet Verification for Autonomous AI Systems* | [`10.5281/zenodo.23775009`](https://doi.org/10.5281/zenodo.23775009) |
| **`TR-2026-04`** | *Merkle-DAG Incremental Verification, Cross-Protocol Semantic Equivalence, and Commit-Bound Metering for Multi-Tenant Agent Exchanges* | [`10.5281/zenodo.23775532`](https://doi.org/10.5281/zenodo.23775532) |
| **`TR-2026-05`** | *Non-Human Identity (NHI) Attestation, On-Behalf-Of (OBO) Token Exchange, and CSA AARM Risk Benchmarking for Autonomous Enterprise Agents* | [`10.5281/zenodo.23776217`](https://doi.org/10.5281/zenodo.23776217) |
| **`TR-2026-06`** | *Hash-Chained Decision Provenance, Purpose-Bound Data Passports, and Reversible Cyber Response in Regulated Cloud Estates* | [`10.5281/zenodo.23776574`](https://doi.org/10.5281/zenodo.23776574) |
| **Compendium** | *Enterprise Agentic AI Governance, Security, and Autonomous Cloud-Native Architecture: Collected Research Compendium (2025--2026)* | [`10.5281/zenodo.23723284`](https://doi.org/10.5281/zenodo.23723284) |

### 3. Foundational Peer-Reviewed Journal Articles (IJSRMT, Vol. 4, Issues 5-12, 2025, ISSN 2583-4029)
1. **Durga, R. K.** (2025). *Implementing Zero Trust Architecture: Principles, Models, and Challenges*. IJSRMT, 4(12), 42-50. DOI: [`10.38124/ijsrmt.v4i12.1050`](https://doi.org/10.38124/ijsrmt.v4i12.1050)
2. **Durga, R. K.** (2025). *Self-Optimizing Factories: The Role of Agentic Automation in Industry 4.0*. IJSRMT, 4(11), 49-59. DOI: [`10.38124/ijsrmt.v4i11.1049`](https://doi.org/10.38124/ijsrmt.v4i11.1049)
3. **Durga, R. K.** (2025). *Cybersecurity in the Digital Age: Foundations, Threats, and Future Directions*. IJSRMT, 4(10), 77-87. DOI: [`10.38124/ijsrmt.v4i10.1048`](https://doi.org/10.38124/ijsrmt.v4i10.1048)
4. **Durga, R. K.** (2025). *Cloud as a Platform for AI/ML: Democratization, Services and Architectures*. IJSRMT, 4(9), 139-149. DOI: [`10.38124/ijsrmt.v4i9.1047`](https://doi.org/10.38124/ijsrmt.v4i9.1047)
5. **Durga, R. K.** (2025). *An Introduction to Cloud Native Applications: Leveraging the Cloud for Scalability and Resilience*. IJSRMT, 4(8), 103-112. DOI: [`10.38124/ijsrmt.v4i8.1046`](https://doi.org/10.38124/ijsrmt.v4i8.1046)
6. **Durga, R. K.** (2025). *From IaaS to FaaS: An Evolutionary Analysis of Cloud Service Models*. IJSRMT, 4(7), 122-130. DOI: [`10.38124/ijsrmt.v4i7.1045`](https://doi.org/10.38124/ijsrmt.v4i7.1045)
7. **Durga, R. K.** (2025). *Beyond Traditional AI: A Comprehensive Study of Agentic Frameworks and Their Applications*. IJSRMT, 4(6), 62-70. DOI: [`10.38124/ijsrmt.v4i6.1044`](https://doi.org/10.38124/ijsrmt.v4i6.1044)
8. **Durga, R. K.** (2025). *A Comprehensive Study of Agentic AI Systems*. IJSRMT, 4(5), 124-133. DOI: [`10.38124/ijsrmt.v4i5.1043`](https://doi.org/10.38124/ijsrmt.v4i5.1043)
