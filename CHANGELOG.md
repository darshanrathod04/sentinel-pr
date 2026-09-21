# Changelog

All notable changes to SentinelPR are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2026-09-22

Initial production release of the SentinelPR Enterprise Code & Security Review Copilot,
built on Shree AI OS `io.github.darshanrathod04:shree-ai-os:1.0.6-developer-preview`.

### Added — Audit Engine

- Java 21 AST audit pipeline (`SentinelAuditOrchestrator`): inspection → dedup → rule
  evaluation → suppression → diff filtering → baseline reconciliation → causal analysis →
  calibration → patch synthesis → verification → policy → exports.
- **13 rules**: `SEC-001-FAIL-OPEN` … `SEC-010-SPRING-PERMISSIVE-CORS` (CWE-tagged) and
  `ARCH-001-CYCLIC-DEPENDENCY`, `ARCH-002-LEAKY-ABSTRACTION`, `ARCH-003-NON-DETERMINISTIC-CALL`.
- Intra-procedural taint & dataflow tracking (`DataflowTracker`) with sanitizer awareness and
  cross-file context (`TaintSource`, `TaintSink`, `TaintFlow`).
- Secret scanning (`SecretScanningEngine`): AWS keys, PEM private keys, credential
  assignments, Shannon-entropy scoring (≥ 3.2), placeholder whitelists, secret redaction.
- Spring context analysis (`FrameworkContextAnalyzer`): CSRF-disabled and wildcard-CORS detection.
- Causal reasoning (`CausalAnalysisEngine`, `CausalChain`): trigger → propagation → exploit
  vector → business impact with `BlastRadius` classification.
- Calibrated confidence (`ConfidenceCalibrator`): deterministic 4-factor model
  (taint 0.35 / AST precision 0.30 / sanitizer absence 0.20 / reachability 0.15),
  threshold 0.70, `ExploitabilityIndex` ranks 1–5.

### Added — Patch Pipeline

- Verified patch synthesis (`DeveloperFacade`, `PatchComposer`): rule-specific AST
  transformations, one composed unified diff per file, JavaParser validity gate after every edit.
- Post-patch regression verification (`PatchVerifier`): re-parse (Shree AI OS `JavaAstParser`
  + JavaParser) and re-run rule evaluation; `regressionVerified` requires 0 remaining CRITICALs.
- Multi-file coordinated fix planning (`MultiFileFixPlanner`, `CoordinatedPatchPlan`).

### Added — Governance

- Technical-debt baselines (`BaselineManager`): SHA-256 fingerprinted snapshots, structural
  ±5-line/method re-matching, `BASELINE_ACCEPTED` suppression, policy supremacy for blocked rules.
- Enterprise policy engine (`PolicyEngine`): severity thresholds, `blockedRules`,
  `failOnUnverifiedPatch`, statuses PASSED / PASSED_WITH_BASELINE / BREACHED / FAILED,
  exit codes 0 / 1 / 2 / 4.
- False-positive suppression (`SuppressionManager`): `@SuppressWarnings("sentinel:<RULE>")`,
  inline `// sentinel-ignore` comments, `.sentinelignore` files.
- Incremental PR diff scanning (`IncrementalDiffScanner`): unified-diff hunk parsing with
  `DIFF_BASELINE` categorization for untouched code.
- Cryptographic audit trail (`AuditTrailLogger`): append-only NDJSON ledger, SHA-256 report
  signatures, tamper verification, SOC2-CC7.1 / ISO27001-A.12.6.1 evidence fields.

### Added — Interfaces

- CLI (`SentinelCliRunner`): target-path audit, `--diff`, `--baseline`, `--create-baseline`,
  `--policy`, `--sarif`, `--audit-log`, `--history`, `--run <id>`, `-f/--format json|sarif|github|text`.
- `--chat` AI assistant command routed through the Shree AI OS LLM router (Gemini BYOK),
  with missing-prompt validation (exit code 3).
- REST API (`/api/v1/sentinel/*`): `/health`, `/review`, `/review/sarif`, `/review/github`,
  `/policy/evaluate`, `/governance/status`.
- Exports: OASIS SARIF v2.1.0 (`SarifReportGenerator`) and GitHub PR review payloads with
  inline comments and ```suggestion``` blocks (`PrReviewCommentBuilder`).

### Added — Platform Integration

- `SentinelClient` singleton bootstrap over the Shree AI OS 10-SDK surface with Google Gemini
  BYOK (`GEMINI_API_KEY`) and deterministic in-memory fallback.
- Session memory & history (`MemoryFacade`, `ReviewSessionMemory`): SHA-256 source
  fingerprinting, Memory Kernel persistence, `.sentinelhistory.json` workspace ledger (schema
  1.0.0, metadata-only guardrail), `--history` / `--run` inspection.

### Added — Tests & Fixtures

- 36 integration tests across `SentinelPrApplicationTest` and P0–P4 verification suites
  (taint, suppression, patch composition, security rules, CLI workflow, governance,
  causal intelligence, architecture rules).
- Fixtures: `VulnerableService`, `TaintedVulnerableService`, `EnterpriseSecurityVulnerableService`,
  coupled and interprocedural sample sets; sample baseline, diff, and policy resources.

### Known Limitations (documented, by design)

- Audit-trail `ExecutionTimings` use fixed defaults rather than measured durations.
- Screenshot assets are not yet captured (placeholders listed in `README.md`).
- When `GEMINI_API_KEY` is absent, chat and reasoning use the deterministic in-memory provider.

### Release Engineering (this phase, no feature changes)

- Committed the official Apache-2.0 `LICENSE` at the repository root (previously missing).
- Added GitHub Actions CI (`.github/workflows/maven.yml`): ubuntu-latest, Temurin 21,
  Maven cache, `mvn -B test`, triggered on push and pull_request.
- Added `examples/` (copies of existing fixtures/governance assets + explainer README).
- Added `scripts/build-release.ps1` (clean → test → package → `SHA256SUMS.txt` → `release/`).
- Added `RELEASE-NOTES.md` maintainer release checklist.
- Populated `.gitignore` (was empty): `target/`, `release/`, `SHA256SUMS.txt`, `.env`, IDE noise.

[1.0.0]: https://github.com/darshanrathod04/sentinel-pr/releases/tag/v1.0.0
