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
- **23 rules**: `SEC-001-FAIL-OPEN` … `SEC-020-XSS` (CWE-tagged) and
  `ARCH-001-CYCLIC-DEPENDENCY`, `ARCH-002-LEAKY-ABSTRACTION`, `ARCH-003-NON-DETERMINISTIC-CALL`.
- Inter-procedural multi-hop taint & dataflow tracking (`DataflowTracker`): recurses through 3+ method
  calls, resolves interface-to-implementation boundaries, prevents recursion loops via parameter-aware
  signatures, and tracks untrusted sources reaching command execution, SQL, file I/O, SSRF, LDAP, and XPath sinks.
- Multi-language AST inspection and security analysis (`com.sentinelpr.core.analysis.multilang`):
  support for Kotlin (`.kt`, `.kts`), Python (`.py`, `.pyw`), and JavaScript/TypeScript (`.js`, `.ts`, `.tsx`, `.mjs`)
  via `SourceLanguage`, `MultiLanguageSourceParser`, and `MultiLanguageAnalysisEngine`.
- Secret scanning (`SecretScanningEngine`): AWS keys, PEM private keys, credential
  assignments, Shannon-entropy scoring (≥ 3.2), placeholder whitelists, secret redaction.
- Spring context analysis (`FrameworkContextAnalyzer`): CSRF-disabled and wildcard-CORS detection.
- Causal reasoning (`CausalAnalysisEngine`, `CausalChain`): trigger → propagation → exploit
  vector → business impact with `BlastRadius` classification.
- Calibrated confidence (`ConfidenceCalibrator`): deterministic 4-factor model
  (taint 0.35 / AST precision 0.30 / sanitizer absence 0.20 / reachability 0.15),
  threshold 0.70, `ExploitabilityIndex` ranks 1–5.
- Adaptive Bayesian Feedback Learning (`com.sentinelpr.core.analysis.calibration.feedback`): Beta-Binomial conjugate updating (alpha=4.0, beta=1.0) driven by reviewer feedback (`CONFIRMED_TRUE_POSITIVE`, `REJECTED_FALSE_POSITIVE`, `ACCEPTED_RISK`), combining 30% global rule precision with 70% localized pattern matching (`ruleId::class#method`), dynamic confidence boosts and penalties clamped to [-0.35, +0.10], automatic suppression of noisy false-positive heuristics as `LOW_CONFIDENCE_HEURISTIC` (< 0.70), disk persistence (`feedback-store.json`), and REST APIs (`POST /api/v1/sentinel/feedback`, `GET /api/v1/sentinel/feedback/stats`).
- Enterprise Web Dashboard (`src/main/resources/static`): standalone, air-gapped single-page security web application with 5 real-time panes (Executive KPI Overview, Interactive Code Reviewer & Diff Inspector with one-click feedback buttons, Multi-Repo Fleet Scanner, 23-rule Security Catalog, and SOC2/ISO27001 Audit Trail Viewer).
- Continuous Watch Mode & Incremental Scan Engine (`com.sentinelpr.core.watch`): recursive filesystem event watcher (`WorkspaceWatchDaemon`) with event debouncing (default 300ms), thread-safe repository state cache (`IncrementalWorkspaceState`), and sub-second incremental re-auditing (`auditIncremental`). Re-parses and re-evaluates only dirty (added, modified, or deleted) files while reusing cached ASTs and findings for untouched files. Supported via CLI (`-w, --watch`, `--debounce <ms>`) and REST APIs (`POST /api/v1/sentinel/watch/start`, `POST /api/v1/sentinel/watch/stop`, `GET /api/v1/sentinel/watch/status`, `POST /api/v1/sentinel/watch/scan`).

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
- - REST API Authentication & RBAC (`com.sentinelpr.api.auth`): Dual authentication via API Key (`X-API-Key`, `Authorization: ApiKey`) and RFC 7519 HS256 JSON Web Tokens (`Authorization: Bearer`), declarative Role-Based Access Control (`ADMIN`, `REVIEWER`, `VIEWER`) via `@RequireRole` and `@RequirePermission` annotations, constant-time verification against timing attacks, token issuance (`POST /api/v1/auth/token`), and principal introspection (`GET /api/v1/auth/me`).
- GitHub App webhook receiver (`/api/v1/github/webhook`, `/api/v1/github/status`): HMAC-SHA256 signature verification (`X-Hub-Signature-256`), PR lifecycle orchestration (`opened`, `synchronize`, `reopened`), automatic diff retrieval, diff-scoped audit execution, automated review submission (`APPROVE`, `REQUEST_CHANGES`, `COMMENT`), check run status synchronization, and delivery deduplication.
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

- Audit-trail `ExecutionTimings` records real measured phase durations (`parseMs`, `analysisMs`, `patchMs`, `totalMs`) from pipeline execution.
- Automated AST patch synthesis and regression verification are strictly bounded to Java 21 LTS sources. Non-Java languages (Kotlin, Python, JS/TS) explicitly assign `MANUAL_REMEDIATION_REQUIRED` with empty diffs and `isVerified = false`.
- Python security inspection uses function-scoped lexical heuristics (`getEnclosingScopeCodeLines`) rather than a full polyglot semantic AST engine; sanitizers are detected within enclosing function blocks without path sensitivity.
- Taint tracking operates within first-order inter-procedural call graphs; database repository lookups (`isRepositoryOrEntityLookup`) halt taint propagation to eliminate lookup key overtaint.
- Integration tests for `PolicyEngine` and `PrReviewCommentBuilder` handling `MANUAL_REMEDIATION_REQUIRED` patches are tracked as follow-up quality items.
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
