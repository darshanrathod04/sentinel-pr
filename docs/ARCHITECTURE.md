# SentinelPR — Internal Architecture

> Derived entirely from the v1.0.0 source tree (`src/main/java`). Every component named here exists in the codebase.

## 1. Module Overview

| Package | Responsibility |
|---|---|
| `com.sentinelpr` | Spring Boot bootstrap (`SentinelPrApplication`) and bean wiring |
| `com.sentinelpr.cli` | Command-line front-end (`SentinelCliRunner`) |
| `com.sentinelpr.api` | REST front-end (`SentinelReviewController`, DTOs) |
| `com.sentinelpr.client` | Shree AI OS integration layer (`SentinelClient`, facades, `MemoryFacade`) |
| `com.sentinelpr.core.analysis` | Taint tracking, secret scanning, framework analysis, diff scanning, suppression, causal analysis, calibration |
| `com.sentinelpr.core.analysis.architecture` | `ArchitectureReviewEngine` (ARCH rules) |
| `com.sentinelpr.core.service` | Orchestrator, inspection, rule evaluation, patch composition/verification, session memory |
| `com.sentinelpr.core.model` | Domain models (`ReviewReport`, `SecurityFinding`, `UnifiedDiffPatch`, …) |
| `com.sentinelpr.core.governance` | Baseline snapshots, policy engine, cryptographic audit trail |
| `com.sentinelpr.core.export` | SARIF 2.1.0 generator, GitHub PR review payload builder |

## 2. Layer Diagram

```mermaid
flowchart TB
    subgraph Frontends
        CLI["SentinelCliRunner (CLI)"]
        REST["SentinelReviewController (REST /api/v1/sentinel)"]
    end

    subgraph Orchestration
        ORCH["SentinelAuditOrchestrator"]
    end

    subgraph Services
        INSPECT["CodeInspectionService"]
        RULES["RuleEvaluationService"]
        PATCH["AutomatedPatchService"]
        MEM["ReviewSessionMemory"]
    end

    subgraph AnalysisEngines
        TAINT["DataflowTracker"]
        SECRET["SecretScanningEngine"]
        FW["FrameworkContextAnalyzer"]
        ARCH["ArchitectureReviewEngine"]
        CAUSAL["CausalAnalysisEngine"]
        CAL["ConfidenceCalibrator"]
        SUPP["SuppressionManager"]
        DIFF["IncrementalDiffScanner"]
        MULTILANG["MultiLanguageAnalysisEngine"]
    end

    subgraph PatchPipeline
        COMPOSE["PatchComposer"]
        VERIFY["PatchVerifier"]
        MULTI["MultiFileFixPlanner"]
    end

    subgraph Governance
        BASE["BaselineManager"]
        POL["PolicyEngine"]
        AUDIT["AuditTrailLogger"]
    end

    subgraph Exports
        SARIF["SarifReportGenerator"]
        GITHUB["PrReviewCommentBuilder"]
    end

    subgraph ShreeAI["Shree AI OS (external dependency)"]
        CLIENT["SentinelClient singleton"]
        SDKS["10-SDK surface: Project · Reasoning · Developer · Memory · Settings · Identity · Knowledge · Planning · Execution · Reflection"]
        LLM["LLM Router (Gemini BYOK / in-memory fallback)"]
    end

    CLI --> ORCH
    REST --> ORCH
    ORCH --> INSPECT & RULES & PATCH & MEM & SUPP & DIFF & CAUSAL & CAL
    RULES --> ARCH
    PATCH --> COMPOSE --> VERIFY
    ORCH --> BASE & POL & AUDIT
    ORCH --> SARIF & GITHUB
    INSPECT --> CLIENT
    RULES --> CLIENT
    COMPOSE --> CLIENT
    MULTI --> CLIENT
    MEM --> CLIENT
    CLIENT --> SDKS
    SDKS --> LLM
```

## 3. CLI Request Flow

```mermaid
flowchart TD
    A["main(String[] args)"] --> B{"args empty?"}
    B -- yes --> U["printUsage() → exit 3"]
    B -- no --> H{"--history / --run <id>?"}
    H -- yes --> HIST["MemoryFacade.formatHistoryTable / formatSessionDetail → exit 0"]
    H -- no --> C{"--chat present?"}
    C -- yes --> CHAT["executeChat(): join remaining args → prompt"]
    CHAT --> C2{"prompt blank?"}
    C2 -- yes --> C3["'Error: Missing chat prompt.' → exit 3"]
    C2 -- no --> C4["SentinelClient.chat(prompt) → print banner + response → exit 0"]
    C -- no --> D["Parse options: --diff --baseline --create-baseline --policy --sarif --audit-log -f/--format, target path"]
    D --> E{"target null?"}
    E -- yes --> U
    E -- no --> F["execute(target, …) → CliExecutionResult"]
    F --> G["System.exit(result.getExitCode())"]
```

Exit codes (`execute(String[])` javadoc): `0` audit passed / history · `1` policy breached · `2` internal engine error · `3` invalid CLI arguments, missing target, or missing chat prompt · `4` patch generation/verification failure.

## 4. Audit Pipeline

Implemented in `SentinelAuditOrchestrator.auditPath(...)` and `auditSources(...)`:

```mermaid
flowchart TD
    S0["Target path (file or directory)"] --> S1["CodeInspectionService.inspectPath()\nMulti-language AST (Java, Kotlin, Python, JS/TS) → InspectedSource graph"]
    S1 --> S2{"ReviewSessionMemory.hasPreviousAudit(SHA-256 fingerprint)?"}
    S2 -- "unchanged source" --> S2a["Return cached report (cachedAudit=true)"]
    S2 -- "new/changed" --> S3["RuleEvaluationService.evaluate()\nReasoningFacade SEC rules + ArchitectureReviewEngine ARCH rules\n+ SecretScanningEngine + FrameworkContextAnalyzer + DataflowTracker"]
    S3 --> S4["CausalAnalysisEngine.enrichFinding()\nTrigger → Propagation → Exploit → Business Impact"]
    S4 --> S5["ConfidenceCalibrator.calibrate()\n4-factor score; below 0.70 → suppressed LOW_CONFIDENCE_HEURISTIC"]
    S5 --> S6["SuppressionManager.evaluateSuppression()\nannotations → inline comments → .sentinelignore"]
    S6 --> S7{"--diff provided?"}
    S7 -- yes --> S8["IncrementalDiffScanner.filterFindings()\noutside PR hunks → suppressed DIFF_BASELINE"]
    S7 -- no --> S9
    S8 --> S9{"--baseline provided?"}
    S9 -- yes --> S10["BaselineManager.filterWithBaseline()\nmatch → suppressed BASELINE_ACCEPTED\nblocked-rule policy supremacy enforced"]
    S9 -- no --> S11
    S10 --> S11["AutomatedPatchService.generatePatches()\nPatchComposer: apply all fixes → ONE unified diff per file"]
    S11 --> S12["PatchVerifier.verify()\nJavaAstParser + JavaParser re-parse, re-run rules,\nrequire 0 remaining CRITICAL → regressionVerified"]
    S12 --> S13["ReviewReport assembled\nPolicyEngine.evaluate → PolicyEvaluationResult\nMemoryFacade.recordSession (metadata only)\nSARIF / GitHub / JSON / text export"]
```

Session deduplication: `ReviewSessionMemory.computeFingerprint` hashes raw source text with SHA-256; recall key is `AUDIT:<fingerprint>`; both a fast in-process `ConcurrentHashMap` cache and the Memory Kernel are consulted.

## 5. Patch Synthesis & Verification

```mermaid
flowchart LR
    F["Active findings (sorted by rule priority)"] --> P1["applyTransformation() per finding\nPatchComposer / DeveloperFacade strategies"]
    P1 --> P2{"isValidJava(candidate)\n(JavaParser round-trip) after EACH transformation"}
    P2 -- invalid --> P2b["Revert to previous source"]
    P2 -- valid --> P1
    P1 --> P3["Generate ONE unified diff per file\nDeveloperFacade.generateUnifiedDiff()"]
    P3 --> P4["PatchVerifier.verify(patchedSource)"]
    P4 --> P5{"AST syntax valid?"}
    P5 -- no --> P6["verified = false, status FAILED/PARTIAL"]
    P5 -- yes --> P7["Re-run RuleEvaluationService on patched code\n(active findings, suppressions honored)"]
    P7 --> P8{"0 CRITICAL remaining?"}
    P8 -- yes --> P9["regressionVerified = true, status SUCCESS"]
    P8 -- no --> P10["regressionVerified = false\nmessage lists unresolved criticals"]
```

Patch strategies (one per rule, in `PatchComposer` / `DeveloperFacade`):

| Rule | Transformation |
|---|---|
| SEC-001-FAIL-OPEN | `return true;` → `return false; // SentinelPR: fail-closed security fix` (or equivalent hardening) |
| SEC-002-UNCLOSED-STREAM | Wrap stream in try-with-resources |
| SEC-003-VOLATILE-COMPOUND | `volatile int` + `++` → `AtomicInteger` with `incrementAndGet()` |
| SEC-004-UNISOLATED-SUBPROCESS | `Runtime.getRuntime().exec(` → `new ProcessBuilder(` |
| SEC-005-SQL-INJECTION | Concatenated SELECT predicate → `?` placeholder (developer completes `PreparedStatement` parameterization) |
| SEC-006-PATH-TRAVERSAL | Inject `Path.of(base.toString(), arg).normalize()` + base-path containment check throwing `SecurityException` (or `new File(base, arg).getCanonicalFile()` variant) |
| SEC-007-INSECURE-DESERIALIZATION | Inject `ObjectInputFilter.Config.createFilter("java.lang.*;java.util.*;!*")` on the `ObjectInputStream` |
| SEC-008-HARDCODED-SECRET | Literal → `System.getenv("AWS_ACCESS_KEY_ID")` / `System.getenv("APP_SECRET")` |
| SEC-009-SPRING-SECURITY-CSRF-DISABLED | Replace flagged snippet with `// CSRF protection preserved` marker (safe rewrite is a developer action) |
| SEC-010-SPRING-PERMISSIVE-CORS | `@CrossOrigin(origins = "*")` / `addAllowedOrigin("*")` → `https://trusted.domain.com` |
| SEC-011-XXE | Configure parser securely: `setFeature(http://apache.org/xml/features/disallow-doctype-decl, true)` |
| SEC-012-SSRF | Host allowlist validation (`isAllowedHost`) before outbound HTTP / socket invocation |
| SEC-013-JWT-NONE-ALG | Signature verification via `parseClaimsJws(key)` or `JWT.require(algorithm).verify()` |
| SEC-014-LOG-INJECTION | CRLF sanitization (`replace('\n', '_').replace('\r', '_')`) or parameterized logger |
| SEC-015-LDAP-INJECTION | Parameterized search filter (`SearchControls`) or `LdapEncoder.filterEncode()` |
| SEC-016-XPATH-INJECTION | Parameterized query via `XPathVariableResolver` |
| SEC-017-OPEN-REDIRECT | Target domain allowlist or relative path check (`isValidRedirect`) |
| SEC-018-WEAK-CRYPTO | Upgrade weak hashes/ciphers (MD5/DES) to SHA-256 and `AES/GCM/NoPadding` |
| SEC-019-INSECURE-RANDOM | Replace `java.util.Random` with `java.security.SecureRandom` in security contexts |
| SEC-020-XSS | Contextual HTML encoding (`HtmlUtils.htmlEscape()`) before writing to HTTP response |

Every candidate patch is parsed again after each edit; invalid candidates are rolled back so the composed diff always re-parses as valid Java 21.

## 6. Governance Engine

```mermaid
flowchart TD
    R["ReviewReport"] --> PB{"Policy blockedRules\nmatch any finding (active OR suppressed)?"}
    PB -- yes --> V["BREACHED (BLOCKED_BY_POLICY)\nBaseline debt cannot hide blocked rules"]
    PB -- no --> T{"Severity counts within\nmaxAllowed{Critical,High,Medium,Low}?"}
    T -- no --> V
    T -- yes --> UV{"failOnUnverifiedPatch\nand unverified patch present?"}
    UV -- yes --> V4["BREACHED (exit 4)"]
    UV -- no --> BASE
    BASE{"suppressedCount > 0?"}
    BASE -- yes --> PW["PASSED_WITH_BASELINE (exit 0)"]
    BASE -- no --> P["PASSED (exit 0)"]
    V --> E1["exit 1"]
    V4 --> E4["exit 4"]
```

Baseline matching (`BaselineEntry.matches`) succeeds on either an exact SHA-256 fingerprint of `filePath|ruleId|methodName|snippet` or a structural match (same file + same rule + same method **or** start line within ±5). `AuditTrailLogger` produces NDJSON entries signed with a SHA-256 over the canonical payload `runId|timestamp|targetPath|inputFingerprint|policyStatus|active|suppressed|blocked|patches|ruleSetVersion|policyVersion`; `verifyAuditEntry` recomputes and compares the signature. Operator identity resolves from `GITHUB_ACTOR` → `USER` → `USERNAME` → `user.name`.

## 7. Memory Subsystem

```mermaid
flowchart LR
    subgraph Record["recordSession()"]
        M1["AuditSessionMetadata\n(runId, targetPath, status, policyStatus,\nseverity counts, finding summaries, durationMs)"]
        M1 --> M2["MemorySDK.store('AUDIT:<runId>')\nMemorySDK.store('SESSION:<runId>')"]
        M2 --> M3["updateSessionIndexInMemorySdk()\nAUDIT_INDEX / SESSION_INDEX"]
        M3 --> M4[".sentinelhistory.json ledger\n(schema 1.0.0, workspaceId)"]
    end
    subgraph Read["--history / --run"]
        R1["formatHistoryTable() / formatSessionDetail(runId)"]
        R1 --> R2["MemorySDK recall (source of truth)"]
        R2 --> R3["Fast session cache"]
        R3 --> R4["Disk ledger hydration (never overwrites MemorySDK)"]
    end
```

**Guardrail (enforced in code, documented on `MemoryFacade`):** only audit *metadata* is persisted — never raw source code, unified diffs, or patch bodies.

## 8. LLM Routing & Gemini BYOK

```mermaid
sequenceDiagram
    participant App as SentinelClient.bootstrap()
    participant S as ShreeAI / SettingsSDK
    participant R as Shree AI OS LLM Router
    participant G as Google Gemini
    participant IM as In-memory provider

    App->>S: ShreeAI.builder().apiKey(SHREE_API_KEY or "local")
    alt GEMINI_API_KEY set
        App->>S: settings().configureApiKey(ProviderType.GEMINI, key)
        S-->>App: "BYOK Gemini provider configured successfully."
    else missing/failed
        App-->>App: deterministic in-memory provider mode
    end
    App->>R: shreeAi.chat(prompt)  [--chat / reasoning]
    R->>G: try provider chain (e.g. gemini/openai)
    G--xR: failure / unavailable
    R->>IM: fallback deterministic provider
    IM-->>R: SDKResponse (answer(), confidence(), metadata())
    R-->>App: SDKResponse
```

- SentinelPR calls only `SentinelClient.chat(...)` / facades; no direct HTTP to Gemini anywhere in this repository.
- `SDKResponse` exposes `answer()` (there is no `content()` method on the 1.0.6 SDK).
- Provider-chain order and degraded-mode behavior are owned by the Shree AI OS platform, not SentinelPR.

## 9. REST API Surface

| Endpoint | Backing components |
|---|---|
| `GET /api/v1/sentinel/health` | Rule counts (`SecurityRule.getCoreSecurityRulesCount()`), platform version |
| `POST /api/v1/sentinel/review` | `SentinelAuditOrchestrator.auditPath / auditSourceCode / auditPathWithDiff …` |
| `POST /api/v1/sentinel/review/sarif` | Same + `SarifReportGenerator` |
| `POST /api/v1/sentinel/review/github` | Same + `PrReviewCommentBuilder` |
| `POST /api/v1/sentinel/policy/evaluate` | `PolicyEngine.evaluate` |
| `GET /api/v1/sentinel/governance/status` | Static governance metadata (SOC2-CC7.1, ISO27001-A.12.6.1, OWASP-TOP-10, CWE-SANS-TOP-25) |
| `POST /api/v1/github/webhook` | `GitHubWebhookController`, `GitHubWebhookService`, `GitHubWebhookSecurityService`: HMAC-SHA256 signature verification (`X-Hub-Signature-256`), PR lifecycle orchestration (`opened`, `synchronize`, `reopened`), automatic diff retrieval, diff-scoped audit execution, automated review submission (`APPROVE`, `REQUEST_CHANGES`, `COMMENT`), check run status synchronization, and delivery deduplication |
| `GET /api/v1/github/status` | GitHub App integration health, webhook secret configuration, and processed delivery count |
| `POST /api/v1/auth/token` | `AuthController`, `ApiKeyAuthenticator`, `JwtTokenService`: Exchanges authorized API key for an RFC 7519 HS256 signed JWT Bearer token |
| `GET /api/v1/auth/me` | `AuthController`, `SentinelSecurityContext`: Returns active principal identity, roles (`ADMIN`, `REVIEWER`, `VIEWER`), and effective permissions |

## 10. REST API Authentication & Role-Based Access Control (RBAC)

```mermaid
flowchart TD
    Req["Incoming HTTP Request"] --> P{"Path is Public?\n(/health, /github/**, /auth/token)"}
    P -- Yes --> Anon["SentinelPrincipal.anonymous() → Proceed"]
    P -- No --> AuthH{"Check Auth Headers\n'X-API-Key' or 'Authorization: Bearer <jwt>'"}
    AuthH -- Missing/Invalid --> 401["HTTP 401 UNAUTHORIZED\n(WWW-Authenticate header)"]
    AuthH -- "X-API-Key present" --> KeyCheck["ApiKeyAuthenticator.authenticate()\nConstant-time digest matching"]
    AuthH -- "Bearer JWT present" --> JwtCheck["JwtTokenService.validateAndParse()\nHS256 signature & expiration validation"]
    KeyCheck & JwtCheck --> RBAC{"Check RBAC\n@RequireRole / @RequirePermission"}
    RBAC -- "Missing Role/Permission" --> 403["HTTP 403 FORBIDDEN"]
    RBAC -- "Authorized" --> Ctx["SentinelSecurityContext.setPrincipal()\nExecute Handler Method"]
    Ctx --> Cleanup["SentinelSecurityContext.clear()"]
```

- **Authentication Methods**: Dual support for API keys (`X-API-Key`, `Authorization: ApiKey <key>`) and RFC 7519 HS256 JSON Web Tokens (`Authorization: Bearer <token>`).
- **Timing Defense**: Constant-time verification (`MessageDigest.isEqual`) on all secrets and cryptographic token signatures.
- **Role Hierarchy**:
  - `ADMIN`: Unrestricted access to all audit, policy, configuration, and governance endpoints (`AUDIT_EXECUTE`, `POLICY_EVALUATE`, `GOVERNANCE_READ`, `CONFIG_MANAGE`).
  - `REVIEWER`: Access to `/review`, `/review/sarif`, `/review/github`, `/policy/evaluate`, `/governance/status` (`AUDIT_EXECUTE`, `POLICY_EVALUATE`, `GOVERNANCE_READ`).
  - `VIEWER`: Read-only access to `/governance/status` and `/health` (`GOVERNANCE_READ`).
- **Security Context**: Thread-safe `SentinelSecurityContext` with automatic cleanup across request lifecycles.

## 11. Documented Gaps (as found in the repository)

- No `.github/` workflows are committed; `USAGE_GUIDE.md` contains only an example GitHub Actions template.
- No `examples/` directory; runnable examples live in `src/test/java/com/sentinelpr/fixture/` and `src/test/resources/`.
- No `LICENSE` file despite the Apache-2.0 badge (see `docs/LICENSE-RECOMMENDATION.md`).
- No screenshot assets (`docs/screenshots/` does not exist).
- `apps/sentinel-pr/` contains copies of `README.md` and `USAGE_GUIDE.md` that can drift from the root versions.
- `AuditTrailEntry.ExecutionTimings` records measured phase timings (`parseMs`, `analysisMs`, `patchMs`, `totalMs`) captured during orchestrator execution.
- **Non-Java Remediation Boundary (Phase 4B.1.1)**: Automated AST patch synthesis and regression verification are restricted to Java 21 LTS sources. Non-Java languages (Kotlin, Python, JavaScript, TypeScript) explicitly yield `MANUAL_REMEDIATION_REQUIRED` with empty unified diffs and `isVerified = false`, failing closed against automated merging or policy bypass.
- **Python Lexical Analysis Limitations (Phase 4B.1.1)**: Multi-language security analysis in Python is performed via pattern matching and function-scoped lexical inspection (`getEnclosingScopeCodeLines`), not full semantic AST dataflow tracking. Scoped keyword checks filter `#` comments and isolate function blocks, but are path-insensitive, variable-agnostic, and do not model full inter-procedural dataflow.
- **First-Order Taint Boundary**: `DataflowTracker` halts taint propagation across database repository/entity lookups (`isRepositoryOrEntityLookup`) to avoid first-order overtaint. Second-order stored vulnerabilities are captured at write and read sinks individually rather than via persistent dataflow state.
- **Tracked Quality Completed (Phase 4B.2)**: Direct integration tests for `PolicyEngine`, `PrReviewCommentBuilder`, and SARIF exporters when evaluating `MANUAL_REMEDIATION_REQUIRED` patches are implemented in `NonJavaRemediationConsumerIntegrationTest`, verifying fail-closed policy enforcement and suppression of invalid synthetic diffs.
- **GitHub Action PR Diff Contract (Phase 4B.2)**: Action runner enforces three-dot merge-base diff extraction with history fetching and explicit `--diff` pass-through, verified via `ActionIntegrationContractTest`. Explicit failure is mandated on missing or malformed PR diffs without silent fallback.
