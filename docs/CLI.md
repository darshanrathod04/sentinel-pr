# SentinelPR — CLI Reference (v1.0.0)

Entry point: `com.sentinelpr.cli.SentinelCliRunner` (implemented in `src/main/java/com/sentinelpr/cli/SentinelCliRunner.java`).

## Invocation

```bash
# Packaged jar
java -jar sentinel-pr.jar <target-path> [options]

# Maven (developer workflow)
mvn exec:java "-Dexec.mainClass=com.sentinelpr.cli.SentinelCliRunner" \
  "-Dexec.args=<target-path> [options]"

# Or simply (Spring Boot CommandLineRunner shortcut: first non-option arg audits the target)
mvn spring-boot:run -- <target-path>
```

Running with **no arguments** prints the usage menu and exits with code `3`.

## Command overview

```text
Usage: java -jar sentinel-pr.jar <target-path> [options]
Options:
  --diff <patch-file>            Enable incremental git diff scanning
  --baseline <baseline-file>     Filter findings against technical debt baseline
  --create-baseline <out.json>   Export findings as technical debt baseline snapshot
  --policy <policy-file>         Enforce enterprise compliance policy thresholds
  --sarif <output-file>          Export OASIS SARIF v2.1.0 report
  --audit-log <ledger.log>       Append signed cryptographic SOC2/ISO27001 audit entry
  --history                      Display review session history from Memory Kernel
  --run <run-id>                 Inspect detailed metadata for a specific review session
  -f, --format <format>          Output format (json, sarif, github, text) [default: json]
  --chat "<prompt>"              Ask SentinelPR AI assistant (Gemini BYOK)
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Audit passed (PASSED or PASSED_WITH_BASELINE), history displayed, or chat answered |
| `1` | Enterprise policy breached (defect thresholds / blocked rules) |
| `2` | Internal engine error (exception during execution) |
| `3` | Invalid CLI arguments, non-existent target path, or missing chat prompt |
| `4` | Patch generation / verification failure (policy breach with unverified patches) |

---

## 1. Basic audit (`<target-path>`)

```bash
sentinel src/main/java/com/sentinelpr/service
```

Audits a file or recursively scans a directory (all `*.java` files; unparseable files are skipped with a warning). Console output:

```text
================================================================================
 SentinelPR — Enterprise Code & Security Review Copilot
 Powered by Shree AI OS (io.github.darshanrathod04:shree-ai-os:1.0.6-developer-preview)
 Target: <absolute target path>
================================================================================

--- [Audit Execution Summary] ---
Status:          SUCCESS
Files Scanned:   1
Vulnerabilities: 3
Suppressed:      0
Patches Created: 1
Cached Session:  false
Message:         Audit completed. Scanned 1 source file(s), identified 3 vulnerability finding(s) (0 suppressed), synthesized 1 verified patch(es).

--- [Detected Vulnerabilities] ---
  [CRITICAL] <description> (<file>:<startLine>-<endLine>)
    Rationale:   <causal rationale>
    Remediation: <remediation guidance>
  ...

--- [Suppressed & Baseline Findings] ---           (only when suppressions exist)
  [SUPPRESSED via BASELINE_ACCEPTED] <description> (<file>:<lines>)
    Matched Reason: Accepted technical debt present in baseline snapshot (fingerprint: <hash>)

--- [Synthesized Verified Patches (Unified Diff)] ---   (only when patches exist)
  Patch for [SEC-003-VOLATILE-COMPOUND, SEC-002-UNCLOSED-STREAM, SEC-001-FAIL-OPEN] -> Status: SUCCESS (Verified: true, RegressionVerified: true)
<unified diff>

--- [Structured JSON Report] ---                   (default format)
<full ReviewReport JSON>
```

If the same source content was audited before (SHA-256 fingerprint match in Memory Kernel), `Cached Session: true` is reported and rule evaluation is skipped.

---

## 2. `--diff <patch-file>`

Enables **incremental PR scanning**: the given unified git diff is parsed into hunks; only findings whose line ranges intersect an added/modified hunk block the PR. All other findings are recorded as suppressed with type `DIFF_BASELINE` ("Baseline finding outside incremental PR diff range").

```bash
sentinel src/test/java/com/sentinelpr/fixture/VulnerableService.java \
  --diff .sentinel-out/pr.patch
```

Typical PR pipeline:

```bash
git diff origin/main...HEAD -- '*.java' > pr.patch
sentinel path/Changed.java --diff pr.patch
```

---

## 3. `--baseline <baseline-file>`

Filters findings against a previously captured technical-debt snapshot. Matches are suppressed with type `BASELINE_ACCEPTED`; unmatched (new) findings stay active. If a `--policy` is also supplied, **blocked rules cannot be suppressed by the baseline** (policy supremacy).

```bash
sentinel src/main/java --baseline .sentinelbaseline.json
```

Baseline matching uses an exact SHA-256 fingerprint (`filePath|ruleId|methodName|snippet`) or a structural match (same file + same rule + same method, or start line within ±5).

---

## 4. `--create-baseline <out.json>`

Captures all active findings of the current audit into a versioned snapshot (schema `1.0`) and writes it to disk.

```bash
sentinel src/main/java --create-baseline local-baseline.json
```

Console line:

```text
[SentinelPR:CLI] Baseline snapshot captured to: D:\work\local-baseline.json
```

Snapshot shape (`BaselineSnapshot`):

```json
{
  "version" : "1.0",
  "createdAt" : "2026-09-21T00:00:00Z",
  "targetPath" : "src/main/java",
  "totalEntries" : 3,
  "entries" : [ {
    "fingerprint" : "<32-hex-chars>",
    "filePath" : "src/main/java/…",
    "ruleId" : "SEC-001-FAIL-OPEN",
    "startLine" : 36, "endLine" : 39,
    "className" : "VulnerableService",
    "methodName" : "checkUserAuthorization",
    "snippet" : "return true;",
    "capturedAt" : "2026-09-21T00:00:00Z"
  } ]
}
```

---

## 5. `--policy <policy-file>`

Evaluates the report against an enterprise policy (`SentinelPolicy` JSON). Policy outcomes: `PASSED`, `PASSED_WITH_BASELINE`, `BREACHED` (and internal `FAILED`). Breaches are printed to **stderr** with `❌` markers and drive exit codes `1`/`4`.

```bash
sentinel src/main/java --policy strict-policy.json
```

Example policy (`strict-policy.json` committed at repo root mirrors `src/test/resources/SamplePolicy.json`):

```json
{
  "policyName": "Enterprise-Strict-Security-Policy",
  "version": "1.0",
  "maxAllowedCritical": 0,
  "maxAllowedHigh": 0,
  "maxAllowedMedium": 5,
  "failOnUnverifiedPatch": true,
  "blockedRules": [ "SEC-001-FAIL-OPEN" ],
  "requiredTags": [ "OWASP-TOP-10", "SOC2-CC7.1" ]
}
```

Breach output (stderr):

```text
--- [Enterprise Policy Evaluation: BREACHED] ---
Enterprise policy 'Enterprise-Strict-Security-Policy' BREACHED with 3 violation(s) (1 blocked by policy). Audit gate failed.
  ❌ Policy breach: Finding violates strictly blocked rule [SEC-001-FAIL-OPEN] in src\…\VulnerableService.java (lines 36-39): Fail-open security catch block grants access upon NullPointerException (BLOCKED_BY_POLICY)
  ...
```

---

## 6. `--sarif <output-file>`

Writes an OASIS SARIF v2.1.0 report for GitHub Code Scanning / GitLab SAST / SonarQube.

```bash
sentinel src/main/java --sarif report.sarif
```

```text
[SentinelPR:CLI] SARIF v2.1.0 report exported to: D:\work\report.sarif
```

Severity mapping: CRITICAL/HIGH → `error`, MEDIUM → `warning`, LOW/INFO → `note`. Each result carries `cwe`, `remediation`, `confidence`, and (when available) `patchStatus`, `patchVerified`, `regressionVerified`, `unifiedDiff` properties. Help URIs link to `https://cwe.mitre.org/data/definitions/<CWE>.html`.

---

## 7. `--audit-log <ledger.log>`

Appends one immutable NDJSON audit entry with a SHA-256 report signature.

```bash
sentinel src/main/java --policy strict-policy.json --audit-log compliance-audit.log
```

```text
[SentinelPR:CLI] Cryptographic audit trail appended to: D:\work\compliance-audit.log
```

Entry fields include `runId`, `timestamp`, `targetPath`, `commitId` (`HEAD`), `branch` (`main`), `operator` (from `GITHUB_ACTOR`/`USER`/`USERNAME`/`user.name`), `inputFingerprint`, `reportSignature`, `policyStatus`, finding counts, `ruleSetVersion` (`v1.0.0`), `policyVersion` (`v1.0`), and execution timings. `AuditTrailLogger.verifyAuditEntry(...)` can recompute and validate the signature later.

---

## 8. `--history`

Prints the review-session history table assembled from Memory Kernel recall, the fast cache, and the durable `.sentinelhistory.json` ledger (metadata only — never source code).

```bash
sentinel --history
```

Returns exit code `0`.

---

## 9. `--run <run-id>`

Displays detailed metadata for one recorded session.

```bash
sentinel --run REV-1a2b3c4d
```

Returns exit code `0`. Unknown run IDs produce the MemorySDK "not found" response rendered by `MemoryFacade.formatSessionDetail`.

---

## 10. `--chat "<prompt>"`

Routes a free-form question through the Shree AI OS LLM router (Gemini BYOK when `GEMINI_API_KEY` is set; deterministic in-memory fallback otherwise). **Everything after `--chat` is joined into a single prompt**, so quoting is optional:

```bash
sentinel --chat "Explain why requestCount++ is unsafe in Java"
sentinel --chat Explain why requestCount++ is unsafe in Java
```

Output:

```text
================================================
 SentinelPR AI Assistant
 Provider: Gemini (BYOK)
================================================

<response content>
```

Missing prompt validation:

```bash
$ sentinel --chat
Error: Missing chat prompt.
Usage:
  sentinel --chat "your question"
$ echo $?
3
```

Exit codes: `0` on success, `3` when the prompt is missing/blank. *Shree AI OS runtime initialization logs may appear on the console around the response; they originate in the platform SDK, not the CLI.*

---

## 11. `-f, --format <json|sarif|github|text>`

Controls stdout output after the human-readable summary (works with any audit):

| Format | Behavior |
|---|---|
| `json` *(default)* | Prints `--- [Structured JSON Report] ---` followed by the full `ReviewReport` JSON |
| `sarif` | Prints `--- [OASIS SARIF v2.1.0 Report] ---` followed by SARIF JSON (same model as `--sarif` writes to disk) |
| `github` | Prints `--- [GitHub PR Review Payload] ---` followed by the JSON body for `POST /repos/{owner}/{repo}/pulls/{pull_number}/reviews`: `commit_id` (`HEAD`), markdown `body` summary table, `event` (`COMMENT`), and inline `comments[]` with `path` / `line` / `side` (`RIGHT`) containing ```suggestion``` blocks extracted from the verified unified diffs |
| `text` | Prints only the human-readable summary sections |

Example:

```bash
sentinel src/main/java --policy strict-policy.json -f github
```

---

## Options are combinable

```bash
sentinel src/main/java \
  --diff pr.patch \
  --baseline local-baseline.json \
  --policy strict-policy.json \
  --create-baseline new-baseline.json \
  --sarif report.sarif \
  --audit-log compliance-audit.log \
  -f sarif
```

Dispatch order implemented in `SentinelCliRunner.execute(...)`: diff+baseline → `auditPathWithDiffAndBaseline`; baseline only → `auditPathWithBaseline`; diff only → `auditPathWithDiff`; otherwise → `auditPath`. Option parsing ignores case for flags and only treats non-`-` arguments as the target path.
