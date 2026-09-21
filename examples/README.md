# SentinelPR Examples

Runnable starting points for SentinelPR v1.0.0. **No new code was invented for this
directory** — every file is a copy of an artifact that already exists in the repository
(test fixtures and root governance assets), kept here so users can try the CLI without
touching the test suite.

| File | Source (original location) |
|---|---|
| `VulnerableService.java` | `src/test/java/com/sentinelpr/fixture/VulnerableService.java` |
| `strict-policy.json` | `strict-policy.json` (repository root) |
| `local-baseline.json` | `local-baseline.json` (repository root) |

> **Note:** `examples/VulnerableService.java` contains *intentional* vulnerabilities.
> It is an audit target, not production code. Do not copy it into `src/` — Maven will
> not compile files under `examples/`, and the canonical (tested) copy lives in the
> test fixtures.

## 1. `VulnerableService.java` — audit target

Deliberately vulnerable Java 21 class with three findings:

| Line(s) | Rule | Severity |
|---|---|---|
| 20–25 | `SEC-002-UNCLOSED-STREAM` (CWE-404) — `FileInputStream` never closed | HIGH |
| 30–40 | `SEC-001-FAIL-OPEN` (CWE-393) — catch block returns `true` on `NullPointerException` | CRITICAL |
| 45–47 | `SEC-003-VOLATILE-COMPOUND` (CWE-362) — `requestCount++` on a `volatile` field | HIGH |

Run the audit:

```bash
mvn -q compile exec:java \
  "-Dexec.mainClass=com.sentinelpr.cli.SentinelCliRunner" \
  "-Dexec.args=examples/VulnerableService.java"
```

Expected result: 3 findings, 1 composed unified-diff patch
(`AtomicInteger`, try-with-resources, fail-closed fix), `regressionVerified: true`.

## 2. `strict-policy.json` — enterprise policy

Copy of the root policy used in the README Quick Start:

- `maxAllowedCritical: 0` — no active CRITICAL findings tolerated
- `maxAllowedHigh: 1` — at most one HIGH finding tolerated
- `maxAllowedMedium: 5`
- `failOnUnverifiedPatch: true` — breach (exit 4) if any synthesized patch fails verification
- `blockedRules: ["SEC-001-FAIL-OPEN"]` — the fail-open rule can **never** be suppressed,
  not by baseline debt, not by diff filtering

Apply it:

```bash
mvn -q compile exec:java \
  "-Dexec.mainClass=com.sentinelpr.cli.SentinelCliRunner" \
  "-Dexec.args=examples/VulnerableService.java --policy examples/strict-policy.json"
```

Expected result: `--- [Enterprise Policy Evaluation: BREACHED] ---` on stderr with the
`SEC-001-FAIL-OPEN` violation marked `BLOCKED_BY_POLICY`, exit code `1`.
(Unset fields fall back to `SentinelPolicy` defaults: policy name
`Enterprise-Strict-Security-Policy`, version `1.0`, unlimited LOW, `requiredTags` `OWASP-TOP-10`.)

## 3. `local-baseline.json` — accepted technical debt

A real baseline snapshot (schema `1.0`) previously captured from `VulnerableService.java`
with `--create-baseline`. It records the same three findings with SHA-256 fingerprints.
Because `SEC-001-FAIL-OPEN` is a blocked rule in the accompanying policy, only the
stream and volatile entries can be suppressed as `BASELINE_ACCEPTED`.

Apply policy + baseline together:

```bash
mvn -q compile exec:java \
  "-Dexec.mainClass=com.sentinelpr.cli.SentinelCliRunner" \
  "-Dexec.args=examples/VulnerableService.java --baseline examples/local-baseline.json --policy examples/strict-policy.json"
```

Expected result: `PASSED_WITH_BASELINE` for the baseline entries, with the blocked
fail-open rule still active → policy verdict determined by the `blockedRules` supremacy check.

## 4. Regenerating a baseline

To capture a fresh snapshot from the current state of the target:

```bash
mvn -q compile exec:java \
  "-Dexec.mainClass=com.sentinelpr.cli.SentinelCliRunner" \
  "-Dexec.args=examples/VulnerableService.java --create-baseline examples/my-baseline.json"
```

## More examples

Additional vulnerable samples (taint flows, secret scanning, Spring misconfigurations,
coupled architectures) live in the test fixtures:
`src/test/java/com/sentinelpr/fixture/` and `src/test/resources/`
(`SampleBaseline.json`, `SamplePolicy.json`, `SampleIncrementalDiff.patch`).
