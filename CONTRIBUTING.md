# Contributing to SentinelPR

Thank you for improving SentinelPR. This guide reflects the actual developer workflow used by the project: Java 21, Maven, JUnit 5 integration tests, and a strict "every statement derives from the implementation" documentation standard.

## 1. Development environment

| Requirement | Version | Notes |
|---|---|---|
| JDK | 21 LTS | `maven.compiler.release=21` is enforced |
| Maven | 3.9+ | Wrapper is not committed; use a local install |
| IDE | Any | IntelliJ IDEA project files are present (`.idea/`) |
| `GEMINI_API_KEY` | optional | Without it, tests and chat run on the deterministic in-memory provider |

## 2. Build & test

```bash
git clone https://github.com/darshanrathod04/sentinel-pr.git
cd sentinel-pr
mvn clean install -DskipTests   # compile & install
mvn test                        # 36 integration tests must pass
```

**The `mvn test` gate is mandatory.** All six suites must stay green:

- `SentinelPrApplicationTest`
- `SentinelPrP0VerificationTest` — taint engine, suppression, patch composition, regression verification
- `SentinelPrP1SecurityVerificationTest` — core SEC rules
- `SentinelPrP2WorkflowVerificationTest` — CLI workflow, history, export formats
- `SentinelPrP3GovernanceVerificationTest` — baselines, policy, audit trail, SARIF
- `SentinelPrP4IntelligenceVerificationTest` — causal chains, calibration, multi-file planning, ARCH rules

## 3. Branching & commits

- Branch from `main`: `feat/<short-name>`, `fix/<short-name>`, `docs/<short-name>`, `rules/<rule-id>`.
- Conventional commit subjects, e.g. `feat(cli): add --chat BYOK assistant command`, `fix(sarif): normalize result paths`.
- One logical change per PR; keep PRs reviewable.

## 4. Code conventions

- Java records are not used for the domain models; the existing immutable classes use
  `final` fields with unmodifiable lists — follow that style.
- All services in `core/service` are Spring `@Service` beans wired in `SentinelPrApplication`;
  pure engines in `core/analysis` are framework-free and constructor-injected for testability.
- Every public class carries a `<b>Name</b>` Javadoc header describing its role.
- Prefer deterministic, AST-derived logic over regexes on raw source; regexes are used only
  where the existing engines already apply them (secret scanning, SQL concat matching).

## 5. Adding a new rule (SEC-0xx / ARCH-0xx)

A rule is only "added" when all of the following exist:

1. **Enum entry** in `SecurityRule` with rule ID (`SEC-011-…` / `ARCH-004-…`), severity, and a CWE-tagged explanation.
2. **Detection logic** in the appropriate engine (`ReasoningFacade` for SEC rules, `ArchitectureReviewEngine` for ARCH rules, or a dedicated analyzer wired into `RuleEvaluationService`).
3. **Patch strategy** in `PatchComposer` (and `DeveloperFacade`) guarded by `isValidJava(...)` so a bad candidate can never corrupt the composed diff.
4. **Causal chain** builder in `CausalAnalysisEngine` (trigger, hops, exploit vector, business impact, blast radius).
5. **Fixture** with intentional vulnerability under `src/test/java/com/sentinelpr/fixture/`.
6. **Tests** asserting detection *and* regression-verified patching in the relevant P-suite.
7. **Documentation** in `docs/SECURITY.md` (detection logic, danger rationale, remediation, vulnerable + fixed code).

## 6. REST / CLI changes

- New REST endpoints belong to `SentinelReviewController` under `/api/v1/sentinel` and must return
  JSON-serializable DTOs (`@JsonInclude(NON_NULL)` models).
- New CLI options must be parsed in `SentinelCliRunner.execute(String[])` **before** target-path
  parsing if they are standalone commands (like `--chat` / `--history`), must be added to
  `printUsage()`, documented in `docs/CLI.md`, and covered by tests.
- Preserve exit-code semantics: `0` pass, `1` policy breach, `2` internal error, `3` bad usage,
  `4` unverified-patch breach.

## 7. Shree AI OS boundary rules

- SentinelPR integrates with Shree AI OS **only** through `com.sentinelpr.client`
  (`SentinelClient` and the facades). Do not add direct HTTP calls to model providers anywhere else.
- The Shree AI OS dependency (`io.github.darshanrathod04:shree-ai-os`) is an external platform;
  report upstream issues to that project instead of patching around it here.
- `MemoryFacade` must never persist raw source code, unified diffs, or patch bodies — the
  metadata-only guardrail is intentional.

## 8. Documentation standards

- Any user-visible behavior change updates the relevant doc (`README.md`, `docs/CLI.md`,
  `docs/SECURITY.md`, `docs/GOVERNANCE.md`, `CHANGELOG.md`).
- Example outputs in docs must be copy-pasted from real runs — never invented.
- Undocumented behavior must be called out explicitly rather than papered over.

## 9. Pull-request checklist

- [ ] `mvn test` passes locally (all 36 tests)
- [ ] New rules/options include fixtures, tests, and documentation
- [ ] No business-logic changes sneak into unrelated files
- [ ] `CHANGELOG.md` updated under an *Unreleased* section for notable changes
- [ ] No secrets, API keys, or generated `target/` artifacts committed
- [ ] Workspace artifacts (`.sentinelhistory.json`, baselines, audit logs) are not committed

## 10. Reporting issues

Open a GitHub issue with: exact CLI invocation, full console output (redact any secrets —
note that findings already redact detected secrets automatically), expected vs. actual behavior,
and — for rule false positives — the smallest code snippet that reproduces the misclassification.
