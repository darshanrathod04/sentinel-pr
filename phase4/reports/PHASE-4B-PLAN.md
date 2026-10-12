# SentinelPR Phase 4B — Real PR Dogfooding & CI/CD Integration Audit Plan

**Phase:** Phase 4B (Production Dogfooding & Pull Request Review Validation)
**SentinelPR Engine Version:** `v1.1.4`
**Starting Commit:** [`0c66b96f5e80997fe8e26a8d0861375053769bd4`](https://github.com/darshanrathod04/sentinel-pr/commit/0c66b96f5e80997fe8e26a8d0861375053769bd4)
**Repository Under Test:** `https://github.com/darshanrathod04/sentinel-pr`
**Status:** Independent Security Audit & Evidence Revision (Pending Maintainer Scope Approval)

---

## 1. Executive Summary & Audit Baseline

This document establishes the independent audit and empirical test plan for **SentinelPR Phase 4B: Real PR Dogfooding & CI/CD Integration**.

Phase 4A evaluated whole-repository static scans against standalone codebases (`Todo-Application`, `Smart Campus Connect`, and `College Management Backend`). Phase 4B evaluates the **pull request lifecycle**, incremental diff filtering, GitHub Actions composite runner behavior, sticky review comment idempotency, SARIF reporting, and CI error handling.

### 1.1 Baseline Verification
- **HEAD Commit SHA:** `0c66b96f5e80997fe8e26a8d0861375053769bd4`
- **Origin Synchronization:** `origin/main` equals `0c66b96f5e80997fe8e26a8d0861375053769bd4` (verified via `git rev-parse origin/main`).
- **Working Tree State:** Clean baseline; only this report file is tracked as untracked/uncommitted pending formal maintainer review.
- **Active Release Version:** Maintained strictly at `v1.1.4`. No release metadata, pom.xml version tags, or GitHub release tags have been modified.
- **Existing Phase 4A Records:** All records in `phase4/observations/` and `phase4/reports/` remain unmodified.

---

## 2. Concise Phase 4B Test Matrix (8 Dimensions)

The evaluation covers 8 operational dimensions, distinguishing between **Historical Real Pull Requests** (executed on GitHub Actions) and **Local CLI Incremental Diff Experiments** (executed on pinned checkouts):

| Dimension | Scenario | Evaluation Target & Context | Base Commit | Head Commit | Evaluation Scope | Provenance Type |
| :---: | :--- | :--- | :--- | :--- | :--- | :--- |
| **Case 1** | **Known Vulnerable PR Diff** | [`darshanrathod04/Todo-Application` PR #1](https://github.com/darshanrathod04/Todo-Application/pull/1) | `bb4b69a50ee8` | `b34cd057ab98` | Detection, Slicing & Remediation | Historical PR + Local CLI |
| **Case 2** | **Known Safe PR Diff** | [`darshanrathod04/College-management-backemd`](https://github.com/darshanrathod04/College-management-backemd/commit/38a084e4fdc59bd7b732502bcf06738e1e05e26a) | `aa4fdcd` | `38a084e4fdc5` | Specificity & DTO Layer Safety | Commit Diff Simulation |
| **Case 3** | **Mixed PR Diff** (Vulnerable + Safe) | [`darshanrathod04/sentinel-pr` PR #7](https://github.com/darshanrathod04/sentinel-pr/pull/7) | `7d030589d797` | `224b6f2ae7dc` | Discrimination & Multi-File Diff | Historical PR + Local CLI |
| **Case 4** | **No-op Non-Java PR Diff** | [`darshanrathod04/sentinel-pr` PR #6](https://github.com/darshanrathod04/sentinel-pr/pull/6) | `0dfd762f7b9a` | `f10596fc4d66` | Non-Java Diff Filtering | Historical PR + Local CLI |
| **Case 5** | **Malformed & Boundary Inputs** | Synthetic edge cases (5A Missing dir, 5B 0 Java files, 5C Malformed diff) | N/A | N/A | Robustness & Error Diagnostics | Local CLI Execution |
| **Case 6** | **Sticky Comment Idempotency** | [`darshanrathod04/Todo-Application` PR #1](https://github.com/darshanrathod04/Todo-Application/pull/1) (Comment `5835224247`) | `bb4b69a50ee8` | `b34cd057ab98` | Bot Update-in-Place & Anti-Spam | Historical GitHub API + Unit Tests |
| **Case 7** | **OASIS SARIF v2.1.0 Export** | CLI `--sarif` output on PR #1 diff | `bb4b69a50ee8` | `b34cd057ab98` | GitHub Code Scanning Interop | Local CLI Artifact |
| **Case 8** | **CI Failure & Permission Bounds** | CLI `--post-comment` without token / PR context | N/A | N/A | Auth Errors & Policy Gating | Local CLI Execution |

---

## 3. Audit 1 — Individual Ground Truth & Strict Classifications

### 3.1 Case 1: Known Vulnerable PR Diff (`Todo-Application` PR #1)
- **Target Repository:** `https://github.com/darshanrathod04/Todo-Application`
- **PR Number:** `#1` (`ci: add SentinelPR security gate`)
- **Base Commit:** `bb4b69a50ee814d00129fdbe2286eeaa048a078f`
- **Head Commit:** `b34cd057ab985bd2480145b8f38fa1bb68ae16a2`
- **Changed Java File in PR Diff:** `src/main/java/com/application/todoList/TodoRepository.java` (+27 lines)

#### Individual Finding Classifications:
1. **Finding 1 — SQL Injection:**
   - **File:** `TodoRepository.java:18`
   - **Rule:** `SEC-005-SQL-INJECTION` (Severity: `CRITICAL`)
   - **Source Code Snippet:** `String rawSql = "SELECT * FROM todos WHERE title = '" + titleFilter + "'; ResultSet rs = stmt.executeQuery(rawSql);`
   - **Ground Truth Evidence:** Untrusted user input (`titleFilter`) concatenated directly into dynamic SQL query executed via `Statement.executeQuery`. Confirmed exploitable SQL injection (CWE-89).
   - **Classification:** **`TP` (True Positive)**.
2. **Finding 2 — Hardcoded Credentials:**
   - **File:** `TodoRepository.java:13`
   - **Rule:** `SEC-008-HARDCODED-SECRET` (Severity: `HIGH`)
   - **Source Code Snippet:** `DriverManager.getConnection("jdbc:mysql://localhost:3306/tododb", "root", "")`
   - **Ground Truth Evidence:** Database username `"root"` and empty password hardcoded directly in application source code. Confirmed credential exposure (CWE-798).
   - **Classification:** **`TP` (True Positive)**.
3. **Pre-Existing Baseline Files (Outside Diff):**
   - **File:** `src/main/java/com/application/todoList/controller/TaskController.java` (Lines 18, 23, 28)
   - **Rule:** `ARCH-002` (`ARCH_LEAKY_ABSTRACTION`)
   - **Engine Behavior in PR-Diff Mode:** Excluded from active findings under suppression type `DIFF_BASELINE` (`"Baseline finding outside incremental PR diff range"`).
   - **Classification:** **`BASELINE_SUPPRESSED` / `OUT_OF_SCOPE`** for incremental PR review.
   - **Metric Rule Notice:** These three findings are pre-existing flaws outside the modified lines; they are **NOT** detection True Negatives and must **NOT** be included in detection metric denominators.

#### Category Separation for Case 1:
- **Category A — Detection Accuracy on PR Diff:**
  - Active PR Findings Detected: `2` (`TP = 2`, `FP = 0`, `FN = 0`, `TN = 0`).
  - **Precision:** $2 / (2 + 0) = \mathbf{100.0\%}$ (Strictly scoped to this single PR diff and its two documented findings)
  - **Recall:** $2 / (2 + 0) = \mathbf{100.0\%}$ (Strictly scoped to this single PR diff and its two documented findings)
  - > [!IMPORTANT]
  - > **Sample Size & Scope Limitation:**
  - > These 100.0% precision and recall metrics apply strictly and exclusively to this single evaluated vulnerable PR diff (`Todo-Application` PR #1) against its documented ground truth (2 findings in 27 changed lines). This sample ($N = 1$ PR diff, 2 vulnerabilities) is insufficient to estimate real-world, product-wide accuracy or generalize detection reliability across arbitrary codebases.
- **Category B — Diff-Filter Slicing Behavior:**
  - Pre-existing Baseline Flaws Excluded: `3` (`BASELINE_SUPPRESSED` in `TaskController.java`).
  - Filter Isolation Rate: `3 / 3` (100% of out-of-diff flaws successfully quarantined from PR blocker status).
- **Category C — Integration Reliability:**
  - Sticky Comment Created / Updated: Verified (Comment ID `5835224247`).
  - Patch Synthesized: 1 multi-rule unified diff patch (`astValid: true`, `target findings removed`).

---

### 3.2 Case 2: Known Safe PR Diff (`College Management Backend` StudentDTO Update)
- **Target Repository:** `https://github.com/darshanrathod04/College-management-backemd`
- **Simulated PR Commit Range:** `aa4fdcd` -> `38a084e4fdc59bd7b732502bcf06738e1e05e26a`
- **Changed Java File in Diff:** `src/main/java/com/college/dto/StudentDTO.java` (+10 / -53 lines)
- **Ground Truth Audit:** Diff updates Jakarta / Bean Validation annotations (`@NotBlank`, `@Schema`, `@Email`, `@Min`, `@Pattern`, `@NotNull`) on private POJO fields.
- **Rule-Specific Classification:**
  - `ARCH-002` (Leaky Abstraction / DTO encapsulation): Applicable to DTO layer. Confirmed safe (clean DTO, no persistence entity leakage). Classification: **`TN` (True Negative)**.
  - Sinks and logic rules (`SEC-001` through `SEC-010`): Evaluated across the file. No tainted dataflow or vulnerable patterns. Because `StudentDTO` contains only field definitions without executable methods or sinks, logic rules are classified as **`NOT_APPLICABLE`** to this specific diff.
- **Valid Metrics for Case 2:**
  - Active PR Findings Detected: `0` (`TP = 0`, `FP = 0`, `FN = 0`).
  - Audited Safe Classification: `1 TN` (`ARCH-002`).
  - Precision / Recall: **N/A** (0/0 denominator).

---

### 3.3 Case 3: Mixed PR Diff (`sentinel-pr` PR #7)
- **Target Repository:** `https://github.com/darshanrathod04/sentinel-pr`
- **PR Number:** `#7` (`Release SentinelPR v1.1.4`)
- **Base Commit:** `7d030589d79730e550e606782249b8d1f49e0908`
- **Head Commit:** `224b6f2ae7dce27050cd852e6b9e940889b4bb2f`
- **Changed Files in Diff:** 30 files introducing synthetic benchmark cases.
- **Observed CLI Result:** 275 files scanned; 271 active findings touching diff hunks; 346 suppressed as baseline; 111 patches synthesized.
- **Audit Assessment:**
  > [!IMPORTANT]
  > **Unverified Aggregate Evidence Notice:**
  > Because the 271 findings stem from a massive commit adding synthetic benchmark fixtures across 11 rules, each finding has not been individually audited against real production PR ground truth.
  > Therefore, the 271 count is recorded strictly as **unverified aggregate evidence of engine execution**, and **no precision or recall percentages are computed from this case**.
- **Companion Safe Hunks:** Safe companion fixtures (`DecoupledServiceA.java`, `SafeUserController.java`, `ADV-SEC001-S01.java`) touching the diff were evaluated with 0 findings, confirming discrimination capability.

---

### 3.4 Case 4: No-op / Non-Java PR Diff (`sentinel-pr` PR #6)
- **Target Repository:** `https://github.com/darshanrathod04/sentinel-pr`
- **PR Number:** `#6` (`chore: upgrade SentinelPR action to v1.1.2`)
- **Base Commit:** `0dfd762f7b9a943ae88cd0fcf6bd5b2ae0d43b30`
- **Head Commit:** `f10596fc4d66668105ca5dc2b14bce40a019df08`
- **Changed Files in Diff:** Exactly 1 file: `.github/workflows/sentinel-pr.yml` (+1 / -1 line).
- **Ground Truth Audit:** Zero Java source files modified.
- **Rule-Specific Classification:**
  - Java security rules (`SEC-001` through `SEC-010`, `ARCH-001` through `ARCH-003`): **`NOT_APPLICABLE`** (no Java AST present in the diff).
  - PR-Diff Slicing Filter (`IncrementalDiffScanner`): **`CLEAN` / `BASELINE_FILTERED`** (correctly recognized that 0 Java hunks changed and reported 0 active PR vulnerabilities).
  - *Correction:* This case confirms diff-slicing silence, but does **not** count as a detection TN and does **not** constitute proof of "100% false-alarm immunity" across arbitrary repositories.

---

## 4. Audit 2 — GitHub Action PR-Diff Behavior Investigation

A critical objective of Phase 4B was auditing the real CI/CD integration defined in [`action.yml`](../../action.yml).

### 4.1 Invocation Analysis in `action.yml` (v1.1.4)
Lines 47–54 of [`action.yml`](../../action.yml#L47-L54) specify:
```yaml
    - name: Run SentinelPR
      shell: bash
      env:
        GITHUB_TOKEN: ${{ inputs.github_token }}
        GEMINI_API_KEY: ${{ inputs.gemini_api_key }}
      run: |
        java -Dloader.main=com.sentinelpr.cli.SentinelCliRunner \
          -cp sentinel-pr.jar org.springframework.boot.loader.launch.PropertiesLauncher \
          --target . \
          --repo ${{ github.repository }} \
          --pr ${{ github.event.pull_request.number }} \
          --post-comment \
          -f ${{ inputs.format }}
```

### 4.2 CLI Argument & Code Path Inspection
1. **Effective Arguments Passed:** `--target . --repo ${{ github.repository }} --pr ${{ github.event.pull_request.number }} --post-comment -f ${{ inputs.format }}`.
2. **Missing Argument:** The argument `--diff <patch-path>` is **completely absent**.
3. **Absence of Implicit Diff Discovery:**
   - In [`SentinelCliRunner.java`](../../src/main/java/com/sentinelpr/cli/SentinelCliRunner.java#L531), `diffPath` defaults to `null`.
   - In [`SentinelCliRunner.java`](../../src/main/java/com/sentinelpr/cli/SentinelCliRunner.java#L324-L332):
     ```java
     if (diffPath != null && Files.exists(diffPath) && baselinePath != null && Files.exists(baselinePath)) {
         report = orchestrator.auditPathWithDiffAndBaseline(targetPath, Files.readString(diffPath), baselinePath, policy);
     } else if (baselinePath != null && Files.exists(baselinePath)) {
         report = orchestrator.auditPathWithBaseline(targetPath, baselinePath, policy);
     } else if (diffPath != null && Files.exists(diffPath)) {
         report = orchestrator.auditPathWithDiff(targetPath, diffPath);
     } else {
         report = orchestrator.auditPath(targetPath); // <-- INVOKED IN ACTION RUNS
     }
     ```
   - Neither `SentinelCliRunner` nor `SentinelAuditOrchestrator` calls `git diff` or the GitHub API to discover changed PR files.
   - When `diffPath == null`, the engine dispatches to `auditPath(targetPath)`, which recursively scans **every Java file in the target repository**.

### 4.3 Confirmed Defect: `DEFECT-PHASE4B-001`
- **Defect Identifier:** `DEFECT-PHASE4B-001`
- **Classification:** **CONFIRMED DEFECT**
- **Component:** [`action.yml`](../../action.yml#L48-L54) (GitHub Action composite runner)
- **Severity:** HIGH (Operational / False Blocker in CI)
- **Description:** Because `action.yml` invokes `SentinelCliRunner` with `--target .` without supplying `--diff`, SentinelPR runs in **whole-repository scan mode** rather than **incremental PR-diff mode**. As a consequence, pre-existing repository technical debt outside the PR diff is reported as active PR findings, causing PRs touching unrelated or non-Java files to be marked `BLOCKED`.

### 4.4 Distinction: Actual Historical GitHub Action Execution vs. Verified CLI Behavior
- **Actual Historical GitHub Action Execution:**
  - On `darshanrathod04/sentinel-pr` PR #7 (Run ID `37021806427`), GitHub Actions executed `darshanrathod04/sentinel-pr@v1.1.4` via `action.yml`. The posted review comment (ID `5954889582`) cited `./examples/VulnerableService.java:46` and stated `... 467 additional findings omitted`. Because `action.yml` omitted `--diff`, the workflow in production scanned all pre-existing benchmark and fixture files across the repository.
  - On `darshanrathod04/sentinel-pr` PR #6 (Run on commit `f10596fc4d66`), the PR touched only `.github/workflows/sentinel-pr.yml`. However, the action scanned all repository baseline fixtures because `--diff` was missing.
- **Verified Local CLI Behavior:**
  - Local CLI execution demonstrates that `SentinelCliRunner` itself **does support** incremental diff scanning when `--diff <patch>` is explicitly provided on the command line.

### 4.5 Proposed Action Integration Contract Regression Test Design (Unexecuted Specification)

> [!NOTE]
> **Status: Proposed Test Design Specification (Not Implemented / Not Executed in Test Suite)**
> To preserve the release v1.1.4 baseline and maintain zero modifications to `src/` during Phase 4B documentation review, this Java test has **not** been added to `src/test/` and has **not** been executed by Maven. No unit test execution logs or exit codes exist for this Java method.
> Instead, empirical verification of the underlying behavior was conducted separately via a local scratch CLI script (`audit2_diff_reproduction.ps1` invoking `SentinelCliRunner` with and without `--diff`), which confirmed the contrasting outcomes.
> The code below represents the proposed design specification for future implementation in the v1.2.0 backlog.

```java
/**
 * PROPOSED TEST SPECIFICATION (v1.2.0 Backlog - Not Yet Committed or Executed):
 * Verifies that a target repository containing both a modified vulnerable file
 * and an unmodified vulnerable baseline file produces contrasting outcomes
 * under full-scan mode (action.yml v1.1.4) versus incremental diff mode (proposed v1.2.0).
 */
@Test
@DisplayName("Action Contract Test: Differentiates full-repository scan from PR-diff scan on mixed repository")
void testActionDiffContractDistinction() throws IOException {
    Path repoDir = createTempRepoDirectory();

    // 1. Unchanged baseline file outside PR diff (contains pre-existing ARCH-002 flaw)
    Path unchangedFile = repoDir.resolve("TaskController.java");
    Files.writeString(unchangedFile, """
        package com.example;
        import org.springframework.web.bind.annotation.*;
        @RestController
        public class TaskController {
            @GetMapping("/tasks")
            public TaskEntity getTask() { return new TaskEntity(); } // Leaky abstraction
        }
    """);

    // 2. Changed file introduced in PR diff (contains new SEC-005 flaw)
    Path changedFile = repoDir.resolve("TodoRepository.java");
    Files.writeString(changedFile, """
        package com.example;
        import java.sql.*;
        public class TodoRepository {
            public void search(String q) throws Exception {
                Connection c = DriverManager.getConnection("jdbc:h2:mem:", "sa", "");
                c.createStatement().executeQuery("SELECT * FROM t WHERE name = '" + q + "'");
            }
        }
    """);

    // 3. Unified diff touching ONLY TodoRepository.java
    String prDiff = """
        --- a/TodoRepository.java
        +++ b/TodoRepository.java
        @@ -1,9 +1,9 @@
        +package com.example;
        +import java.sql.*;
        +public class TodoRepository {
        +    public void search(String q) throws Exception {
        +        Connection c = DriverManager.getConnection("jdbc:h2:mem:", "sa", "");
        +        c.createStatement().executeQuery("SELECT * FROM t WHERE name = '" + q + "'");
        +    }
        +}
    """;
    Path diffPath = repoDir.resolve("pr.diff");
    Files.writeString(diffPath, prDiff);

    SentinelCliRunner runner = new SentinelCliRunner();

    // EXECUTION A: Full-Repository Scan (v1.1.4 action.yml contract: no --diff)
    SentinelCliRunner.CliExecutionResult fullResult = runner.execute(
        repoDir, null, null, null, null, null, null, null, "json"
    );
    // EXPECTED OUTCOME A: Both files flagged (Total = 2, Active = 2, Suppressed = 0)
    assertEquals(2, fullResult.getReport().getVulnerabilityCount(),
        "Full repository scan must detect both changed and unchanged baseline flaws");
    assertEquals(0, fullResult.getReport().getSuppressedCount(),
        "Full repository scan must not suppress baseline findings");

    // EXECUTION B: Incremental PR Scan (Proposed v1.2.0 contract: with --diff)
    SentinelCliRunner.CliExecutionResult diffResult = runner.execute(
        repoDir, diffPath, null, null, null, null, null, null, "json"
    );
    // EXPECTED OUTCOME B: Only TodoRepository.java is active; TaskController.java is BASELINE_SUPPRESSED
    assertEquals(1, diffResult.getReport().getVulnerabilityCount(),
        "Incremental scan must detect ONLY the flaw in the changed file");
    assertEquals(1, diffResult.getReport().getSuppressedCount(),
        "Incremental scan must suppress the pre-existing flaw outside the diff");
    assertEquals("DIFF_BASELINE", diffResult.getReport().getSuppressedFindings().get(0).getSuppressionType());
}
```

---

## 5. Audit 3 — Remediation & Patch Verification Breakdown

For the synthesized multi-rule patch on `TodoRepository.java` (`SEC-005` SQL injection and `SEC-008` hardcoded secret):

```diff
--- a/TodoRepository.java
+++ b/TodoRepository.java
@@ -6,15 +6,16 @@
 import java.sql.DriverManager;
 import java.sql.ResultSet;
-import java.sql.Statement;
-
-public class TodoRepository {
-    public void searchTodo(String titleFilter) {
-        try {
-            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/tododb", "root", "");
-            Statement stmt = conn.createStatement();
-
-            // INTENTIONAL VULNERABILITY: Raw input string concatenation (Source to Sink)
-            String rawSql = "SELECT * FROM todos WHERE title = '" + titleFilter + "'";
-            ResultSet rs = stmt.executeQuery(rawSql);
+import java.sql.PreparedStatement;
+import java.sql.Statement;
+
+public class TodoRepository {
+    public void searchTodo(String titleFilter) {
+        try {
+            Connection conn = DriverManager.getConnection(System.getenv("DB_URL"), System.getenv("DB_USER"), System.getenv("DB_PASSWORD"));
+            PreparedStatement stmt = conn.prepareStatement(
+                "SELECT * FROM todos WHERE title = ?"
+            );
+            stmt.setString(1, titleFilter);
+            ResultSet rs = stmt.executeQuery();

             while (rs.next()) {
```

### Detailed Remediation Verification Matrix:
| Verification Dimension | Engine Behavior (SentinelPR) | Independent Audit Verification | Status |
| :--- | :--- | :--- | :---: |
| **1. AST Syntax Validity** | Verified in-memory via `JavaParser` (Java 21 LTS) and `JavaAstParser` | Verified: parse tree generated without syntax errors | **VERIFIED** |
| **2. Patched-Source Rescan** | In-memory re-scan by `PatchVerifier` | Executed SentinelPR CLI on patched file: **0 vulnerabilities detected** | **VERIFIED** |
| **3. Compilation** | **NOT EXECUTED** by SentinelPR engine | Executed `javac -d scratch TodoRepository.java` & `mvn compile`: **Exit Code 0** | **VERIFIED (External)** |
| **4. External Regression Testing** | In-memory AST re-evaluation only (`regressionVerified: true`) | Target test suite (`mvn test`) **NOT RUN** by engine during review | **NOT_TESTED BY ENGINE** |

> [!NOTE]
> In SentinelPR v1.1.4, `astValid: true` and `regressionVerified: true` indicate **in-memory AST syntax parsing and rule re-evaluation silence**. SentinelPR does **not** invoke `javac` or execute external JUnit tests. External compilation was proven separately via `javac` (exit 0) and `mvn compile` (exit 0).

---

## 6. Audit 4 — Malformed Diff Parsing & Encoding Analysis

### 6.1 Malformed Diff Parsing: Error-Handling Concern
- **Input Evaluated:** Truncated hunk header `@@ -invalid hunk @@` without standard unified diff range syntax.
- **Engine Handling in [`IncrementalDiffScanner.java`](../../src/main/java/com/sentinelpr/core/analysis/diff/IncrementalDiffScanner.java#L327-L338):**
  - Line 327: `Matcher matcher = HUNK_HEADER_PATTERN.matcher(line);`
  - When the hunk header regex fails to match, `matcher.find()` returns `false`.
  - The scanner skips the malformed hunk without throwing an unhandled exception (`inHunk` remains `false`).
- **Audit Assessment — Identified Defect / Concern:**
  > [!WARNING]
  > **Silent Recovery Design Concern:**
  > Silently recovering from malformed hunk headers without logging a warning or returning a parse error is an **error-handling deficiency, not proof of robust handling**.
  > If a diff file is corrupted or truncated by an upstream tool, SentinelPR will silently skip those lines. As a result, newly introduced vulnerabilities inside the unparsed hunks will be erroneously classified as `BASELINE_SUPPRESSED`, creating a **silent false negative risk**.
  > *Backlog Item:* The diff parser should emit an explicit diagnostic warning and/or return a non-zero parse-failure exit code when encountering corrupted hunks.

### 6.2 Character Encoding Investigation
- **Observed Behavior:** During initial test script execution, `SentinelCliRunner` threw `java.nio.charset.MalformedInputException: Input length = 1` when reading `case1-vulnerable.diff`.
- **Root Cause Analysis:**
  - The failure was caused by Windows PowerShell 5.1 redirection syntax (`git diff ... > file.diff`), which writes files encoded in **UTF-16 LE with a Byte Order Mark (BOM)** (bytes `FF FE`).
  - Java's `Files.readString(path)` defaults to standard **UTF-8**.
  - When diffs are generated via POSIX environments, standard Git CLI, or UTF-8 redirection (`[System.Text.UTF8Encoding]`), `Files.readString(path)` parses cleanly.
- **Audit Conclusion:**
  - This was an **artifact of the test harness environment**, not an engine defect.
  - Standard Git, GitHub Actions runners, and developer terminals produce UTF-8 unified diffs.
  - Broadening SentinelPR to support arbitrary encodings is **unnecessary**, though adding UTF-8 BOM tolerance (`\uFEFF`) is a minor convenience recommendation.

---

## 7. Audit 5 — Evidence Provenance & Pinned Metadata

All evaluation evidence has been cross-referenced with exact remote Git and GitHub REST API metadata:

| Context | Exact Target Identifier | Pinned Commit SHA / ID | Event / State | API Evidence & Timestamps |
| :--- | :--- | :--- | :--- | :--- |
| **Repo 1** | `darshanrathod04/Todo-Application` | `bb4b69a50ee814d00129fdbe2286eeaa048a078f` (Base) | Pinned Baseline | Verified via Git remote |
| **Repo 1 PR** | `darshanrathod04/Todo-Application` PR #1 | `b34cd057ab985bd2480145b8f38fa1bb68ae16a2` (Head) | PR `open` | [`pull/1`](https://github.com/darshanrathod04/Todo-Application/pull/1) |
| **CI Run** | `Todo-Application` Run `36766658788` | `b34cd057ab985bd2480145b8f38fa1bb68ae16a2` | Completed `success` | Workflow: `SentinelPR Security Gate` |
| **CI Run** | `Todo-Application` Run `36157469594` | `75bcb1f8bd6f5e67cc92922ecdfeee48c24238c5` | Completed `success` | Initial PR vulnerability introduction |
| **Comment** | PR #1 Sticky Comment | Issue Comment ID `5835224247` | Sticky Review | Created: `2026-09-25T15:46:01Z`<br>Updated: `2026-09-30T19:35:15Z` |
| **Repo 2** | `darshanrathod04/College-management-backemd` | `38a084e4fdc59bd7b732502bcf06738e1e05e26a` | Pinned Commit | Parent: `aa4fdcd` (Commit Diff) |
| **Repo 3 PR** | `darshanrathod04/sentinel-pr` PR #7 | `224b6f2ae7dce27050cd852e6b9e940889b4bb2f` (Head) | PR `closed` | [`pull/7`](https://github.com/darshanrathod04/sentinel-pr/pull/7) |
| **Repo 3 Run** | `sentinel-pr` Run `37021806427` | `224b6f2ae7dce27050cd852e6b9e940889b4bb2f` | Completed `success` | PR #7 Review Run |
| **Repo 3 PR** | `darshanrathod04/sentinel-pr` PR #6 | `f10596fc4d66668105ca5dc2b14bce40a019df08` (Head) | PR `closed` | [`pull/6`](https://github.com/darshanrathod04/sentinel-pr/pull/6) |

---

## 8. Summary of Confirmed Defects vs. Rejected Hypotheses

### Confirmed Defects & Design Concerns:
1. **`DEFECT-PHASE4B-001` (action.yml omits `--diff`):**
   - **Status:** **CONFIRMED DEFECT**
   - **Impact:** In CI runs, `action.yml` runs SentinelPR against the entire repository tree instead of changed PR hunks, blocking PRs on pre-existing repository debt.
   - **Action Item:** For `v1.2.0`, update `action.yml` to automatically generate `git diff ${{ github.event.pull_request.base.sha }}...${{ github.event.pull_request.head.sha }} > pr.diff` and pass `--diff pr.diff`.
2. **`CONCERN-PHASE4B-002` (Malformed diff silent skip):**
   - **Status:** **DESIGN CONCERN**
   - **Impact:** Silent skip of corrupted hunks risks suppressing genuine new vulnerabilities as baseline.
   - **Action Item:** Add diagnostic warning logging and strict parse error exit code.

### Hypotheses Rejected:
1. **Encoding Handling Defect in SentinelPR:**
   - **Status:** **REJECTED**
   - **Finding:** SentinelPR conforms to the standard UTF-8 contract for POSIX and Git diffs. The UTF-16 MalformedInputException was exclusively caused by Windows PowerShell 5.1 default redirection behavior during test artifact generation.
2. **Comment Multiplication / Spamming Defect:**
   - **Status:** **REJECTED**
   - **Finding:** GitHub API audit confirmed that multiple CI runs on `Todo-Application` PR #1 updated comment `5835224247` in place over a 5-day span (`2026-09-25` to `2026-09-30`), maintaining exactly 1 comment on the pull request thread.

---

## 9. Final Limitations & Operational Status Breakdown

### 9.1 Scope Boundaries
1. **Repository Codebase Preserved:** No production code in `src/main/`, composite action in `action.yml`, test suites in `src/test/`, benchmark fixtures, Maven configuration (`pom.xml`), schemas, or existing Phase 4A records were modified.
2. **Release Metadata:** Maintained strictly at `v1.1.4`.

### 9.2 Precise Status Breakdown Across Dimensions
Rather than claiming universal end-to-end execution across all dimensions, the exact operational verification status is broken down as follows:

- **Case 1 (Known Vulnerable PR Diff):** Historical GitHub API evidence inspected (`Todo-Application` PR #1) and local CLI execution reproduced on pinned checkout (`b34cd057ab98`). Scoped detection verified (`2 TP` on PR diff; `3 BASELINE_SUPPRESSED`). Metrics ($100.0\%$ precision and recall) are strictly scoped to this single PR diff and its two documented findings ($N = 1$), and cannot estimate product-wide accuracy.
- **Case 2 (Known Safe PR Diff):** Commit diff simulation executed locally via CLI on pinned checkout (`38a084e4fdc5`). Diff safety verified (`1 TN` on `ARCH-002`, `0` active findings).
- **Case 3 (Mixed PR Diff):** Historical GitHub PR inspected and local CLI execution reproduced on pinned checkout (`224b6f2ae7dc`). **Remains explicitly unverified individually**: aggregate CLI execution confirmed (271 diff findings, 346 baseline suppressed), but individual finding ground truth across 30 synthetic fixture files was not independently audited. Zero precision/recall claimed.
- **Case 4 (No-op Non-Java PR Diff):** Historical GitHub PR inspected and local CLI execution reproduced on pinned checkout (`f10596fc4d66`). Verified that diff filter yields 0 active PR findings when no Java files change. Does not count as a detection TN.
- **Case 5 (Boundary & Malformed Inputs):** Local CLI execution verified for missing directories (5A, exit code 3) and zero Java files (5B, exit code 0). For malformed diff headers (5C), silent skipping was verified and identified as an error-handling concern (`CONCERN-PHASE4B-002`), not robust handling.
- **Case 6 (Sticky Comment Idempotency):** Historical GitHub REST API comment metadata inspected (Comment `5835224247` updated in place over a 5-day span) and unit test suite verified (17/17 tests pass across comment services).
- **Case 7 (SARIF Export):** Local CLI `--sarif` artifact generated and schema inspected. Verified OASIS SARIF v2.1.0 JSON output.
- **Case 8 (CI Failure & Permission Bounds):** Local CLI execution verified without credentials (exit code 2) and without required arguments (exit code 3).
- **Action Integration Contract (`testActionDiffContractDistinction`):** **NOT IMPLEMENTED / NOT EXECUTED.** This Java test is an unexecuted design specification proposed for the v1.2.0 backlog. It was not added to `src/test/` and was not run via Maven. Defect `DEFECT-PHASE4B-001` was grounded in the inspected `action.yml` invocation and verified via local CLI reproduction (`audit2_diff_reproduction.ps1`), which remains distinct from historical GitHub Action execution.
- **Remediation Build Verification:** Patched-source AST validity and rule-rescan silence verified by engine; compilation verified externally via `javac` and `mvn compile`. External test suite execution (`mvn test`) was **NOT_TESTED BY ENGINE**.

### 9.3 Next Steps
Present this audited plan and revised report for maintainer review. Upon approval, stage and commit only `phase4/reports/PHASE-4B-PLAN.md`.
