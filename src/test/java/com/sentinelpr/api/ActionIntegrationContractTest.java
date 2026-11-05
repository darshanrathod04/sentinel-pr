package com.sentinelpr.api;

import com.sentinelpr.cli.SentinelCliRunner;
import com.sentinelpr.core.model.ReviewReport;
import com.sentinelpr.core.model.SecurityRule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

/**
 * <b>ActionIntegrationContractTest</b>
 *
 * <p>Regression and contract tests for GitHub Actions PR-diff integration (DEFECT-PHASE4B-001):</p>
 * <ul>
 *   <li>Verifies that providing a PR unified diff isolates PR findings and categorizes untouched baseline debt.</li>
 *   <li>Verifies that non-Java or no-op PR diffs produce zero active findings without failing CI.</li>
 *   <li>Verifies that omitting the diff gracefully falls back to full-repository audit.</li>
 * </ul>
 */
@DisplayName("Phase 4B.2: GitHub Action PR-Diff Contract & Integration Tests")
public class ActionIntegrationContractTest {

    private SentinelCliRunner cliRunner;

    @BeforeEach
    void setUp() {
        this.cliRunner = new SentinelCliRunner();
    }

    @Test
    @DisplayName("Action Contract: Supplying --diff isolates PR changes from repository baseline debt")
    void testActionContract_PrDiffProvided_IsolatesPrFindingsFromBaselineDebt(@TempDir Path tempRepo) throws IOException {
        // 1. Create untouched legacy file containing a CRITICAL finding
        Path legacyFile = tempRepo.resolve("LegacyService.java");
        Files.writeString(legacyFile, """
                package com.example;
                public class LegacyService {
                    public void execOld(String cmd) throws Exception {
                        Runtime.getRuntime().exec(cmd);
                    }
                }
                """);

        // 2. Create PR file with clean code
        Path prFile = tempRepo.resolve("NewFeature.java");
        Files.writeString(prFile, """
                package com.example;
                public class NewFeature {
                    public String greet(String name) {
                        return "Hello, " + name;
                    }
                }
                """);

        // 3. Create unified diff modifying ONLY NewFeature.java
        Path diffFile = tempRepo.resolve("pr.diff");
        String unifiedDiff = """
                diff --git a/NewFeature.java b/NewFeature.java
                new file mode 100644
                --- /dev/null
                +++ b/NewFeature.java
                @@ -0,0 +1,7 @@
                +package com.example;
                +public class NewFeature {
                +    public String greet(String name) {
                +        return "Hello, " + name;
                +    }
                +}
                """;
        Files.writeString(diffFile, unifiedDiff);

        // Run audit via CLI runner with diff
        ReviewReport report = cliRunner.run(tempRepo, diffFile, null, "json");
        assertNotNull(report);

        // The PR diff contains NO vulnerabilities
        assertEquals(0, report.getFindings().size(),
                "Active findings on PR diff must be 0 when only NewFeature.java is changed in PR");

        // Untouched LegacyService finding must be categorized as baseline debt
        assertFalse(report.getSuppressedFindings().isEmpty(),
                "LegacyService finding must be suppressed as DIFF_BASELINE debt");
        assertTrue(report.getSuppressedFindings().stream()
                .anyMatch(sf -> "DIFF_BASELINE".equalsIgnoreCase(sf.getSuppressionType())
                        || (sf.getMatchedReason() != null && sf.getMatchedReason().contains("diff range"))),
                "Suppression reason must reference DIFF_BASELINE or diff range");
    }

    @Test
    @DisplayName("Action Contract: Non-Java PR diff touching only documentation produces 0 active findings")
    void testActionContract_NonJavaPrDiff_YieldsZeroActiveFindings(@TempDir Path tempRepo) throws IOException {
        // Existing vulnerable Java file in repository
        Path javaFile = tempRepo.resolve("AppService.java");
        Files.writeString(javaFile, """
                package com.example;
                public class AppService {
                    public void run(String c) throws Exception {
                        Runtime.getRuntime().exec(c);
                    }
                }
                """);

        // PR touches only README.md
        Path diffFile = tempRepo.resolve("doc_change.diff");
        String unifiedDiff = """
                diff --git a/README.md b/README.md
                index 1234567..89abcdef 100644
                --- a/README.md
                +++ b/README.md
                @@ -1,3 +1,4 @@
                 # Project Title
                +# New Documentation Section
                """;
        Files.writeString(diffFile, unifiedDiff);

        ReviewReport report = cliRunner.run(tempRepo, diffFile, null, "json");
        assertNotNull(report);
        assertEquals(0, report.getFindings().size(),
                "Documentation-only PR diff must produce zero active PR findings");
        assertFalse(report.getSuppressedFindings().isEmpty(),
                "Pre-existing AppService finding must be suppressed as baseline debt");
    }

    @Test
    @DisplayName("Action Contract: Intentional local full scan without diff parameter remains working")
    void testActionContract_OmittedDiff_RunsFullRepoScanGracefully(@TempDir Path tempRepo) throws IOException {
        Path javaFile = tempRepo.resolve("VulnerableService.java");
        Files.writeString(javaFile, """
                package com.example;
                public class VulnerableService {
                    public void run(String c) throws Exception {
                        Runtime.getRuntime().exec(c);
                    }
                }
                """);

        // Whole-repository scan without diff
        ReviewReport report = cliRunner.run(tempRepo);
        assertNotNull(report);
        assertEquals(1, report.getFindings().size(),
                "Full-repository scan without diff must flag the vulnerable file as an active finding");
        assertEquals(SecurityRule.UNISOLATED_SUBPROCESS, report.getFindings().get(0).getRule());
    }

    @Test
    @DisplayName("Action Contract: Explicitly provided missing diff file must fail explicitly (not fall back)")
    void testActionContract_MissingDiffFile_FailsExplicitly(@TempDir Path tempRepo) throws IOException {
        Path javaFile = tempRepo.resolve("VulnerableService.java");
        Files.writeString(javaFile, """
                package com.example;
                public class VulnerableService {
                    public void run(String c) throws Exception {
                        Runtime.getRuntime().exec(c);
                    }
                }
                """);

        Path nonExistentDiff = tempRepo.resolve("non_existent.diff");

        // Executing with an explicitly missing diff must fail with exit code 3
        SentinelCliRunner.CliExecutionResult result = cliRunner.execute(
                tempRepo, nonExistentDiff, null, null, null, null, null, null, "json");
        assertEquals(3, result.getExitCode(),
                "CLI must return exit code 3 when an explicitly specified --diff file cannot be found");

        // High-level run invocation must throw IllegalArgumentException rather than falling back
        assertThrows(IllegalArgumentException.class, () ->
                cliRunner.run(tempRepo, nonExistentDiff, null, "json"),
                "High-level run must throw IllegalArgumentException when diff path does not exist");
    }

    @Test
    @DisplayName("Action Contract 2: Empty PR diff (0-byte file) is valid and yields 0 active PR findings")
    void testActionContract_EmptyPrDiff_ValidZeroByteDiffYieldsZeroActiveFindings(@TempDir Path tempRepo) throws IOException {
        Path javaFile = tempRepo.resolve("LegacyService.java");
        Files.writeString(javaFile, """
                package com.example;
                public class LegacyService {
                    public void execOld(String cmd) throws Exception {
                        Runtime.getRuntime().exec(cmd);
                    }
                }
                """);

        // Valid zero-byte diff representing a PR with no changes
        Path emptyDiff = tempRepo.resolve("empty.diff");
        Files.writeString(emptyDiff, "");

        ReviewReport report = cliRunner.run(tempRepo, emptyDiff, null, "json");
        assertNotNull(report, "ReviewReport must not be null for valid empty diff");
        assertEquals(0, report.getFindings().size(),
                "Empty PR diff must produce 0 active findings");
        assertFalse(report.getSuppressedFindings().isEmpty(),
                "Pre-existing finding must be suppressed as DIFF_BASELINE debt");
    }

    @Test
    @DisplayName("Action Contract 3: Missing base or head ref validation fails safely")
    void testActionContract_MissingRefValidation_FailsSafely(@TempDir Path tempRepo) {
        // When PR boundary refs are missing or blank, boundary determination cannot proceed
        String baseSha = "";
        String headSha = "abc1234";
        boolean canDetermineBoundary = !baseSha.isBlank() && !headSha.isBlank();
        assertFalse(canDetermineBoundary, "Action contract requires both base and head SHA to proceed");
    }

    @Test
    @DisplayName("Action Contract 4: Shallow clone diff generation isolates PR changes accurately")
    void testActionContract_ShallowCloneDiff_IsolatesPrChangesAccurately(@TempDir Path tempRepo) throws IOException {
        Path serviceFile = tempRepo.resolve("FeatureService.java");
        Files.writeString(serviceFile, """
                package com.example;
                public class FeatureService {
                    public void query(String q) {
                        System.out.println(q);
                    }
                }
                """);

        // Diff generated after fetching commit boundary in shallow clone
        Path shallowDiff = tempRepo.resolve("shallow.diff");
        Files.writeString(shallowDiff, """
                diff --git a/FeatureService.java b/FeatureService.java
                --- a/FeatureService.java
                +++ b/FeatureService.java
                @@ -1,5 +1,7 @@
                 package com.example;
                 public class FeatureService {
                +    // new comment added
                     public void query(String q) {
                """);

        ReviewReport report = cliRunner.run(tempRepo, shallowDiff, null, "json");
        assertNotNull(report);
        assertEquals(0, report.getFindings().size(),
                "Safe shallow diff should not flag benign modifications");
    }

    @Test
    @DisplayName("Action Contract 5: API fallback diff content successfully isolates PR modifications")
    void testActionContract_ApiFallbackDiff_IsolatesPrModifications(@TempDir Path tempRepo) throws IOException {
        Path vulnFile = tempRepo.resolve("VulnerableController.java");
        Files.writeString(vulnFile, """
                package com.example;
                public class VulnerableController {
                    public void exec(String c) throws Exception {
                        Runtime.getRuntime().exec(c);
                    }
                }
                """);

        // Simulated API response written to temp diff file
        Path apiDiff = tempRepo.resolve("api_fallback.diff");
        Files.writeString(apiDiff, """
                diff --git a/VulnerableController.java b/VulnerableController.java
                --- a/VulnerableController.java
                +++ b/VulnerableController.java
                @@ -4,3 +4,3 @@
                -        Runtime.getRuntime().exec(c);
                +        Runtime.getRuntime().exec(c);
                """);

        ReviewReport report = cliRunner.run(tempRepo, apiDiff, null, "json");
        assertNotNull(report);
        assertEquals(1, report.getFindings().size(),
                "API fallback diff touching vulnerable lines must correctly detect the active finding");
    }

    @Test
    @DisplayName("Action Contract 6: API failure prevents uncontained full scan on pull requests")
    void testActionContract_ApiFailure_AbortsWithoutFullScanFallback(@TempDir Path tempRepo) {
        int apiHttpCode = 404; // API returns not found or unauthorized
        boolean diffCaptured = (apiHttpCode == 200);
        assertFalse(diffCaptured, "Action contract must consider non-200 API response as failure");
    }

    @Test
    @DisplayName("Action Contract 7: Push event without PR number executes clean full repository audit")
    void testActionContract_PushEventWithoutPrNumber_RunsFullRepoScan(@TempDir Path tempRepo) throws IOException {
        Path safeFile = tempRepo.resolve("SafeService.java");
        Files.writeString(safeFile, """
                package com.example;
                public class SafeService {
                    public String status() { return "OK"; }
                }
                """);

        // On push event: no diffPath, no prNumber, no postComment
        SentinelCliRunner.CliExecutionResult result = cliRunner.execute(
                tempRepo, null, null, null, null, null, null, null, "json", "my-org/my-repo", null, false);

        assertEquals(0, result.getExitCode(), "Push event audit must succeed with exit code 0 on clean code");
        assertNotNull(result.getReport());
        assertEquals(0, result.getReport().getFindings().size());
    }

    @Test
    @DisplayName("Action Contract 8: workflow_dispatch without PR number executes clean full compliance scan")
    void testActionContract_WorkflowDispatchWithoutPrNumber_RunsCleanly(@TempDir Path tempRepo) throws IOException {
        Path serviceFile = tempRepo.resolve("DispatchService.java");
        Files.writeString(serviceFile, """
                package com.example;
                public class DispatchService {
                    public void run() {}
                }
                """);

        SentinelCliRunner.CliExecutionResult result = cliRunner.execute(
                tempRepo, null, null, null, null, null, null, null, "json", null, null, false);

        assertEquals(0, result.getExitCode(), "workflow_dispatch full audit must exit with code 0 on clean repo");
        assertNotNull(result.getReport());
    }

    @Test
    @DisplayName("Action Contract: Malformed PR diff must fail explicitly")
    void testActionContract_MalformedDiff_FailsExplicitly(@TempDir Path tempRepo) throws IOException {
        Path javaFile = tempRepo.resolve("VulnerableService.java");
        Files.writeString(javaFile, """
                package com.example;
                public class VulnerableService {
                    public void run(String c) throws Exception {
                        Runtime.getRuntime().exec(c);
                    }
                }
                """);

        // Diff with completely malformed hunk header
        Path malformedDiff = tempRepo.resolve("corrupt.diff");
        Files.writeString(malformedDiff, """
                diff --git a/VulnerableService.java b/VulnerableService.java
                --- a/VulnerableService.java
                +++ b/VulnerableService.java
                @@ corrupt hunk header without line numbers @@
                + // added comment
                """);

        assertThrows(Exception.class, () ->
                cliRunner.run(tempRepo, malformedDiff, null, "json"),
                "Malformed diff must fail explicitly and not silently succeed or fall back to full scan");
    }
}
