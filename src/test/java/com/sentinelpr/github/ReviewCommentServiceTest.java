package com.sentinelpr.github;

import com.sentinelpr.cli.SentinelCliRunner;
import com.sentinelpr.core.governance.policy.PolicyEvaluationResult;
import com.sentinelpr.core.model.ReviewReport;
import com.sentinelpr.core.model.SecurityFinding;
import com.sentinelpr.core.model.SecurityRule;
import com.sentinelpr.core.model.Severity;
import com.sentinelpr.core.model.UnifiedDiffPatch;
import com.sentinelpr.github.model.GitHubComment;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * <b>ReviewCommentServiceTest</b>
 *
 * <p>Unit and integration tests for {@link ReviewCommentService} verifying markdown generation
 * against the SentinelPR v1.1.0 specification template and sticky comment posting/updating flows.</p>
 */
class ReviewCommentServiceTest {

    private GitHubApiClient mockApiClient;
    private StickyCommentFinder stickyFinder;
    private ReviewCommentService reviewCommentService;

    private static final String REPO = "darshanrathod04/sentinel-pr";
    private static final int PR_NUMBER = 12;

    @BeforeEach
    void setUp() {
        mockApiClient = mock(GitHubApiClient.class);
        stickyFinder = new StickyCommentFinder();
        reviewCommentService = new ReviewCommentService(mockApiClient, stickyFinder);
    }

    @Test
    @DisplayName("buildCommentMarkdown synthesizes markdown conforming exactly to template for BLOCKED status")
    void testBuildCommentMarkdownBlocked() {
        SecurityFinding finding1 = new SecurityFinding(
                "FND-001",
                SecurityRule.FAIL_OPEN_SECURITY,
                Severity.CRITICAL,
                "src/main/java/VulnerableService.java",
                "VulnerableService",
                "authenticate",
                36,
                39,
                "catch (Exception e) { return true; }",
                "Fail-open catch block grants unauthorized access",
                "Security exception",
                "Return false upon exception",
                0.98
        );

        SecurityFinding finding2 = new SecurityFinding(
                "FND-002",
                SecurityRule.SQL_INJECTION,
                Severity.HIGH,
                "src/main/java/UserService.java",
                "UserService",
                "findUser",
                52,
                54,
                "stmt.executeQuery(query)",
                "SQL Injection vulnerability",
                "Tainted input reaches executeQuery sink",
                "Use PreparedStatement",
                0.95
        );

        UnifiedDiffPatch patch = new UnifiedDiffPatch(
                "FND-001",
                "SEC-001-FAIL-OPEN",
                "src/main/java/VulnerableService.java",
                "--- a/src/main/java/VulnerableService.java\n+++ b/src/main/java/VulnerableService.java\n@@ -36,4 +36,4 @@\n- catch (Exception e) { return true; }\n+ catch (Exception e) { return false; }",
                "package com.sentinelpr;\n",
                UnifiedDiffPatch.Status.SUCCESS,
                true,
                true,
                "Verified patch"
        );

        ReviewReport report = new ReviewReport(
                "REV-123",
                Instant.now(),
                "src/main/java",
                2,
                2,
                "FAILED",
                false,
                "Audit completed with findings",
                List.of(finding1, finding2),
                Collections.emptyList(),
                List.of(patch)
        );

        PolicyEvaluationResult policy = PolicyEvaluationResult.breached(
                "StrictEnterprisePolicy",
                List.of("Critical finding threshold exceeded: 1 > 0"),
                1,
                1,
                0,
                0,
                "Critical finding threshold exceeded: 1 > 0"
        );

        String markdown = reviewCommentService.buildCommentMarkdown(report, policy);

        // 1. Verify sticky marker
        assertTrue(markdown.startsWith("<!-- sentinel-pr-review -->\n\n"),
                "Markdown must begin with the exact sticky marker");

        // 2. Verify title and Status: BLOCKED
        assertTrue(markdown.contains("# 🛡 SentinelPR Security Review\n\nStatus: BLOCKED\n\n"),
                "Markdown must have the review title and Status: BLOCKED");

        // 3. Verify Findings section with table headers and rows
        assertTrue(markdown.contains("## Findings\n\n"), "Must contain Findings header");
        assertTrue(markdown.contains("| Severity | Rule | File |\n|----------|------|------|\n"),
                "Must contain exact findings table headers");
        assertTrue(markdown.contains("| CRITICAL | SEC-001-FAIL-OPEN | src/main/java/VulnerableService.java:36 |\n"),
                "Must list CRITICAL finding row");
        assertTrue(markdown.contains("| HIGH | SEC-005-SQL-INJECTION | src/main/java/UserService.java:52 |\n"),
                "Must list HIGH finding row");

        // 4. Verify Suggested Patch section with ```diff
        assertTrue(markdown.contains("## Suggested Patch\n\n```diff\n"), "Must contain Suggested Patch diff block");
        assertTrue(markdown.contains("--- a/src/main/java/VulnerableService.java\n+++ b/src/main/java/VulnerableService.java"),
                "Diff block must contain the synthesized unified diff from report.getPatches()");
        assertTrue(markdown.contains("```\n\n"), "Diff block must be properly closed");

        // 5. Verify footer
        assertTrue(markdown.endsWith("---\nPowered by SentinelPR + Shree AI OS\n"),
                "Markdown must end with the exact footer");
    }

    @Test
    @DisplayName("buildCommentMarkdown synthesizes markdown for clean PASSED status")
    void testBuildCommentMarkdownPassed() {
        ReviewReport cleanReport = new ReviewReport(
                "REV-CLEAN",
                Instant.now(),
                "src/main/java",
                5,
                0,
                "SUCCESS",
                false,
                "Clean audit",
                Collections.emptyList(),
                Collections.emptyList(),
                Collections.emptyList()
        );

        PolicyEvaluationResult passedPolicy = PolicyEvaluationResult.passed(
                "StrictPolicy", 0, 0, 0, "All policy checks passed."
        );

        String markdown = reviewCommentService.buildCommentMarkdown(cleanReport, passedPolicy);

        assertTrue(markdown.startsWith("<!-- sentinel-pr-review -->\n\n"));
        assertTrue(markdown.contains("Status: PASSED\n\n"));
        assertTrue(markdown.contains("| Severity | Rule | File |\n|----------|------|------|\n"));
        assertTrue(markdown.contains("Clean (0 active findings)"));
        assertTrue(markdown.contains("```diff\n# No patch required\n```\n\n"));
        assertTrue(markdown.endsWith("---\nPowered by SentinelPR + Shree AI OS\n"));
    }

    @Test
    @DisplayName("postOrUpdateComment creates new comment when no sticky comment exists")
    void testPostOrUpdateCommentCreatesWhenNotFound() {
        ReviewReport cleanReport = new ReviewReport(
                "REV-001", Instant.now(), "src", 1, 0, "SUCCESS", false, "Clean",
                Collections.emptyList(), Collections.emptyList(), Collections.emptyList()
        );

        // Mock existing comments: only non-sticky comments exist
        GitHubComment otherComment = new GitHubComment(501L, "Standard pull request comment.");
        when(mockApiClient.getComments(REPO, PR_NUMBER)).thenReturn(List.of(otherComment));

        GitHubComment createdComment = new GitHubComment(502L, "Created review comment");
        when(mockApiClient.createComment(eq(REPO), eq(PR_NUMBER), anyString())).thenReturn(createdComment);

        GitHubComment result = reviewCommentService.postOrUpdateComment(REPO, PR_NUMBER, cleanReport, null);

        assertNotNull(result);
        assertEquals(502L, result.getId());

        // Verify createComment was called with markdown containing sticky marker
        ArgumentCaptor<String> bodyCaptor = ArgumentCaptor.forClass(String.class);
        verify(mockApiClient).createComment(eq(REPO), eq(PR_NUMBER), bodyCaptor.capture());
        assertTrue(bodyCaptor.getValue().contains("<!-- sentinel-pr-review -->"));

        // Verify updateComment was NEVER called
        verify(mockApiClient, never()).updateComment(anyString(), anyLong(), anyString());
    }

    @Test
    @DisplayName("postOrUpdateComment updates existing comment when sticky comment exists")
    void testPostOrUpdateCommentUpdatesWhenFound() {
        ReviewReport cleanReport = new ReviewReport(
                "REV-001", Instant.now(), "src", 1, 0, "SUCCESS", false, "Clean",
                Collections.emptyList(), Collections.emptyList(), Collections.emptyList()
        );

        // Mock existing comments: sticky comment exists with ID 888L
        GitHubComment stickyComment = new GitHubComment(888L, "<!-- sentinel-pr-review -->\nPrior review");
        when(mockApiClient.getComments(REPO, PR_NUMBER)).thenReturn(List.of(stickyComment));

        GitHubComment result = reviewCommentService.postOrUpdateComment(REPO, PR_NUMBER, cleanReport, null);

        assertNotNull(result);
        assertEquals(888L, result.getId());

        // Verify updateComment was called with comment ID 888L and updated markdown
        ArgumentCaptor<String> bodyCaptor = ArgumentCaptor.forClass(String.class);
        verify(mockApiClient).updateComment(eq(REPO), eq(888L), bodyCaptor.capture());
        assertTrue(bodyCaptor.getValue().contains("Status: PASSED"));

        // Verify createComment was NEVER called
        verify(mockApiClient, never()).createComment(anyString(), anyInt(), anyString());
    }

    @Test
    @DisplayName("CLI Integration: SentinelCliRunner with --post-comment triggers review comment workflow")
    void testCliRunnerWithPostCommentFlag() throws IOException {
        Path targetPath = Path.of("src/test/java/com/sentinelpr/fixture/VulnerableService.java");

        // Mock getComments and createComment
        when(mockApiClient.getComments(REPO, PR_NUMBER)).thenReturn(Collections.emptyList());
        when(mockApiClient.createComment(eq(REPO), eq(PR_NUMBER), anyString()))
                .thenReturn(new GitHubComment(999L, "Created comment"));

        // Instantiate SentinelCliRunner with our mocked reviewCommentService
        SentinelCliRunner runner = new SentinelCliRunner(
                new com.sentinelpr.core.service.SentinelAuditOrchestrator(
                        new com.sentinelpr.core.service.CodeInspectionService(com.sentinelpr.client.SentinelClient.getInstance()),
                        new com.sentinelpr.core.service.RuleEvaluationService(com.sentinelpr.client.SentinelClient.getInstance()),
                        new com.sentinelpr.core.service.AutomatedPatchService(com.sentinelpr.client.SentinelClient.getInstance()),
                        new com.sentinelpr.core.service.ReviewSessionMemory(com.sentinelpr.client.SentinelClient.getInstance())
                ),
                new com.sentinelpr.core.export.sarif.SarifReportGenerator(),
                new com.sentinelpr.core.export.github.PrReviewCommentBuilder(),
                new com.sentinelpr.core.governance.baseline.BaselineManager(),
                new com.sentinelpr.core.governance.policy.PolicyEngine(),
                new com.sentinelpr.core.governance.audit.AuditTrailLogger(),
                com.sentinelpr.client.SentinelClient.getInstance().memoryFacade(),
                reviewCommentService
        );

        String[] cliArgs = new String[]{
                targetPath.toString(),
                "--repo", REPO,
                "--pr", String.valueOf(PR_NUMBER),
                "--post-comment",
                "-f", "github"
        };

        int exitCode = runner.execute(cliArgs);

        assertEquals(0, exitCode, "CLI execution should succeed with exit code 0");

        // Verify that reviewCommentService posted a comment to GitHub
        verify(mockApiClient).createComment(eq(REPO), eq(PR_NUMBER), anyString());
    }
}
