package com.sentinelpr;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sentinelpr.api.SentinelReviewController;
import com.sentinelpr.api.dto.ReviewFileRequest;
import com.sentinelpr.cli.SentinelCliRunner;
import com.sentinelpr.client.SentinelClient;
import com.sentinelpr.core.analysis.diff.IncrementalDiffScanner;
import com.sentinelpr.core.analysis.diff.IncrementalDiffScanner.FileDiff;
import com.sentinelpr.core.export.github.PrReviewCommentBuilder;
import com.sentinelpr.core.export.github.PrReviewCommentBuilder.GitHubInlineComment;
import com.sentinelpr.core.export.github.PrReviewCommentBuilder.GitHubReviewPayload;
import com.sentinelpr.core.export.sarif.SarifReportGenerator;
import com.sentinelpr.core.model.ReviewReport;
import com.sentinelpr.core.model.SecurityFinding;
import com.sentinelpr.core.model.SecurityRule;
import com.sentinelpr.core.model.SuppressedFinding;
import com.sentinelpr.core.service.AutomatedPatchService;
import com.sentinelpr.core.service.CodeInspectionService;
import com.sentinelpr.core.service.ReviewSessionMemory;
import com.sentinelpr.core.service.RuleEvaluationService;
import com.sentinelpr.core.service.SentinelAuditOrchestrator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.http.ResponseEntity;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * <b>SentinelPrP2WorkflowVerificationTest</b>
 *
 * <p>Integration test suite validating P2 enterprise developer workflow capabilities:</p>
 * <ol>
 *   <li>Incremental Git Diff Parser & Range Filter (IncrementalDiffScanner)</li>
 *   <li>OASIS SARIF v2.1.0 Exporter (SarifReportGenerator)</li>
 *   <li>GitHub PR Review Comment & Suggestion Synthesis (PrReviewCommentBuilder)</li>
 *   <li>CLI Runner Workflow Flags (--diff, --sarif, --format)</li>
 *   <li>REST API Workflow Endpoints (/review, /review/sarif, /review/github)</li>
 * </ol>
 */
class SentinelPrP2WorkflowVerificationTest {

    private SentinelClient client;
    private SentinelAuditOrchestrator orchestrator;
    private IncrementalDiffScanner diffScanner;
    private SarifReportGenerator sarifGenerator;
    private PrReviewCommentBuilder reviewCommentBuilder;
    private SentinelReviewController reviewController;
    private ObjectMapper objectMapper;

    private Path fixtureFile;
    private Path diffFile;

    @BeforeEach
    void setUp() {
        client = SentinelClient.bootstrap("local");
        CodeInspectionService inspectionService = new CodeInspectionService(client);
        RuleEvaluationService evaluationService = new RuleEvaluationService(client);
        AutomatedPatchService patchService = new AutomatedPatchService(client);
        ReviewSessionMemory sessionMemory = new ReviewSessionMemory(client);

        orchestrator = new SentinelAuditOrchestrator(
                inspectionService,
                evaluationService,
                patchService,
                sessionMemory
        );
        orchestrator.getSessionMemory().clearCache();

        diffScanner = orchestrator.getDiffScanner();
        sarifGenerator = new SarifReportGenerator();
        reviewCommentBuilder = new PrReviewCommentBuilder();
        reviewController = new SentinelReviewController(orchestrator, sarifGenerator, reviewCommentBuilder);
        objectMapper = new ObjectMapper();

        fixtureFile = Path.of("src/test/java/com/sentinelpr/fixture/VulnerableService.java");
        diffFile = Path.of("src/test/resources/SampleIncrementalDiff.patch");

        assertTrue(Files.exists(fixtureFile), "Fixture file must exist: " + fixtureFile);
        assertTrue(Files.exists(diffFile), "Diff patch fixture must exist: " + diffFile);
    }

    @Test
    @DisplayName("P2-1: IncrementalDiffScanner extracts hunks and filters findings to PR range")
    void testIncrementalDiffScannerFiltersFindings() throws IOException {
        String patchContent = Files.readString(diffFile);
        Map<String, FileDiff> parsedDiffs = diffScanner.parse(patchContent);

        assertFalse(parsedDiffs.isEmpty(), "Diff scanner should parse file diffs");
        FileDiff fileDiff = diffScanner.findMatchingFileDiff(fixtureFile.toString(), parsedDiffs);
        assertNotNull(fileDiff, "Should find matching file diff for VulnerableService.java");

        assertFalse(fileDiff.getHunks().isEmpty(), "File diff should contain at least one hunk");
        IncrementalDiffScanner.DiffHunk hunk = fileDiff.getHunks().get(0);
        assertEquals(30, hunk.getOldStart());
        assertEquals(30, hunk.getNewStart());

        // Fail-open catch block at lines 36-39 touches lines 30-41 of hunk
        assertTrue(hunk.touchesRange(36, 39), "Lines 36-39 should touch hunk interval");

        // Unclosed stream at lines 20-25 does NOT touch hunk
        assertFalse(hunk.touchesRange(20, 25), "Lines 20-25 should NOT touch hunk interval");

        // Volatile compound op at lines 45-47 does NOT touch hunk
        assertFalse(hunk.touchesRange(45, 47), "Lines 45-47 should NOT touch hunk interval");

        // Execute incremental audit via orchestrator
        ReviewReport report = orchestrator.auditPathWithDiff(fixtureFile, patchContent);

        assertNotNull(report, "Review report must not be null");
        assertEquals(1, report.getVulnerabilityCount(), "Only 1 finding touches PR diff range");

        SecurityFinding activeFinding = report.getFindings().get(0);
        assertEquals(SecurityRule.FAIL_OPEN_SECURITY, activeFinding.getRule(),
                "Active finding touching diff must be SEC-001 Fail-Open");

        // Verify baseline suppressed findings
        assertFalse(report.getSuppressedFindings().isEmpty(), "Non-diff findings must be categorized as baseline");
        boolean hasBaselineStream = false;
        boolean hasBaselineVolatile = false;

        for (SuppressedFinding sf : report.getSuppressedFindings()) {
            assertEquals("DIFF_BASELINE", sf.getSuppressionType(),
                    "Suppression type must be DIFF_BASELINE");
            assertEquals("Baseline finding outside incremental PR diff range", sf.getMatchedReason());

            if (sf.getFinding().getRule() == SecurityRule.UNCLOSED_IO_STREAM) {
                hasBaselineStream = true;
            }
            if (sf.getFinding().getRule() == SecurityRule.VOLATILE_COMPOUND_OP) {
                hasBaselineVolatile = true;
            }
        }

        assertTrue(hasBaselineStream, "Unclosed stream outside hunk must be baseline suppressed");
        assertTrue(hasBaselineVolatile, "Volatile compound op outside hunk must be baseline suppressed");
    }

    @Test
    @DisplayName("P2-2: SarifReportGenerator produces schema-compliant OASIS SARIF v2.1.0 JSON")
    void testSarifReportGeneratorSchemaCompliance(@TempDir Path tempDir) throws Exception {
        // Run full audit on fixture
        ReviewReport report = orchestrator.auditPath(fixtureFile);
        assertFalse(report.getFindings().isEmpty(), "Baseline audit should find vulnerabilities");

        // Generate SARIF JSON
        String sarifJson = sarifGenerator.generateSarifJson(report);
        assertNotNull(sarifJson);
        assertFalse(sarifJson.isBlank());

        // Validate SARIF JSON structure
        JsonNode root = objectMapper.readTree(sarifJson);
        assertEquals("https://json.schemastore.org/sarif-2.1.0.json", root.path("$schema").asText());
        assertEquals("2.1.0", root.path("version").asText());

        JsonNode runs = root.path("runs");
        assertTrue(runs.isArray() && runs.size() > 0, "SARIF runs array must contain at least one run");

        JsonNode run = runs.get(0);
        JsonNode tool = run.path("tool").path("driver");
        assertEquals("SentinelPR", tool.path("name").asText());
        assertEquals("1.0.0", tool.path("version").asText());

        // Verify rules catalog
        JsonNode rules = tool.path("rules");
        assertTrue(rules.isArray(), "Driver rules must be an array");
        assertEquals(SecurityRule.values().length, rules.size(), "Rules array must catalog all 10 rules");

        // Verify results
        JsonNode results = run.path("results");
        assertTrue(results.isArray(), "Results must be an array");
        assertEquals(report.getFindings().size(), results.size(), "Results count must match findings count");

        JsonNode firstResult = results.get(0);
        assertFalse(firstResult.path("ruleId").asText().isBlank());
        assertEquals("error", firstResult.path("level").asText());

        JsonNode locations = firstResult.path("locations");
        assertTrue(locations.isArray() && locations.size() > 0);
        JsonNode physLoc = locations.get(0).path("physicalLocation");
        assertEquals("%SRCROOT%", physLoc.path("artifactLocation").path("uriBaseId").asText());
        assertTrue(physLoc.path("region").path("startLine").asInt() > 0);

        // Test export to file
        Path sarifOutput = tempDir.resolve("sentinel-report.sarif");
        sarifGenerator.exportToFile(report, sarifOutput);
        assertTrue(Files.exists(sarifOutput));
        assertTrue(Files.size(sarifOutput) > 0);
    }

    @Test
    @DisplayName("P2-3: PrReviewCommentBuilder synthesizes GitHub review payload with suggestions")
    void testGitHubPrCommentSynthesis() throws Exception {
        ReviewReport report = orchestrator.auditPath(fixtureFile);
        assertFalse(report.getFindings().isEmpty());

        GitHubReviewPayload payload = reviewCommentBuilder.buildReviewPayload(report, "sha-abc-123");
        assertNotNull(payload);
        assertEquals("sha-abc-123", payload.getCommitId());
        assertEquals("REQUEST_CHANGES", payload.getEvent(),
                "Event must be REQUEST_CHANGES when critical/high defects are present");

        // Review Body Markdown assertions
        String body = payload.getBody();
        assertTrue(body.contains("## 🛡️ SentinelPR Code & Security Review"), "Body must contain header");
        assertTrue(body.contains("Executive Audit Metrics"), "Body must contain audit metrics table");
        assertTrue(body.contains("Identified Vulnerabilities"), "Body must contain identified vulnerabilities table");
        assertTrue(body.contains(SecurityRule.FAIL_OPEN_SECURITY.getRuleId()));

        // Inline Comments assertions
        List<GitHubInlineComment> comments = payload.getComments();
        assertEquals(report.getFindings().size(), comments.size(),
                "Inline comments count must equal findings count");

        GitHubInlineComment firstComment = comments.get(0);
        assertEquals("RIGHT", firstComment.getSide());
        assertTrue(firstComment.getLine() > 0);
        assertTrue(firstComment.getPath().contains("VulnerableService.java"));

        String commentBody = firstComment.getBody();
        assertTrue(commentBody.contains("> [!") || commentBody.contains("Causal Rationale:"),
                "Comment body must contain alert banner or rationale");
        assertTrue(commentBody.contains("Remediation Guidance:"), "Comment body must contain remediation guidance");
        assertTrue(commentBody.contains("```suggestion") || commentBody.contains("```diff"),
                "Comment body must contain code suggestion block or diff");

        // Verify APPROVE event on empty findings
        ReviewReport cleanReport = new ReviewReport("CLEAN-1", null, "Clean.java", 1, 0, "SUCCESS", false, "Clean", List.of(), List.of());
        assertEquals("APPROVE", reviewCommentBuilder.determineReviewEvent(cleanReport.getFindings()));
    }

    @Test
    @DisplayName("P2-4: SentinelCliRunner supports --diff and --sarif flags")
    void testCliRunnerIncrementalAndSarifExport(@TempDir Path tempDir) throws Exception {
        Path sarifOutput = tempDir.resolve("cli-output.sarif");
        SentinelCliRunner runner = new SentinelCliRunner(orchestrator, sarifGenerator, reviewCommentBuilder);

        ReviewReport report = runner.run(fixtureFile, diffFile, sarifOutput, "sarif");

        assertNotNull(report);
        assertEquals(1, report.getVulnerabilityCount(), "CLI incremental scan should yield 1 active finding");
        assertTrue(Files.exists(sarifOutput), "SARIF output file must have been generated");
        assertTrue(Files.size(sarifOutput) > 0, "SARIF output file must not be empty");
    }

    @Test
    @DisplayName("P2-5: SentinelReviewController handles diffContent, /review/sarif, and /review/github")
    void testRestControllerWorkflowIntegration() throws Exception {
        // 1. Health check
        ResponseEntity<Map<String, Object>> health = reviewController.health();
        assertEquals(200, health.getStatusCode().value());
        assertEquals(10, health.getBody().get("rules"), "Controller health endpoint must report 10 active rules");

        // 2. Incremental review via POST /review with diffContent
        String patchContent = Files.readString(diffFile);
        ReviewFileRequest diffRequest = new ReviewFileRequest();
        diffRequest.setTargetPath(fixtureFile.toString());
        diffRequest.setDiffContent(patchContent);

        ResponseEntity<?> reviewResp = reviewController.review(diffRequest);
        assertEquals(200, reviewResp.getStatusCode().value());
        assertTrue(reviewResp.getBody() instanceof ReviewReport);
        ReviewReport diffReport = (ReviewReport) reviewResp.getBody();
        assertEquals(1, diffReport.getVulnerabilityCount(), "Incremental review should filter to 1 active finding");

        // 3. POST /review/sarif
        ReviewFileRequest sarifRequest = new ReviewFileRequest();
        sarifRequest.setTargetPath(fixtureFile.toString());

        ResponseEntity<?> sarifResp = reviewController.reviewSarif(sarifRequest);
        assertEquals(200, sarifResp.getStatusCode().value());
        assertTrue(sarifResp.getBody() instanceof Map);
        Map<?, ?> sarifMap = (Map<?, ?>) sarifResp.getBody();
        assertEquals("https://json.schemastore.org/sarif-2.1.0.json", sarifMap.get("$schema"));
        assertEquals("2.1.0", sarifMap.get("version"));

        // 4. POST /review/github
        ReviewFileRequest githubRequest = new ReviewFileRequest();
        githubRequest.setTargetPath(fixtureFile.toString());

        ResponseEntity<?> githubResp = reviewController.reviewGithub(githubRequest);
        assertEquals(200, githubResp.getStatusCode().value());
        assertTrue(githubResp.getBody() instanceof GitHubReviewPayload);
        GitHubReviewPayload payload = (GitHubReviewPayload) githubResp.getBody();
        assertEquals("REQUEST_CHANGES", payload.getEvent());
        assertFalse(payload.getComments().isEmpty());
    }
}
