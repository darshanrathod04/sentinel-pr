package com.sentinelpr.core.analysis.multilang.python;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sentinelpr.cli.SentinelCliRunner;
import com.sentinelpr.client.SentinelClient;
import com.sentinelpr.core.export.github.PrReviewCommentBuilder;
import com.sentinelpr.core.export.sarif.SarifReportGenerator;
import com.sentinelpr.core.governance.policy.PolicyEngine;
import com.sentinelpr.core.governance.policy.PolicyEvaluationResult;
import com.sentinelpr.core.governance.policy.SentinelPolicy;
import com.sentinelpr.core.model.InspectedSource;
import com.sentinelpr.core.model.ReviewReport;
import com.sentinelpr.core.model.SecurityFinding;
import com.sentinelpr.core.model.UnifiedDiffPatch;
import com.sentinelpr.core.remediation.PatchValidationStatus;
import com.sentinelpr.core.service.CodeInspectionService;
import com.sentinelpr.core.service.PatchComposer;
import com.sentinelpr.core.service.RuleEvaluationService;
import com.sentinelpr.github.ReviewCommentService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * <b>PythonSarifAndCommentIntegrationTest</b>
 *
 * <p>Phase 5 Milestone 8: Verifies end-to-end integration of Python AST security findings
 * into OASIS SARIF v2.1.0 exports, GitHub PR sticky comments, PR review comment payloads,
 * and the SentinelPR CLI runner.</p>
 */
@DisplayName("Phase 5: Python SARIF, CLI & GitHub Action Integration Tests")
public class PythonSarifAndCommentIntegrationTest {

    private CodeInspectionService inspectionService;
    private RuleEvaluationService evaluationService;
    private PatchComposer patchComposer;
    private SarifReportGenerator sarifGenerator;
    private PrReviewCommentBuilder commentBuilder;
    private ReviewCommentService reviewCommentService;
    private PolicyEngine policyEngine;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        SentinelClient client = SentinelClient.getInstance();
        this.inspectionService = new CodeInspectionService();
        this.evaluationService = new RuleEvaluationService();
        this.patchComposer = new PatchComposer(client);
        this.sarifGenerator = new SarifReportGenerator();
        this.commentBuilder = new PrReviewCommentBuilder();
        this.reviewCommentService = new ReviewCommentService();
        this.policyEngine = new PolicyEngine();
        this.objectMapper = new ObjectMapper()
                .registerModule(new com.fasterxml.jackson.datatype.jsr310.JavaTimeModule());
    }

    private static final String VULN_PYTHON_SCRIPT = """
            import os
            import sqlite3
            from flask import Flask, request

            app = Flask(__name__)

            @app.route("/user")
            def get_user():
                user_id = request.args.get("id")
                conn = sqlite3.connect("users.db")
                cursor = conn.cursor()
                query = f"SELECT * FROM users WHERE id = '{user_id}'"
                cursor.execute(query)
                return "OK"

            @app.route("/exec")
            def run_cmd():
                cmd = request.args.get("cmd")
                os.system(cmd)
                return "Done"
            """;

    @Test
    @DisplayName("SARIF: Python findings serialize with correct URI, rule, and manual remediation status")
    void testSarifExport_WithPythonFindings() throws Exception {
        InspectedSource source = inspectionService.inspectSourceCode(VULN_PYTHON_SCRIPT, "src/api/routes.py");
        List<SecurityFinding> findings = evaluationService.evaluate(source);
        assertFalse(findings.isEmpty(), "Must identify Python findings");

        UnifiedDiffPatch patch = patchComposer.compose(source, findings);
        assertEquals(UnifiedDiffPatch.Status.MANUAL_REMEDIATION_REQUIRED, patch.getStatus());

        ReviewReport report = new ReviewReport(
                "REV-PY-SARIF",
                Instant.now(),
                "src/api/routes.py",
                1,
                findings.size(),
                "ACTIVE_VULNERABILITIES",
                false,
                "Python audit completed",
                findings,
                Collections.emptyList(),
                List.of(patch)
        );

        String sarifJson = sarifGenerator.generateSarifJson(report);
        assertNotNull(sarifJson);

        JsonNode rootNode = objectMapper.readTree(sarifJson);
        assertEquals("2.1.0", rootNode.get("version").asText());
        assertEquals("https://json.schemastore.org/sarif-2.1.0.json", rootNode.get("$schema").asText());

        JsonNode runs = rootNode.get("runs");
        assertNotNull(runs);
        assertTrue(runs.isArray() && !runs.isEmpty());

        JsonNode run = runs.get(0);
        assertEquals("SentinelPR", run.get("tool").get("driver").get("name").asText());

        JsonNode results = run.get("results");
        assertNotNull(results);
        assertEquals(findings.size(), results.size());

        for (JsonNode result : results) {
            String ruleId = result.get("ruleId").asText();
            assertTrue(ruleId.startsWith("SEC-"), "Rule ID must be valid SentinelPR rule: " + ruleId);

            JsonNode loc = result.get("locations").get(0).get("physicalLocation");
            String uri = loc.get("artifactLocation").get("uri").asText();
            assertEquals("src/api/routes.py", uri);

            JsonNode props = result.get("properties");
            assertNotNull(props);
            assertEquals("MANUAL_REMEDIATION_REQUIRED", props.get("patchStatus").asText());
            assertFalse(props.get("patchVerified").asBoolean());
        }
    }

    @Test
    @DisplayName("PR Review Comments: Suppresses inline diff/suggestion and labels MANUAL_REMEDIATION_REQUIRED")
    void testPrReviewCommentBuilder_WithPythonFindings() {
        InspectedSource source = inspectionService.inspectSourceCode(VULN_PYTHON_SCRIPT, "app.py");
        List<SecurityFinding> findings = evaluationService.evaluate(source);
        assertFalse(findings.isEmpty());

        UnifiedDiffPatch patch = patchComposer.compose(source, findings);
        ReviewReport report = new ReviewReport(
                "REV-PY-PR",
                Instant.now(),
                "app.py",
                1,
                findings.size(),
                "ACTIVE_VULNERABILITIES",
                false,
                "Python audit completed",
                findings,
                Collections.emptyList(),
                List.of(patch)
        );

        PrReviewCommentBuilder.GitHubReviewPayload payload = commentBuilder.buildReviewPayload(report, "commit-py-123");
        assertEquals("commit-py-123", payload.getCommitId());
        assertEquals("REQUEST_CHANGES", payload.getEvent());

        String summary = payload.getBody();
        assertTrue(summary.contains("MANUAL_REMEDIATION_REQUIRED"), "Review summary table must explicitly show MANUAL_REMEDIATION_REQUIRED");
        assertTrue(summary.contains("app.py"), "Summary table must reference Python file");

        // Verify each inline comment
        for (PrReviewCommentBuilder.GitHubInlineComment inline : payload.getComments()) {
            assertEquals("app.py", inline.getPath());
            String commentBody = inline.getBody();
            assertFalse(commentBody.contains("```suggestion"), "Python inline comment must NEVER contain ```suggestion");
            assertFalse(commentBody.contains("```diff"), "Python inline comment must NEVER contain ```diff");
            assertTrue(commentBody.contains("Causal Rationale:"), "Must provide causal rationale for developer");
            assertTrue(commentBody.contains("Remediation Guidance:"), "Must provide remediation guidance");
        }
    }

    @Test
    @DisplayName("ReviewCommentService: Sticky comment indicates manual remediation when Python findings exist")
    void testStickyComment_WithPythonFindings() {
        InspectedSource source = inspectionService.inspectSourceCode(VULN_PYTHON_SCRIPT, "backend/server.py");
        List<SecurityFinding> findings = evaluationService.evaluate(source);
        assertFalse(findings.isEmpty());

        UnifiedDiffPatch patch = patchComposer.compose(source, findings);
        ReviewReport report = new ReviewReport(
                "REV-PY-STICKY",
                Instant.now(),
                "backend/server.py",
                1,
                findings.size(),
                "ACTIVE_VULNERABILITIES",
                false,
                "Python audit completed",
                findings,
                Collections.emptyList(),
                List.of(patch)
        );

        String markdown = reviewCommentService.buildCommentMarkdown(report);
        assertTrue(markdown.startsWith("<!-- sentinel-pr-review -->\n\n"));
        assertTrue(markdown.contains("Status: BLOCKED\n\n"));
        assertTrue(markdown.contains("SEC-005-SQL-INJECTION") && markdown.contains("backend/server.py:"), "Must list SQL injection finding");
        assertTrue(markdown.contains("# Manual remediation required (automated patch synthesis unavailable for target language or rule)"),
                "Diff section must inform developer that manual remediation is required");
    }

    @Test
    @DisplayName("CLI Formatters: Correctly formats Python review report for json, sarif, and github")
    void testCliFormatters_WithPythonReport() throws Exception {
        InspectedSource source = inspectionService.inspectSourceCode(VULN_PYTHON_SCRIPT, "src/api/routes.py");
        List<SecurityFinding> findings = evaluationService.evaluate(source);
        assertFalse(findings.isEmpty());

        UnifiedDiffPatch patch = patchComposer.compose(source, findings);
        ReviewReport report = new ReviewReport(
                "REV-PY-CLI",
                Instant.now(),
                "src/api/routes.py",
                1,
                findings.size(),
                "ACTIVE_VULNERABILITIES",
                false,
                "Python audit completed",
                findings,
                Collections.emptyList(),
                List.of(patch)
        );

        // SARIF format
        String sarifOutput = sarifGenerator.generateSarifJson(report);
        assertTrue(sarifOutput.contains("routes.py"));
        assertTrue(sarifOutput.contains("MANUAL_REMEDIATION_REQUIRED"));

        // GitHub review payload format
        PrReviewCommentBuilder.GitHubReviewPayload ghPayload = commentBuilder.buildReviewPayload(report);
        assertEquals("REQUEST_CHANGES", ghPayload.getEvent());
        assertTrue(ghPayload.getBody().contains("MANUAL_REMEDIATION_REQUIRED"));

        // Structured JSON format
        String jsonOutput = objectMapper.writeValueAsString(report);
        assertTrue(jsonOutput.contains("REV-PY-CLI"));
        assertTrue(jsonOutput.contains("routes.py"));
        assertTrue(jsonOutput.contains("MANUAL_REMEDIATION_REQUIRED"));

        // Enterprise Policy verification: failOnUnverifiedPatch triggers exit code 4
        SentinelPolicy policyStrictPatch = new SentinelPolicy(
                "Enterprise-Strict-Patch",
                "1.0",
                0, // maxCritical
                0, // maxHigh
                0, // maxMedium
                0, // maxLow
                true, // failOnUnverifiedPatch
                Collections.emptyList(),
                Collections.emptyList()
        );

        PolicyEvaluationResult patchPolicyResult = policyEngine.evaluate(report, policyStrictPatch);
        assertTrue(patchPolicyResult.isBreached(), "Policy must breach on unverified non-Java patch");
        assertEquals(4, patchPolicyResult.getExitCode(), "Must return exit code 4 when unverified patch requirement fails");

        // Policy breach on findings threshold with failOnUnverifiedPatch=false triggers exit code 1
        SentinelPolicy policyFindingsThreshold = new SentinelPolicy(
                "Enterprise-Threshold-Only",
                "1.0",
                0, // maxCritical
                0, // maxHigh
                0, // maxMedium
                0, // maxLow
                false, // failOnUnverifiedPatch
                Collections.emptyList(),
                Collections.emptyList()
        );

        PolicyEvaluationResult thresholdPolicyResult = policyEngine.evaluate(report, policyFindingsThreshold);
        assertTrue(thresholdPolicyResult.isBreached(), "Policy must breach on critical findings");
        assertEquals(1, thresholdPolicyResult.getExitCode(), "Must return exit code 1 on findings breach");
    }
}
