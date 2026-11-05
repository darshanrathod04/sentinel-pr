package com.sentinelpr.core.analysis.multilang.python;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sentinelpr.client.SentinelClient;
import com.sentinelpr.core.export.github.PrReviewCommentBuilder;
import com.sentinelpr.core.export.sarif.SarifReportGenerator;
import com.sentinelpr.core.governance.policy.PolicyEngine;
import com.sentinelpr.core.governance.policy.PolicyEvaluationResult;
import com.sentinelpr.core.governance.policy.SentinelPolicy;
import com.sentinelpr.core.model.InspectedSource;
import com.sentinelpr.core.model.ReviewReport;
import com.sentinelpr.core.model.SecurityFinding;
import com.sentinelpr.core.model.SourceLanguage;
import com.sentinelpr.core.model.UnifiedDiffPatch;
import com.sentinelpr.core.remediation.PatchValidationStatus;
import com.sentinelpr.core.service.PatchVerificationResult;
import com.sentinelpr.core.service.CodeInspectionService;
import com.sentinelpr.core.service.PatchComposer;
import com.sentinelpr.core.service.PatchVerifier;
import com.sentinelpr.core.service.RuleEvaluationService;
import com.sentinelpr.github.ReviewCommentService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * <b>MixedLanguageRemediationBoundaryTest</b>
 *
 * <p>Phase 5 Milestone 9: Validates mixed-language repository scans containing both Java 21 LTS
 * and Python source code. Enforces strict safety boundary guarantees:</p>
 * <ul>
 *   <li>Java findings generate AST-rewritten, regression-verified unified diff patches.</li>
 *   <li>Python findings strictly enforce {@link UnifiedDiffPatch.Status#MANUAL_REMEDIATION_REQUIRED}.</li>
 *   <li>No Python code is ever routed into {@code JavaParser} or Java AST synthesis pipelines.</li>
 *   <li>Downstream consumers (SARIF, PR Review Comments, Sticky PR comments, PolicyEngine)
 *       correctly segregate verified Java patches from manual Python remediation.</li>
 * </ul>
 */
@DisplayName("Phase 5: Mixed-Language Remediation Boundary & Hardening Tests")
public class MixedLanguageRemediationBoundaryTest {

    private CodeInspectionService inspectionService;
    private RuleEvaluationService evaluationService;
    private PatchComposer patchComposer;
    private PatchVerifier patchVerifier;
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
        this.patchVerifier = new PatchVerifier(inspectionService, evaluationService);
        this.sarifGenerator = new SarifReportGenerator();
        this.commentBuilder = new PrReviewCommentBuilder();
        this.reviewCommentService = new ReviewCommentService();
        this.policyEngine = new PolicyEngine();
        this.objectMapper = new ObjectMapper()
                .registerModule(new com.fasterxml.jackson.datatype.jsr310.JavaTimeModule());
    }

    private static final String VULN_JAVA_CODE = """
            package com.example.service;

            import java.io.File;
            import java.io.FileInputStream;
            import java.io.IOException;

            public class ReportService {
                public String loadReport(File file) throws IOException {
                    FileInputStream fis = new FileInputStream(file);
                    byte[] data = new byte[1024];
                    int len = fis.read(data);
                    return new String(data, 0, len);
                }
            }
            """;

    private static final String VULN_PYTHON_CODE = """
            import sqlite3
            from flask import Flask, request

            app = Flask(__name__)

            @app.route("/search")
            def search():
                q = request.args.get("q")
                conn = sqlite3.connect("data.db")
                cur = conn.cursor()
                query = f"SELECT * FROM items WHERE name = '{q}'"
                cur.execute(query)
                return "Results"
            """;

    @Test
    @DisplayName("Boundary: Mixed Java + Python scan segregates verified Java patches from manual Python remediation")
    void testMixedLanguage_SegregatesVerifiedFromManualPatches() {
        // Inspect both sources
        InspectedSource javaSource = inspectionService.inspectSourceCode(VULN_JAVA_CODE, "src/main/java/ReportService.java");
        InspectedSource pySource = inspectionService.inspectSourceCode(VULN_PYTHON_CODE, "api/search.py");

        assertEquals(SourceLanguage.JAVA, javaSource.getLanguage());
        assertEquals(SourceLanguage.PYTHON, pySource.getLanguage());

        // Evaluate rules
        List<SecurityFinding> javaFindings = evaluationService.evaluate(javaSource);
        List<SecurityFinding> pyFindings = evaluationService.evaluate(pySource);

        assertFalse(javaFindings.isEmpty(), "Must find unclosed stream in Java");
        assertFalse(pyFindings.isEmpty(), "Must find SQL injection in Python");

        // Synthesize patches
        UnifiedDiffPatch javaPatch = patchComposer.compose(javaSource, javaFindings);
        UnifiedDiffPatch pyPatch = patchComposer.compose(pySource, pyFindings);

        // Java patch MUST be SUCCESS/verified with non-empty diff
        assertEquals(UnifiedDiffPatch.Status.SUCCESS, javaPatch.getStatus(), "Java patch must be SUCCESS");
        assertTrue(javaPatch.isVerified(), "Java patch must be marked verified");
        assertFalse(javaPatch.getUnifiedDiff().isBlank(), "Java patch must contain non-empty unified diff");
        assertTrue(javaPatch.getUnifiedDiff().contains("try (FileInputStream fis = new FileInputStream(file))"),
                "Java patch must apply try-with-resources AST fix");

        // Python patch MUST be MANUAL_REMEDIATION_REQUIRED with empty diff
        assertEquals(UnifiedDiffPatch.Status.MANUAL_REMEDIATION_REQUIRED, pyPatch.getStatus(),
                "Python patch must strictly enforce MANUAL_REMEDIATION_REQUIRED");
        assertFalse(pyPatch.isVerified(), "Python patch must NOT be marked verified");
        assertEquals("", pyPatch.getUnifiedDiff(), "Python patch unified diff must be empty");
        assertEquals(PatchValidationStatus.MANUAL_REMEDIATION_REQUIRED, pyPatch.getValidationStatus());
    }

    @Test
    @DisplayName("Boundary: PatchVerifier safely returns MANUAL_REMEDIATION_REQUIRED for Python code without invoking JavaParser")
    void testPatchVerifier_PythonCodeSafelyFailsClosed() {
        PatchVerificationResult verResult = patchVerifier.verify(VULN_PYTHON_CODE, "api/search.py");

        assertFalse(verResult.isSyntaxValid(), "PatchVerifier must reject non-Java syntax");
        assertFalse(verResult.isRegressionVerified(), "PatchVerifier must not verify regression for non-Java");
        assertEquals(PatchValidationStatus.MANUAL_REMEDIATION_REQUIRED, verResult.getValidationStatus(),
                "Validation status must be MANUAL_REMEDIATION_REQUIRED");
    }

    @Test
    @DisplayName("Downstream SARIF: Mixed report serializes both languages with honest verification flags")
    void testMixedReport_SarifHonestFlags() throws Exception {
        InspectedSource javaSource = inspectionService.inspectSourceCode(VULN_JAVA_CODE, "src/main/java/ReportService.java");
        InspectedSource pySource = inspectionService.inspectSourceCode(VULN_PYTHON_CODE, "api/search.py");

        List<SecurityFinding> javaFindings = evaluationService.evaluate(javaSource);
        List<SecurityFinding> pyFindings = evaluationService.evaluate(pySource);

        UnifiedDiffPatch javaPatch = patchComposer.compose(javaSource, javaFindings);
        UnifiedDiffPatch pyPatch = patchComposer.compose(pySource, pyFindings);

        List<SecurityFinding> allFindings = new ArrayList<>();
        allFindings.addAll(javaFindings);
        allFindings.addAll(pyFindings);

        List<UnifiedDiffPatch> allPatches = List.of(javaPatch, pyPatch);

        ReviewReport mixedReport = new ReviewReport(
                "REV-MIXED-001",
                Instant.now(),
                "repo/mixed",
                2,
                allFindings.size(),
                "ACTIVE_VULNERABILITIES",
                false,
                "Mixed scan completed",
                allFindings,
                Collections.emptyList(),
                allPatches
        );

        String sarifJson = sarifGenerator.generateSarifJson(mixedReport);
        assertNotNull(sarifJson);

        JsonNode root = objectMapper.readTree(sarifJson);
        JsonNode results = root.get("runs").get(0).get("results");
        assertEquals(allFindings.size(), results.size());

        boolean foundVerifiedJava = false;
        boolean foundManualPython = false;

        for (JsonNode res : results) {
            String uri = res.get("locations").get(0).get("physicalLocation").get("artifactLocation").get("uri").asText();
            JsonNode props = res.get("properties");

            if (uri.endsWith("ReportService.java")) {
                assertEquals("SUCCESS", props.get("patchStatus").asText());
                assertTrue(props.get("patchVerified").asBoolean());
                assertTrue(props.has("unifiedDiff"));
                foundVerifiedJava = true;
            } else if (uri.endsWith("search.py")) {
                assertEquals("MANUAL_REMEDIATION_REQUIRED", props.get("patchStatus").asText());
                assertFalse(props.get("patchVerified").asBoolean());
                foundManualPython = true;
            }
        }

        assertTrue(foundVerifiedJava, "SARIF must contain verified Java result");
        assertTrue(foundManualPython, "SARIF must contain manual remediation Python result");
    }

    @Test
    @DisplayName("Downstream PR Review Payload: Emits suggestion for Java and omits suggestion for Python")
    void testMixedReport_PrReviewPayloadSuggestions() {
        InspectedSource javaSource = inspectionService.inspectSourceCode(VULN_JAVA_CODE, "src/main/java/ReportService.java");
        InspectedSource pySource = inspectionService.inspectSourceCode(VULN_PYTHON_CODE, "api/search.py");

        List<SecurityFinding> javaFindings = evaluationService.evaluate(javaSource);
        List<SecurityFinding> pyFindings = evaluationService.evaluate(pySource);

        UnifiedDiffPatch javaPatch = patchComposer.compose(javaSource, javaFindings);
        UnifiedDiffPatch pyPatch = patchComposer.compose(pySource, pyFindings);

        List<SecurityFinding> allFindings = new ArrayList<>();
        allFindings.addAll(javaFindings);
        allFindings.addAll(pyFindings);

        ReviewReport mixedReport = new ReviewReport(
                "REV-MIXED-002",
                Instant.now(),
                "repo/mixed",
                2,
                allFindings.size(),
                "ACTIVE_VULNERABILITIES",
                false,
                "Mixed scan completed",
                allFindings,
                Collections.emptyList(),
                List.of(javaPatch, pyPatch)
        );

        PrReviewCommentBuilder.GitHubReviewPayload payload = commentBuilder.buildReviewPayload(mixedReport, "commit-mixed-999");
        assertEquals("REQUEST_CHANGES", payload.getEvent());

        boolean foundJavaSuggestion = false;
        boolean checkedPythonInline = false;

        for (PrReviewCommentBuilder.GitHubInlineComment comment : payload.getComments()) {
            if (comment.getPath().endsWith("ReportService.java")) {
                assertTrue(comment.getBody().contains("```suggestion"), "Java comment must contain code suggestion");
                foundJavaSuggestion = true;
            } else if (comment.getPath().endsWith("search.py")) {
                assertFalse(comment.getBody().contains("```suggestion"), "Python comment must NOT contain code suggestion");
                assertFalse(comment.getBody().contains("```diff"), "Python comment must NOT contain diff block");
                checkedPythonInline = true;
            }
        }

        assertTrue(foundJavaSuggestion, "Must have verified Java suggestion in review payload");
        assertTrue(checkedPythonInline, "Must have verified Python comment without suggestion block");
    }

    @Test
    @DisplayName("Downstream Sticky Comment: Suggested patch block contains Java diff without corrupting with Python")
    void testMixedReport_StickyCommentOnlyEmbedsValidJavaDiff() {
        InspectedSource javaSource = inspectionService.inspectSourceCode(VULN_JAVA_CODE, "src/main/java/ReportService.java");
        InspectedSource pySource = inspectionService.inspectSourceCode(VULN_PYTHON_CODE, "api/search.py");

        List<SecurityFinding> javaFindings = evaluationService.evaluate(javaSource);
        List<SecurityFinding> pyFindings = evaluationService.evaluate(pySource);

        UnifiedDiffPatch javaPatch = patchComposer.compose(javaSource, javaFindings);
        UnifiedDiffPatch pyPatch = patchComposer.compose(pySource, pyFindings);

        List<SecurityFinding> allFindings = new ArrayList<>();
        allFindings.addAll(javaFindings);
        allFindings.addAll(pyFindings);

        ReviewReport mixedReport = new ReviewReport(
                "REV-MIXED-003",
                Instant.now(),
                "repo/mixed",
                2,
                allFindings.size(),
                "ACTIVE_VULNERABILITIES",
                false,
                "Mixed scan completed",
                allFindings,
                Collections.emptyList(),
                List.of(javaPatch, pyPatch)
        );

        String stickyComment = reviewCommentService.buildCommentMarkdown(mixedReport);
        assertTrue(stickyComment.startsWith("<!-- sentinel-pr-review -->\n\n"));
        assertTrue(stickyComment.contains("Status: BLOCKED\n\n"));

        // Must list both findings in table
        assertTrue(stickyComment.contains("src/main/java/ReportService.java"));
        assertTrue(stickyComment.contains("api/search.py"));

        // Suggested Patch must contain the Java diff
        assertTrue(stickyComment.contains("--- a/src/main/java/ReportService.java"));
        assertTrue(stickyComment.contains("+++ b/src/main/java/ReportService.java"));

        // Must NOT contain any fake or broken Python diff lines
        assertFalse(stickyComment.contains("--- a/api/search.py"));
        assertFalse(stickyComment.contains("+++ b/api/search.py"));
    }
}
