package com.sentinelpr.core.remediation;

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
import com.sentinelpr.core.service.CodeInspectionService;
import com.sentinelpr.core.service.PatchComposer;
import com.sentinelpr.core.service.RuleEvaluationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * <b>NonJavaRemediationConsumerIntegrationTest</b>
 *
 * <p>Integration tests verifying downstream consumers of {@link UnifiedDiffPatch} and
 * {@link PatchValidationStatus#MANUAL_REMEDIATION_REQUIRED}:</p>
 * <ul>
 *   <li>{@link PolicyEngine}: fail-closed behavior when failOnUnverifiedPatch is active.</li>
 *   <li>{@link PrReviewCommentBuilder}: omission of code suggestion and diff blocks when diff is empty.</li>
 *   <li>{@link SarifReportGenerator}: serialization of unverified patch properties.</li>
 * </ul>
 */
@DisplayName("Phase 4B.2: Non-Java Remediation Consumer Integration Tests")
public class NonJavaRemediationConsumerIntegrationTest {

    private CodeInspectionService inspectionService;
    private RuleEvaluationService evaluationService;
    private PatchComposer patchComposer;
    private PolicyEngine policyEngine;
    private PrReviewCommentBuilder commentBuilder;
    private SarifReportGenerator sarifGenerator;

    @BeforeEach
    void setUp() {
        SentinelClient client = SentinelClient.getInstance();
        this.inspectionService = new CodeInspectionService();
        this.evaluationService = new RuleEvaluationService();
        this.patchComposer = new PatchComposer(client);
        this.policyEngine = new PolicyEngine();
        this.commentBuilder = new PrReviewCommentBuilder();
        this.sarifGenerator = new SarifReportGenerator();
    }

    @Test
    @DisplayName("PolicyEngine: Fails closed when non-Java finding patch has MANUAL_REMEDIATION_REQUIRED")
    void testPolicyEngine_FailsClosedOnManualRemediation() {
        String pyCode = """
                import os
                def run_cmd(c):
                    os.system(c)
                """;
        InspectedSource source = inspectionService.inspectSourceCode(pyCode, "task_runner.py");
        assertEquals(SourceLanguage.PYTHON, source.getLanguage());

        List<SecurityFinding> findings = evaluationService.evaluate(source);
        assertFalse(findings.isEmpty(), "Must find command injection in Python");

        UnifiedDiffPatch patch = patchComposer.compose(source, findings);
        assertEquals(UnifiedDiffPatch.Status.MANUAL_REMEDIATION_REQUIRED, patch.getStatus());
        assertFalse(patch.isVerified());

        // Build mock ReviewReport with this finding and patch
        ReviewReport report = new ReviewReport(
                "audit-nonjava-01",
                Instant.now(),
                "repo/test",
                1,
                findings.size(),
                "ACTIVE_VULNERABILITIES",
                false,
                "Audit completed with findings",
                findings,
                Collections.emptyList(),
                List.of(patch)
        );

        // Strict enterprise policy requiring all patches to be verified
        SentinelPolicy policy = new SentinelPolicy(
                "Strict-CI-Policy",
                "1.0",
                10,     // maxAllowedCritical (allow findings to isolate patch failure)
                10,     // maxAllowedHigh
                10,     // maxAllowedMedium
                10,     // maxAllowedLow
                true,   // failOnUnverifiedPatch -> MUST FAIL CLOSED
                Collections.emptyList(),
                Collections.emptyList()
        );

        PolicyEvaluationResult result = policyEngine.evaluate(report, policy);
        assertEquals(PolicyEvaluationResult.Status.BREACHED, result.getStatus(),
                "Policy with failOnUnverifiedPatch must breach when non-Java patch requires manual remediation");
        assertTrue(result.getViolations().stream()
                .anyMatch(v -> v.contains("is unverified or failed") && (v.contains("Manual remediation required") || v.contains("MANUAL_REMEDIATION_REQUIRED"))),
                "Violation list must cite the unverified patch requirement");
    }

    @Test
    @DisplayName("PrReviewCommentBuilder: Suppresses suggestion and diff blocks for manual remediation")
    void testPrReviewCommentBuilder_OmitsSuggestionBlockForManualRemediation() {
        String ktCode = """
                package com.example
                class Service {
                    fun exec(cmd: String) {
                        Runtime.getRuntime().exec(cmd)
                    }
                }
                """;
        InspectedSource source = inspectionService.inspectSourceCode(ktCode, "Service.kt");
        List<SecurityFinding> findings = evaluationService.evaluate(source);
        assertFalse(findings.isEmpty());

        SecurityFinding finding = findings.get(0);
        UnifiedDiffPatch patch = patchComposer.compose(source, findings);
        assertEquals(UnifiedDiffPatch.Status.MANUAL_REMEDIATION_REQUIRED, patch.getStatus());
        assertEquals("", patch.getUnifiedDiff());

        String commentMarkdown = commentBuilder.buildInlineCommentMarkdown(finding, patch);

        assertNotNull(commentMarkdown);
        assertFalse(commentMarkdown.contains("```suggestion"),
                "Must NOT generate a ```suggestion block when patch is MANUAL_REMEDIATION_REQUIRED");
        assertFalse(commentMarkdown.contains("```diff"),
                "Must NOT generate a ```diff block when patch has an empty diff");
        assertTrue(commentMarkdown.contains("Un-isolated Subprocess") || commentMarkdown.contains("Command Injection"),
                "Comment must contain finding title");
        assertTrue(commentMarkdown.contains(finding.getCausalRationale()),
                "Comment must contain causal rationale");
    }

    @Test
    @DisplayName("SarifReportGenerator: Marks non-Java manual remediation patch as unverified")
    void testSarifExport_MarksManualRemediationUnverified() {
        String jsCode = "const cp = require('child_process'); cp.exec(process.argv[2]);";
        InspectedSource source = inspectionService.inspectSourceCode(jsCode, "index.js");
        List<SecurityFinding> findings = evaluationService.evaluate(source);
        assertFalse(findings.isEmpty());

        UnifiedDiffPatch patch = patchComposer.compose(source, findings);
        assertEquals(UnifiedDiffPatch.Status.MANUAL_REMEDIATION_REQUIRED, patch.getStatus());

        ReviewReport report = new ReviewReport(
                "audit-sarif-nonjava",
                Instant.now(),
                "repo/node-app",
                1,
                findings.size(),
                "ACTIVE_VULNERABILITIES",
                false,
                "Audit completed",
                findings,
                Collections.emptyList(),
                List.of(patch)
        );

        String sarifJson = sarifGenerator.generateSarifJson(report);
        assertNotNull(sarifJson);
        assertTrue(sarifJson.contains("\"patchVerified\" : false") || sarifJson.contains("\"patchVerified\": false") || sarifJson.contains("\"patchVerified\" : false"),
                "SARIF properties must record patchVerified as false for non-Java patch");
        assertTrue(sarifJson.contains("child_process.exec"),
                "SARIF must contain finding code snippet");
    }

    @Test
    @DisplayName("PrReviewCommentBuilder: PR summary accurately marks non-Java patch as unverified")
    void testPrReviewCommentBuilder_PrReviewSummaryMarkdown() {
        String tsCode = "import cp from 'child_process'; function run(c: string) { cp.exec(c); }";
        InspectedSource source = inspectionService.inspectSourceCode(tsCode, "runner.ts");
        List<SecurityFinding> findings = evaluationService.evaluate(source);
        UnifiedDiffPatch patch = patchComposer.compose(source, findings);

        ReviewReport report = new ReviewReport(
                "audit-ts-01",
                Instant.now(),
                "repo/ts-app",
                1,
                findings.size(),
                "ACTIVE_VULNERABILITIES",
                false,
                "Audit completed",
                findings,
                Collections.emptyList(),
                List.of(patch)
        );

        String summary = commentBuilder.buildReviewSummaryMarkdown(report, "REQUEST_CHANGES");
        assertNotNull(summary);
        assertTrue(summary.contains("SentinelPR"),
                "Must include standard header");
        // In the table, non-verified patches are rendered as "—"
        assertTrue(summary.contains("—"),
                "Unverified patch must display '—' badge rather than verified checkmark");
    }
}
