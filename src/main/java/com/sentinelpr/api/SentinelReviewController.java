package com.sentinelpr.api;

import com.sentinelpr.api.dto.PolicyEvaluateRequest;
import com.sentinelpr.api.dto.ReviewFileRequest;
import com.sentinelpr.core.export.github.PrReviewCommentBuilder;
import com.sentinelpr.core.export.sarif.SarifReportGenerator;
import com.sentinelpr.core.governance.policy.PolicyEngine;
import com.sentinelpr.core.governance.policy.PolicyEvaluationResult;
import com.sentinelpr.core.governance.policy.SentinelPolicy;
import com.sentinelpr.core.model.ReviewReport;
import com.sentinelpr.core.model.SecurityRule;
import com.sentinelpr.core.service.SentinelAuditOrchestrator;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * <b>SentinelReviewController</b>
 *
 * <p>REST API endpoint for triggering code and security reviews with support for
 * full AST audits, incremental git diff filtering, OASIS SARIF v2.1.0 exports,
 * enterprise policy governance, and GitHub Pull Request review comments.</p>
 */
@RestController
@RequestMapping("/api/v1/sentinel")
public class SentinelReviewController {

    private final SentinelAuditOrchestrator orchestrator;
    private final SarifReportGenerator sarifGenerator;
    private final PrReviewCommentBuilder reviewCommentBuilder;
    private final PolicyEngine policyEngine;

    public SentinelReviewController(SentinelAuditOrchestrator orchestrator) {
        this(orchestrator, new SarifReportGenerator(), new PrReviewCommentBuilder(), new PolicyEngine());
    }

    public SentinelReviewController(
            SentinelAuditOrchestrator orchestrator,
            SarifReportGenerator sarifGenerator,
            PrReviewCommentBuilder reviewCommentBuilder
    ) {
        this(orchestrator, sarifGenerator, reviewCommentBuilder, new PolicyEngine());
    }

    public SentinelReviewController(
            SentinelAuditOrchestrator orchestrator,
            SarifReportGenerator sarifGenerator,
            PrReviewCommentBuilder reviewCommentBuilder,
            PolicyEngine policyEngine
    ) {
        this.orchestrator = Objects.requireNonNull(orchestrator, "orchestrator must not be null");
        this.sarifGenerator = Objects.requireNonNull(sarifGenerator, "sarifGenerator must not be null");
        this.reviewCommentBuilder = Objects.requireNonNull(reviewCommentBuilder, "reviewCommentBuilder must not be null");
        this.policyEngine = Objects.requireNonNull(policyEngine, "policyEngine must not be null");
    }

    /**
     * Health check and copilot metadata endpoint.
     */
    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> health() {
        return ResponseEntity.ok(Map.of(
                "service", "SentinelPR - Enterprise Code & Security Review Copilot",
                "status", "UP",
                "platform", "Shree AI OS (1.0.6-developer-preview)",
                "rules", SecurityRule.getCoreSecurityRulesCount(),
                "architecturalRules", SecurityRule.values().length - SecurityRule.getCoreSecurityRulesCount(),
                "totalRules", SecurityRule.values().length
        ));
    }

    /**
     * POST /api/v1/sentinel/review
     *
     * <p>Analyzes Java source code or filesystem path, evaluates AST security rules,
     * filters by incremental PR diff if provided, and produces verified code patches
     * in JSON or SARIF format.</p>
     */
    @PostMapping(value = "/review", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> review(@RequestBody ReviewFileRequest request) {
        try {
            ReviewReport report;
            boolean hasDiff = request.getDiffContent() != null && !request.getDiffContent().isBlank();

            if (request.getTargetPath() != null && !request.getTargetPath().isBlank()) {
                Path targetPath = Path.of(request.getTargetPath());
                report = hasDiff
                        ? orchestrator.auditPathWithDiff(targetPath, request.getDiffContent())
                        : orchestrator.auditPath(targetPath);
            } else if (request.getSourceCode() != null && !request.getSourceCode().isBlank()) {
                String simPath = (request.getSimulatedFileName() != null && !request.getSimulatedFileName().isBlank())
                        ? request.getSimulatedFileName()
                        : "VulnerableService.java";
                report = hasDiff
                        ? orchestrator.auditSourceCodeWithDiff(request.getSourceCode(), simPath, request.getDiffContent())
                        : orchestrator.auditSourceCode(request.getSourceCode(), simPath);
            } else {
                return ResponseEntity.badRequest().body(Map.of(
                        "error", "Invalid request: must specify either 'targetPath' or 'sourceCode'"
                ));
            }

            if ("sarif".equalsIgnoreCase(request.getFormat())) {
                return ResponseEntity.ok(sarifGenerator.buildSarifModel(report));
            } else if ("github".equalsIgnoreCase(request.getFormat())) {
                return ResponseEntity.ok(reviewCommentBuilder.buildReviewPayload(report));
            }

            return ResponseEntity.ok(report);

        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        } catch (IOException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "File I/O error during audit: " + e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Review pipeline execution failed: " + e.getMessage()));
        }
    }

    /**
     * POST /api/v1/sentinel/review/sarif
     *
     * <p>Executes review and returns schema-compliant OASIS SARIF v2.1.0 output.</p>
     */
    @PostMapping(value = "/review/sarif", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> reviewSarif(@RequestBody ReviewFileRequest request) {
        request.setFormat("sarif");
        return review(request);
    }

    /**
     * POST /api/v1/sentinel/review/github
     *
     * <p>Executes review and returns GitHub PR review payload.</p>
     */
    @PostMapping(value = "/review/github", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> reviewGithub(@RequestBody ReviewFileRequest request) {
        request.setFormat("github");
        return review(request);
    }

    /**
     * POST /api/v1/sentinel/policy/evaluate
     *
     * <p>Evaluates a review report or target path against an enterprise compliance policy.</p>
     */
    @PostMapping(value = "/policy/evaluate", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> evaluatePolicy(@RequestBody PolicyEvaluateRequest request) {
        try {
            ReviewReport report = request.getReport();
            if (report == null && request.getTargetPath() != null && !request.getTargetPath().isBlank()) {
                report = orchestrator.auditPath(Path.of(request.getTargetPath()));
            }

            if (report == null) {
                return ResponseEntity.badRequest().body(Map.of(
                        "error", "Invalid request: must specify either 'report' or 'targetPath'"
                ));
            }

            SentinelPolicy policy = request.getPolicy() != null ? request.getPolicy() : SentinelPolicy.createDefaultStrictPolicy();
            PolicyEvaluationResult result = policyEngine.evaluate(report, policy);
            return ResponseEntity.ok(result);

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Policy evaluation failed: " + e.getMessage()));
        }
    }

    /**
     * GET /api/v1/sentinel/governance/status
     *
     * <p>Returns active enterprise governance configuration, standards compliance, and baseline status.</p>
     */
    @GetMapping("/governance/status")
    public ResponseEntity<Map<String, Object>> governanceStatus() {
        return ResponseEntity.ok(Map.of(
                "status", "ACTIVE",
                "rulesCatalog", SecurityRule.getCoreSecurityRulesCount(),
                "totalRules", SecurityRule.values().length,
                "architecturalRules", SecurityRule.values().length - SecurityRule.getCoreSecurityRulesCount(),
                "defaultPolicy", SentinelPolicy.DEFAULT_POLICY_NAME,
                "baselineEngine", "SentinelBaselineSnapshot v" + com.sentinelpr.core.governance.baseline.BaselineSnapshot.CURRENT_VERSION,
                "complianceStandards", List.of("SOC2-CC7.1", "ISO27001-A.12.6.1", "OWASP-TOP-10", "CWE-SANS-TOP-25"),
                "auditTrailLedger", "SHA-256 Immutable Signature Chain"
        ));
    }
}
