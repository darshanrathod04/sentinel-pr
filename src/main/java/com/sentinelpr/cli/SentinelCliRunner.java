package com.sentinelpr.cli;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.sentinelpr.client.SentinelClient;
import com.sentinelpr.core.analysis.DataflowTracker;
import com.sentinelpr.core.analysis.SuppressionManager;
import com.sentinelpr.core.model.ReviewReport;
import com.sentinelpr.core.model.SecurityFinding;
import com.sentinelpr.core.model.SuppressedFinding;
import com.sentinelpr.core.model.UnifiedDiffPatch;
import com.sentinelpr.core.service.AutomatedPatchService;
import com.sentinelpr.core.service.CodeInspectionService;
import com.sentinelpr.core.service.PatchComposer;
import com.sentinelpr.core.service.PatchVerifier;
import com.sentinelpr.core.service.ReviewSessionMemory;
import com.sentinelpr.core.service.RuleEvaluationService;
import com.sentinelpr.core.service.SentinelAuditOrchestrator;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;

/**
 * <b>SentinelCliRunner</b>
 *
 * <p>Command-line runner for SentinelPR. Accepts a target Java source file or directory,
 * executes AST rule evaluation and verified patch synthesis, and outputs a structured
 * JSON report.</p>
 */
public class SentinelCliRunner {

    private final SentinelAuditOrchestrator orchestrator;
    private final ObjectMapper objectMapper;

    public SentinelCliRunner() {
        SentinelClient client = SentinelClient.getInstance();
        CodeInspectionService inspectionService = new CodeInspectionService(client);
        RuleEvaluationService evaluationService = new RuleEvaluationService(client);
        PatchVerifier verifier = new PatchVerifier(inspectionService, evaluationService);
        PatchComposer composer = new PatchComposer(client.developer(), verifier);
        AutomatedPatchService patchService = new AutomatedPatchService(client, composer, verifier);

        this.orchestrator = new SentinelAuditOrchestrator(
                inspectionService,
                evaluationService,
                patchService,
                new ReviewSessionMemory(client),
                new SuppressionManager(),
                new DataflowTracker()
        );
        this.objectMapper = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .enable(SerializationFeature.INDENT_OUTPUT);
    }

    public SentinelCliRunner(SentinelAuditOrchestrator orchestrator) {
        this.orchestrator = Objects.requireNonNull(orchestrator, "orchestrator must not be null");
        this.objectMapper = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .enable(SerializationFeature.INDENT_OUTPUT);
    }

    /**
     * Executes review and prints structured JSON report to stdout.
     *
     * @param targetPath path to file or directory
     * @return generated ReviewReport
     */
    public ReviewReport run(Path targetPath) {
        try {
            if (!Files.exists(targetPath)) {
                System.err.println("[SentinelPR:CLI] Error: Target path not found: " + targetPath.toAbsolutePath());
                System.exit(1);
            }

            System.out.println("================================================================================");
            System.out.println(" SentinelPR — Enterprise Code & Security Review Copilot");
            System.out.println(" Powered by Shree AI OS (io.github.darshanrathod04:shree-ai-os:1.0.6-developer-preview)");
            System.out.println(" Target: " + targetPath.toAbsolutePath());
            System.out.println("================================================================================");

            ReviewReport report = orchestrator.auditPath(targetPath);

            System.out.println("\n--- [Audit Execution Summary] ---");
            System.out.println("Status:          " + report.getStatus());
            System.out.println("Files Scanned:   " + report.getScannedFileCount());
            System.out.println("Vulnerabilities: " + report.getVulnerabilityCount());
            System.out.println("Suppressed:      " + report.getSuppressedCount());
            System.out.println("Patches Created: " + report.getPatches().size());
            System.out.println("Cached Session:  " + report.isCachedAudit());
            System.out.println("Message:         " + report.getSummary());

            if (!report.getFindings().isEmpty()) {
                System.out.println("\n--- [Detected Vulnerabilities] ---");
                for (SecurityFinding f : report.getFindings()) {
                    System.out.printf("  [%s] %s (%s:%d-%d)%n",
                            f.getSeverity(), f.getDescription(), f.getTargetFile(), f.getStartLine(), f.getEndLine());
                    System.out.println("    Rationale:   " + f.getCausalRationale());
                    System.out.println("    Remediation: " + f.getRemediation());
                }
            }

            if (!report.getSuppressedFindings().isEmpty()) {
                System.out.println("\n--- [Suppressed Findings] ---");
                for (SuppressedFinding sf : report.getSuppressedFindings()) {
                    System.out.printf("  [SUPPRESSED via %s] %s (%s:%d-%d)%n",
                            sf.getSuppressionType(), sf.getFinding().getDescription(),
                            sf.getFinding().getTargetFile(), sf.getFinding().getStartLine(), sf.getFinding().getEndLine());
                    System.out.println("    Matched Reason: " + sf.getMatchedReason());
                }
            }

            if (!report.getPatches().isEmpty()) {
                System.out.println("\n--- [Synthesized Verified Patches (Unified Diff)] ---");
                for (UnifiedDiffPatch p : report.getPatches()) {
                    System.out.printf("  Patch for [%s] -> Status: %s (Verified: %s, RegressionVerified: %s)%n",
                            p.getRuleId(), p.getStatus(), p.isVerified(), p.isRegressionVerified());
                    System.out.println(p.getUnifiedDiff());
                }
            }

            System.out.println("\n--- [Structured JSON Report] ---");
            String jsonOutput = objectMapper.writeValueAsString(report);
            System.out.println(jsonOutput);

            return report;

        } catch (Exception e) {
            System.err.println("[SentinelPR:CLI] Review failed: " + e.getMessage());
            e.printStackTrace(System.err);
            throw new RuntimeException("CLI execution failed", e);
        }
    }

    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Usage: java -jar sentinel-pr.jar <path-to-java-file-or-directory>");
            System.exit(1);
        }

        Path target = Path.of(args[0]);
        SentinelCliRunner runner = new SentinelCliRunner();
        runner.run(target);
    }
}
