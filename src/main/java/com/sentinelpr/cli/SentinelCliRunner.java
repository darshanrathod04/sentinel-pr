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
import com.sentinelpr.core.export.github.PrReviewCommentBuilder;
import com.sentinelpr.core.export.sarif.SarifReportGenerator;
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
 * executes AST rule evaluation, incremental diff filtering, and verified patch synthesis,
 * with options for SARIF v2.1.0 report generation and PR review payloads.</p>
 */
public class SentinelCliRunner {

    private final SentinelAuditOrchestrator orchestrator;
    private final SarifReportGenerator sarifGenerator;
    private final PrReviewCommentBuilder reviewCommentBuilder;
    private final ObjectMapper objectMapper;

    public SentinelCliRunner() {
        this(createDefaultOrchestrator());
    }

    public SentinelCliRunner(SentinelAuditOrchestrator orchestrator) {
        this(orchestrator, new SarifReportGenerator(), new PrReviewCommentBuilder());
    }

    public SentinelCliRunner(
            SentinelAuditOrchestrator orchestrator,
            SarifReportGenerator sarifGenerator,
            PrReviewCommentBuilder reviewCommentBuilder
    ) {
        this.orchestrator = Objects.requireNonNull(orchestrator, "orchestrator must not be null");
        this.sarifGenerator = Objects.requireNonNull(sarifGenerator, "sarifGenerator must not be null");
        this.reviewCommentBuilder = Objects.requireNonNull(reviewCommentBuilder, "reviewCommentBuilder must not be null");
        this.objectMapper = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .enable(SerializationFeature.INDENT_OUTPUT);
    }

    private static SentinelAuditOrchestrator createDefaultOrchestrator() {
        SentinelClient client = SentinelClient.getInstance();
        CodeInspectionService inspectionService = new CodeInspectionService(client);
        RuleEvaluationService evaluationService = new RuleEvaluationService(client);
        PatchVerifier verifier = new PatchVerifier(inspectionService, evaluationService);
        PatchComposer composer = new PatchComposer(client.developer(), verifier);
        AutomatedPatchService patchService = new AutomatedPatchService(client, composer, verifier);

        return new SentinelAuditOrchestrator(
                inspectionService,
                evaluationService,
                patchService,
                new ReviewSessionMemory(client),
                new SuppressionManager(),
                new DataflowTracker()
        );
    }

    /**
     * Executes review and prints structured JSON report to stdout.
     *
     * @param targetPath path to file or directory
     * @return generated ReviewReport
     */
    public ReviewReport run(Path targetPath) {
        return run(targetPath, null, null, "json");
    }

    /**
     * Executes review with optional incremental diff filtering and report export.
     *
     * @param targetPath      path to file or directory
     * @param diffPath        optional path to unified git diff / patch file
     * @param sarifOutputPath optional path to save SARIF v2.1.0 report
     * @param format          output format (json, sarif, github, text)
     * @return generated ReviewReport
     */
    public ReviewReport run(Path targetPath, Path diffPath, Path sarifOutputPath, String format) {
        try {
            if (!Files.exists(targetPath)) {
                System.err.println("[SentinelPR:CLI] Error: Target path not found: " + targetPath.toAbsolutePath());
                System.exit(1);
            }

            System.out.println("================================================================================");
            System.out.println(" SentinelPR — Enterprise Code & Security Review Copilot");
            System.out.println(" Powered by Shree AI OS (io.github.darshanrathod04:shree-ai-os:1.0.6-developer-preview)");
            System.out.println(" Target: " + targetPath.toAbsolutePath());
            if (diffPath != null) {
                System.out.println(" Diff:   " + diffPath.toAbsolutePath());
            }
            System.out.println("================================================================================");

            ReviewReport report = (diffPath != null && Files.exists(diffPath))
                    ? orchestrator.auditPathWithDiff(targetPath, diffPath)
                    : orchestrator.auditPath(targetPath);

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
                System.out.println("\n--- [Suppressed & Baseline Findings] ---");
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

            // Export SARIF if requested
            if (sarifOutputPath != null) {
                sarifGenerator.exportToFile(report, sarifOutputPath);
                System.out.println("\n[SentinelPR:CLI] SARIF v2.1.0 report exported to: " + sarifOutputPath.toAbsolutePath());
            }

            // Format output to stdout
            String effectiveFormat = format != null ? format.toLowerCase() : "json";
            switch (effectiveFormat) {
                case "sarif" -> {
                    System.out.println("\n--- [OASIS SARIF v2.1.0 Report] ---");
                    System.out.println(sarifGenerator.generateSarifJson(report));
                }
                case "github" -> {
                    System.out.println("\n--- [GitHub PR Review Payload] ---");
                    System.out.println(reviewCommentBuilder.toJson(reviewCommentBuilder.buildReviewPayload(report)));
                }
                case "text" -> {
                    // Summary already logged
                }
                default -> {
                    System.out.println("\n--- [Structured JSON Report] ---");
                    System.out.println(objectMapper.writeValueAsString(report));
                }
            }

            return report;

        } catch (Exception e) {
            System.err.println("[SentinelPR:CLI] Review failed: " + e.getMessage());
            e.printStackTrace(System.err);
            throw new RuntimeException("CLI execution failed", e);
        }
    }

    public static void main(String[] args) {
        if (args.length < 1) {
            printUsage();
            System.exit(1);
        }

        Path target = null;
        Path diffPath = null;
        Path sarifPath = null;
        String format = "json";

        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            if ("--diff".equalsIgnoreCase(arg) && i + 1 < args.length) {
                diffPath = Path.of(args[++i]);
            } else if ("--sarif".equalsIgnoreCase(arg) && i + 1 < args.length) {
                sarifPath = Path.of(args[++i]);
            } else if (("-f".equalsIgnoreCase(arg) || "--format".equalsIgnoreCase(arg)) && i + 1 < args.length) {
                format = args[++i];
            } else if (!arg.startsWith("-")) {
                target = Path.of(arg);
            }
        }

        if (target == null) {
            printUsage();
            System.exit(1);
        }

        SentinelCliRunner runner = new SentinelCliRunner();
        runner.run(target, diffPath, sarifPath, format);
    }

    private static void printUsage() {
        System.out.println("Usage: java -jar sentinel-pr.jar <target-path> [options]");
        System.out.println("Options:");
        System.out.println("  --diff <patch-file>        Enable incremental git diff scanning");
        System.out.println("  --sarif <output-file>      Export OASIS SARIF v2.1.0 report");
        System.out.println("  -f, --format <format>      Output format (json, sarif, github, text) [default: json]");
    }
}
