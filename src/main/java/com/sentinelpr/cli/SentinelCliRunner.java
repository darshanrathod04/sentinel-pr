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
import com.sentinelpr.core.governance.audit.AuditTrailEntry;
import com.sentinelpr.core.governance.audit.AuditTrailLogger;
import com.sentinelpr.core.governance.baseline.BaselineManager;
import com.sentinelpr.core.governance.policy.PolicyEngine;
import com.sentinelpr.core.governance.policy.PolicyEvaluationResult;
import com.sentinelpr.core.governance.policy.SentinelPolicy;
import com.sentinelpr.core.service.AutomatedPatchService;
import com.sentinelpr.core.service.CodeInspectionService;
import com.sentinelpr.core.service.PatchComposer;
import com.sentinelpr.core.service.PatchVerifier;
import com.sentinelpr.core.service.ReviewSessionMemory;
import com.sentinelpr.core.service.RuleEvaluationService;
import com.sentinelpr.core.service.SentinelAuditOrchestrator;
import com.shreeai.os.platform.sdk.SDKResponse;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Objects;

/**
 * <b>SentinelCliRunner</b>
 *
 * <p>Command-line runner for SentinelPR. Accepts a target Java source file or directory,
 * executes AST rule evaluation, incremental diff filtering, technical debt baseline tracking,
 * verified patch synthesis, enterprise policy enforcement, and cryptographic audit trail logging.</p>
 */
public class SentinelCliRunner {

    private final SentinelAuditOrchestrator orchestrator;
    private final SarifReportGenerator sarifGenerator;
    private final PrReviewCommentBuilder reviewCommentBuilder;
    private final BaselineManager baselineManager;
    private final PolicyEngine policyEngine;
    private final AuditTrailLogger auditTrailLogger;
    private final com.sentinelpr.client.MemoryFacade memoryFacade;
    private final ObjectMapper objectMapper;

    public SentinelCliRunner() {
        this(createDefaultOrchestrator());
    }

    public SentinelCliRunner(SentinelAuditOrchestrator orchestrator) {
        this(orchestrator, new SarifReportGenerator(), new PrReviewCommentBuilder(), new BaselineManager(), new PolicyEngine(), new AuditTrailLogger());
    }

    public SentinelCliRunner(
            SentinelAuditOrchestrator orchestrator,
            SarifReportGenerator sarifGenerator,
            PrReviewCommentBuilder reviewCommentBuilder
    ) {
        this(orchestrator, sarifGenerator, reviewCommentBuilder, new BaselineManager(), new PolicyEngine(), new AuditTrailLogger());
    }

    public SentinelCliRunner(
            SentinelAuditOrchestrator orchestrator,
            SarifReportGenerator sarifGenerator,
            PrReviewCommentBuilder reviewCommentBuilder,
            BaselineManager baselineManager,
            PolicyEngine policyEngine,
            AuditTrailLogger auditTrailLogger
    ) {
        this(orchestrator, sarifGenerator, reviewCommentBuilder, baselineManager, policyEngine, auditTrailLogger, SentinelClient.getInstance().memoryFacade());
    }

    public SentinelCliRunner(
            SentinelAuditOrchestrator orchestrator,
            SarifReportGenerator sarifGenerator,
            PrReviewCommentBuilder reviewCommentBuilder,
            BaselineManager baselineManager,
            PolicyEngine policyEngine,
            AuditTrailLogger auditTrailLogger,
            com.sentinelpr.client.MemoryFacade memoryFacade
    ) {
        this.orchestrator = Objects.requireNonNull(orchestrator, "orchestrator must not be null");
        this.sarifGenerator = Objects.requireNonNull(sarifGenerator, "sarifGenerator must not be null");
        this.reviewCommentBuilder = Objects.requireNonNull(reviewCommentBuilder, "reviewCommentBuilder must not be null");
        this.baselineManager = Objects.requireNonNull(baselineManager, "baselineManager must not be null");
        this.policyEngine = Objects.requireNonNull(policyEngine, "policyEngine must not be null");
        this.auditTrailLogger = Objects.requireNonNull(auditTrailLogger, "auditTrailLogger must not be null");
        this.memoryFacade = Objects.requireNonNull(memoryFacade, "memoryFacade must not be null");
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

    public static class CliExecutionResult {
        private final int exitCode;
        private final ReviewReport report;
        private final PolicyEvaluationResult policyResult;
        private final AuditTrailEntry auditEntry;

        public CliExecutionResult(int exitCode, ReviewReport report, PolicyEvaluationResult policyResult, AuditTrailEntry auditEntry) {
            this.exitCode = exitCode;
            this.report = report;
            this.policyResult = policyResult;
            this.auditEntry = auditEntry;
        }

        public int getExitCode() {
            return exitCode;
        }

        public ReviewReport getReport() {
            return report;
        }

        public PolicyEvaluationResult getPolicyResult() {
            return policyResult;
        }

        public AuditTrailEntry getAuditEntry() {
            return auditEntry;
        }
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
        return run(targetPath, diffPath, null, null, null, sarifOutputPath, null, format);
    }

    /**
     * Executes review with full governance suite options.
     */
    public ReviewReport run(
            Path targetPath,
            Path diffPath,
            Path baselinePath,
            Path createBaselinePath,
            Path policyPath,
            Path sarifOutputPath,
            Path auditLogPath,
            String format
    ) {
        CliExecutionResult result = execute(targetPath, diffPath, baselinePath, createBaselinePath, policyPath, sarifOutputPath, auditLogPath, format);
        if (result.getExitCode() == 2) {
            throw new RuntimeException("CLI execution failed");
        }
        return result.getReport();
    }

    /**
     * Executes review with full governance evaluation, returning structured {@link CliExecutionResult}.
     */
    public CliExecutionResult execute(
            Path targetPath,
            Path diffPath,
            Path baselinePath,
            Path createBaselinePath,
            Path policyPath,
            Path sarifOutputPath,
            Path auditLogPath,
            String format
    ) {
        long startTime = System.currentTimeMillis();
        try {
            if (targetPath == null || !Files.exists(targetPath)) {
                System.err.println("[SentinelPR:CLI] Error: Target path not found: " + (targetPath != null ? targetPath.toAbsolutePath() : "null"));
                return new CliExecutionResult(3, null, null, null);
            }

            System.out.println("================================================================================");
            System.out.println(" SentinelPR — Enterprise Code & Security Review Copilot");
            System.out.println(" Powered by Shree AI OS (io.github.darshanrathod04:shree-ai-os:1.0.6-developer-preview)");
            System.out.println(" Target: " + targetPath.toAbsolutePath());
            if (diffPath != null) {
                System.out.println(" Diff:   " + diffPath.toAbsolutePath());
            }
            if (baselinePath != null) {
                System.out.println(" Baseline: " + baselinePath.toAbsolutePath());
            }
            if (policyPath != null) {
                System.out.println(" Policy:   " + policyPath.toAbsolutePath());
            }
            System.out.println("================================================================================");

            // Pre-load policy if specified
            SentinelPolicy policy = null;
            if (policyPath != null && Files.exists(policyPath)) {
                policy = policyEngine.loadPolicy(policyPath);
            }

            // Audit dispatch
            ReviewReport report;
            if (diffPath != null && Files.exists(diffPath) && baselinePath != null && Files.exists(baselinePath)) {
                report = orchestrator.auditPathWithDiffAndBaseline(targetPath, Files.readString(diffPath), baselinePath, policy);
            } else if (baselinePath != null && Files.exists(baselinePath)) {
                report = orchestrator.auditPathWithBaseline(targetPath, baselinePath, policy);
            } else if (diffPath != null && Files.exists(diffPath)) {
                report = orchestrator.auditPathWithDiff(targetPath, diffPath);
            } else {
                report = orchestrator.auditPath(targetPath);
            }

            // Policy evaluation
            PolicyEvaluationResult policyResult = null;
            int exitCode = 0;
            if (policy != null) {
                policyResult = policyEngine.evaluate(report, policy);
                exitCode = policyResult.getExitCode();
            }

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

            // Export baseline snapshot if requested
            if (createBaselinePath != null) {
                baselineManager.exportBaseline(report, createBaselinePath);
                System.out.println("\n[SentinelPR:CLI] Baseline snapshot captured to: " + createBaselinePath.toAbsolutePath());
            }

            // Export SARIF if requested
            if (sarifOutputPath != null) {
                sarifGenerator.exportToFile(report, sarifOutputPath);
                System.out.println("\n[SentinelPR:CLI] SARIF v2.1.0 report exported to: " + sarifOutputPath.toAbsolutePath());
            }

            // Output format to stdout
            String effectiveFormat = format != null ? format.toLowerCase() : "json";
            switch (effectiveFormat) {
                case "sarif" -> {
                    System.out.println("\n--- [OASIS SARIF v2.1.0 Report] ---");
                    System.out.println(sarifGenerator.generateSarifJson(report));
                }
                case "github" -> {
                    System.out.println("\n--- [GitHub PR Review Payload] ---");
                    System.out.println(reviewCommentBuilder.toJson(reviewCommentBuilder.buildReviewPayload(report, policyResult, "HEAD")));
                }
                case "text" -> {
                    // Summary already logged
                }
                default -> {
                    System.out.println("\n--- [Structured JSON Report] ---");
                    System.out.println(objectMapper.writeValueAsString(report));
                }
            }

            if (policyResult != null) {
                if (policyResult.isBreached()) {
                    System.err.println("\n--- [Enterprise Policy Evaluation: BREACHED] ---");
                    System.err.println(policyResult.getSummary());
                    for (String violation : policyResult.getViolations()) {
                        System.err.println("  ❌ " + violation);
                    }
                } else {
                    System.out.println("\n--- [Enterprise Policy Evaluation: " + policyResult.getStatus() + "] ---");
                    System.out.println(policyResult.getSummary());
                }
            }

            // Cryptographic audit log
            AuditTrailEntry auditEntry = null;
            if (auditLogPath != null) {
                auditEntry = auditTrailLogger.createAuditEntry(report, policyResult, "HEAD", "main", null);
                auditTrailLogger.appendAuditLog(auditEntry, auditLogPath);
                System.out.println("\n[SentinelPR:CLI] Cryptographic audit trail appended to: " + auditLogPath.toAbsolutePath());
            }

            // Record audit session metadata into Memory Kernel (strictly metadata, no raw code or patches)
            long durationMs = System.currentTimeMillis() - startTime;
            memoryFacade.recordSession(report, policyResult, durationMs);

            return new CliExecutionResult(exitCode, report, policyResult, auditEntry);

        } catch (Exception e) {
            System.err.println("[SentinelPR:CLI] Execution error: " + e.getMessage());
            e.printStackTrace(System.err);
            return new CliExecutionResult(2, null, null, null);
        }
    }

    /**
     * Executes CLI from command-line arguments string array, returning process exit code:
     * <ul>
     *   <li>0: Audit passed & policy compliant (PASSED or PASSED_WITH_BASELINE), or History displayed</li>
     *   <li>1: Policy breached (defect thresholds / blocked rules)</li>
     *   <li>2: Internal engine error</li>
     *   <li>3: Invalid CLI arguments or non-existent target path</li>
     *   <li>4: Patch generation / verification failure</li>
     * </ul>
     */
    public int execute(String[] args) {
        if (args == null || args.length < 1) {
            printUsage();
            return 3;
        }

        boolean isHistory = false;
        String historyRunId = null;
        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            if ("--history".equalsIgnoreCase(arg) || "history".equalsIgnoreCase(arg)) {
                isHistory = true;
            } else if ("--run".equalsIgnoreCase(arg) && i + 1 < args.length) {
                historyRunId = args[++i];
            }
        }

        if (isHistory || historyRunId != null) {
            if (historyRunId != null) {
                System.out.println(memoryFacade.formatSessionDetail(historyRunId));
            } else {
                System.out.println(memoryFacade.formatHistoryTable());
            }
            return 0;
        }

        // Chat mode (Gemini BYOK) — must be detected before target-path parsing.
        // The entire remaining text after --chat is treated as one prompt.
        for (int i = 0; i < args.length; i++) {
            if ("--chat".equalsIgnoreCase(args[i])) {
                return executeChat(Arrays.copyOfRange(args, i + 1, args.length));
            }
        }

        Path target = null;
        Path diffPath = null;
        Path baselinePath = null;
        Path createBaselinePath = null;
        Path policyPath = null;
        Path sarifPath = null;
        Path auditLogPath = null;
        String format = "json";

        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            if ("--diff".equalsIgnoreCase(arg) && i + 1 < args.length) {
                diffPath = Path.of(args[++i]);
            } else if ("--baseline".equalsIgnoreCase(arg) && i + 1 < args.length) {
                baselinePath = Path.of(args[++i]);
            } else if ("--create-baseline".equalsIgnoreCase(arg) && i + 1 < args.length) {
                createBaselinePath = Path.of(args[++i]);
            } else if ("--policy".equalsIgnoreCase(arg) && i + 1 < args.length) {
                policyPath = Path.of(args[++i]);
            } else if ("--sarif".equalsIgnoreCase(arg) && i + 1 < args.length) {
                sarifPath = Path.of(args[++i]);
            } else if ("--audit-log".equalsIgnoreCase(arg) && i + 1 < args.length) {
                auditLogPath = Path.of(args[++i]);
            } else if (("-f".equalsIgnoreCase(arg) || "--format".equalsIgnoreCase(arg)) && i + 1 < args.length) {
                format = args[++i];
            } else if (!arg.startsWith("-")) {
                target = Path.of(arg);
            }
        }

        if (target == null) {
            printUsage();
            return 3;
        }

        CliExecutionResult result = execute(target, diffPath, baselinePath, createBaselinePath, policyPath, sarifPath, auditLogPath, format);
        return result.getExitCode();
    }

    public static void main(String[] args) {
        SentinelCliRunner runner = new SentinelCliRunner();
        int exitCode = runner.execute(args);
        System.exit(exitCode);
    }

    /**
     * Executes the SentinelPR AI assistant chat command (Gemini BYOK) via the
     * Shree AI OS LLM router and prints the model response.
     *
     * @param promptArgs remaining command-line arguments after --chat
     * @return 0 on success, 3 when the prompt is missing or blank
     */
    private int executeChat(String[] promptArgs) {
        String prompt = (promptArgs == null) ? "" : String.join(" ", promptArgs).trim();
        if (prompt.isEmpty()) {
            System.out.println("Error: Missing chat prompt.");
            System.out.println("Usage:");
            System.out.println("  sentinel --chat \"your question\"");
            return 3;
        }

        System.out.println("================================================");
        System.out.println(" SentinelPR AI Assistant");
        System.out.println(" Provider: Gemini (BYOK)");
        System.out.println("================================================");
        System.out.println();

        SDKResponse response = SentinelClient.getInstance().chat(prompt);
        System.out.println(response.answer());
        return 0;
    }

    private static void printUsage() {
        System.out.println("Usage: java -jar sentinel-pr.jar <target-path> [options]");
        System.out.println("Options:");
        System.out.println("  --diff <patch-file>            Enable incremental git diff scanning");
        System.out.println("  --baseline <baseline-file>     Filter findings against technical debt baseline");
        System.out.println("  --create-baseline <out.json>   Export findings as technical debt baseline snapshot");
        System.out.println("  --policy <policy-file>         Enforce enterprise compliance policy thresholds");
        System.out.println("  --sarif <output-file>          Export OASIS SARIF v2.1.0 report");
        System.out.println("  --audit-log <ledger.log>       Append signed cryptographic SOC2/ISO27001 audit entry");
        System.out.println("  --history                      Display review session history from Memory Kernel");
        System.out.println("  --run <run-id>                 Inspect detailed metadata for a specific review session");
        System.out.println("  -f, --format <format>          Output format (json, sarif, github, text) [default: json]");
        System.out.println("  --chat \"<prompt>\"            Ask SentinelPR AI assistant (Gemini BYOK)");
    }

    public com.sentinelpr.client.MemoryFacade getMemoryFacade() {
        return memoryFacade;
    }

    public BaselineManager getBaselineManager() {
        return baselineManager;
    }

    public PolicyEngine getPolicyEngine() {
        return policyEngine;
    }

    public AuditTrailLogger getAuditTrailLogger() {
        return auditTrailLogger;
    }
}
