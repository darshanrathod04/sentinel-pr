package com.sentinelpr.core.service;

import com.sentinelpr.core.analysis.DataflowTracker;
import com.sentinelpr.core.analysis.SuppressionManager;
import com.sentinelpr.core.analysis.SuppressionResult;
import com.sentinelpr.core.analysis.calibration.ConfidenceCalibrator;
import com.sentinelpr.core.analysis.causal.CausalAnalysisEngine;
import com.sentinelpr.core.model.CoordinatedPatchPlan;
import com.sentinelpr.core.model.InspectedSource;
import com.sentinelpr.core.model.ReviewReport;
import com.sentinelpr.core.model.SecurityFinding;
import com.sentinelpr.core.model.SuppressedFinding;
import com.sentinelpr.core.model.UnifiedDiffPatch;
import com.sentinelpr.core.analysis.diff.IncrementalDiffScanner;
import com.sentinelpr.core.analysis.diff.IncrementalDiffScanner.FileDiff;
import com.sentinelpr.core.governance.baseline.BaselineEntry;
import com.sentinelpr.core.governance.baseline.BaselineManager;
import com.sentinelpr.core.governance.baseline.BaselineSnapshot;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * <b>SentinelAuditOrchestrator</b>
 *
 * <p>Coordinates the complete end-to-end security review pipeline:</p>
 * <ol>
 *   <li>Inspection via AST parser</li>
 *   <li>Session memory deduplication check</li>
 *   <li>Rule reasoning and vulnerability evaluation</li>
 *   <li>False positive suppression engine (annotations, inline comments, .sentinelignore)</li>
 *   <li>Incremental PR diff filtering (diff baseline separation)</li>
 *   <li>Enterprise technical debt baseline evaluation (BASELINE_ACCEPTED)</li>
 *   <li>Deep cognitive causal analysis (CausalAnalysisEngine) & confidence calibration</li>
 *   <li>Atomic patch composition, multi-file coordinated planning, and regression verification</li>
 *   <li>Session memory persistence</li>
 * </ol>
 */
@Service
public class SentinelAuditOrchestrator {

    private final CodeInspectionService inspectionService;
    private final RuleEvaluationService evaluationService;
    private final AutomatedPatchService patchService;
    private final ReviewSessionMemory sessionMemory;
    private final SuppressionManager suppressionManager;
    private final DataflowTracker dataflowTracker;
    private final IncrementalDiffScanner diffScanner;
    private final BaselineManager baselineManager;
    private final CausalAnalysisEngine causalAnalysisEngine;
    private final ConfidenceCalibrator confidenceCalibrator;
    private final MultiFileFixPlanner multiFileFixPlanner;

    public SentinelAuditOrchestrator(
            CodeInspectionService inspectionService,
            RuleEvaluationService evaluationService,
            AutomatedPatchService patchService,
            ReviewSessionMemory sessionMemory
    ) {
        this(inspectionService, evaluationService, patchService, sessionMemory, new SuppressionManager(), new DataflowTracker(), new IncrementalDiffScanner(), new BaselineManager());
    }

    public SentinelAuditOrchestrator(
            CodeInspectionService inspectionService,
            RuleEvaluationService evaluationService,
            AutomatedPatchService patchService,
            ReviewSessionMemory sessionMemory,
            SuppressionManager suppressionManager,
            DataflowTracker dataflowTracker
    ) {
        this(inspectionService, evaluationService, patchService, sessionMemory, suppressionManager, dataflowTracker, new IncrementalDiffScanner(), new BaselineManager());
    }

    public SentinelAuditOrchestrator(
            CodeInspectionService inspectionService,
            RuleEvaluationService evaluationService,
            AutomatedPatchService patchService,
            ReviewSessionMemory sessionMemory,
            SuppressionManager suppressionManager,
            DataflowTracker dataflowTracker,
            IncrementalDiffScanner diffScanner
    ) {
        this(inspectionService, evaluationService, patchService, sessionMemory, suppressionManager, dataflowTracker, diffScanner, new BaselineManager());
    }

    public SentinelAuditOrchestrator(
            CodeInspectionService inspectionService,
            RuleEvaluationService evaluationService,
            AutomatedPatchService patchService,
            ReviewSessionMemory sessionMemory,
            SuppressionManager suppressionManager,
            DataflowTracker dataflowTracker,
            IncrementalDiffScanner diffScanner,
            BaselineManager baselineManager
    ) {
        this(inspectionService, evaluationService, patchService, sessionMemory, suppressionManager, dataflowTracker, diffScanner, baselineManager,
                new CausalAnalysisEngine(), new ConfidenceCalibrator(), new MultiFileFixPlanner());
    }

    public SentinelAuditOrchestrator(
            CodeInspectionService inspectionService,
            RuleEvaluationService evaluationService,
            AutomatedPatchService patchService,
            ReviewSessionMemory sessionMemory,
            SuppressionManager suppressionManager,
            DataflowTracker dataflowTracker,
            IncrementalDiffScanner diffScanner,
            BaselineManager baselineManager,
            CausalAnalysisEngine causalAnalysisEngine,
            ConfidenceCalibrator confidenceCalibrator,
            MultiFileFixPlanner multiFileFixPlanner
    ) {
        this.inspectionService = Objects.requireNonNull(inspectionService, "inspectionService must not be null");
        this.evaluationService = Objects.requireNonNull(evaluationService, "evaluationService must not be null");
        this.patchService = Objects.requireNonNull(patchService, "patchService must not be null");
        this.sessionMemory = Objects.requireNonNull(sessionMemory, "sessionMemory must not be null");
        this.suppressionManager = Objects.requireNonNull(suppressionManager, "suppressionManager must not be null");
        this.dataflowTracker = Objects.requireNonNull(dataflowTracker, "dataflowTracker must not be null");
        this.diffScanner = Objects.requireNonNull(diffScanner, "diffScanner must not be null");
        this.baselineManager = Objects.requireNonNull(baselineManager, "baselineManager must not be null");
        this.causalAnalysisEngine = Objects.requireNonNull(causalAnalysisEngine, "causalAnalysisEngine must not be null");
        this.confidenceCalibrator = Objects.requireNonNull(confidenceCalibrator, "confidenceCalibrator must not be null");
        this.multiFileFixPlanner = Objects.requireNonNull(multiFileFixPlanner, "multiFileFixPlanner must not be null");
    }

    /**
     * Executes a full review on a target file or directory.
     */
    public ReviewReport auditPath(Path targetPath) throws IOException {
        Objects.requireNonNull(targetPath, "targetPath must not be null");
        String reportId = "REV-" + UUID.randomUUID().toString().substring(0, 8);

        if (!Files.exists(targetPath)) {
            throw new IllegalArgumentException("Target path does not exist: " + targetPath);
        }

        // If single file, check session memory first
        if (Files.isRegularFile(targetPath)) {
            String rawContent = Files.readString(targetPath);
            String fingerprint = sessionMemory.computeFingerprint(rawContent);

            if (sessionMemory.hasPreviousAudit(fingerprint)) {
                ReviewReport cached = sessionMemory.getPreviousAudit(fingerprint);
                if (cached != null) {
                    return new ReviewReport(
                            reportId,
                            Instant.now(),
                            targetPath.toString(),
                            cached.getScannedFileCount(),
                            cached.getVulnerabilityCount(),
                            cached.getStatus(),
                            true,
                            "Session Memory Hit: Unchanged file retrieved from previous audit run without re-evaluating rules.",
                            cached.getFindings(),
                            cached.getSuppressedFindings(),
                            cached.getPatches()
                    );
                }
            }
        }

        // Inspect AST
        List<InspectedSource> sources = inspectionService.inspectPath(targetPath);

        List<SecurityFinding> allActiveFindings = new ArrayList<>();
        List<SuppressedFinding> allSuppressedFindings = new ArrayList<>();
        List<UnifiedDiffPatch> allPatches = new ArrayList<>();

        for (InspectedSource source : sources) {
            List<SecurityFinding> rawFindings = evaluationService.evaluate(source, sources);

            List<SecurityFinding> activeSourceFindings = new ArrayList<>();
            for (SecurityFinding raw : rawFindings) {
                SecurityFinding enriched = causalAnalysisEngine.enrichFinding(raw, source);
                ConfidenceCalibrator.CalibrationResult cal = confidenceCalibrator.calibrate(enriched, source);
                SecurityFinding finding = enriched.withCalibratedConfidence(cal.getScore(), cal.getExploitabilityIndex());

                if (cal.isLowConfidence()) {
                    String reason = String.format("Calibrated confidence score (%.2f) below threshold (%.2f)",
                            cal.getScore(), confidenceCalibrator.getMinConfidenceThreshold());
                    allSuppressedFindings.add(new SuppressedFinding(finding, reason, ConfidenceCalibrator.LOW_CONFIDENCE_SUPPRESSION_TYPE));
                } else {
                    SuppressionResult sup = suppressionManager.evaluateSuppression(finding, source, targetPath);
                    if (sup.isSuppressed()) {
                        allSuppressedFindings.add(new SuppressedFinding(finding, sup.getReason(), sup.getType()));
                    } else {
                        activeSourceFindings.add(finding);
                    }
                }
            }

            allActiveFindings.addAll(activeSourceFindings);

            if (!activeSourceFindings.isEmpty()) {
                List<UnifiedDiffPatch> patches = patchService.generatePatches(source, activeSourceFindings);
                allPatches.addAll(patches);
            }
        }

        String status = "SUCCESS";
        String summary = String.format(
                "Audit completed. Scanned %d source file(s), identified %d vulnerability finding(s) (%d suppressed), synthesized %d verified patch(es).",
                sources.size(), allActiveFindings.size(), allSuppressedFindings.size(), allPatches.size()
        );

        ReviewReport report = new ReviewReport(
                reportId,
                Instant.now(),
                targetPath.toString(),
                sources.size(),
                allActiveFindings.size(),
                status,
                false,
                summary,
                allActiveFindings,
                allSuppressedFindings,
                allPatches
        );

        // Record in session memory if single file
        if (Files.isRegularFile(targetPath)) {
            String rawContent = Files.readString(targetPath);
            String fingerprint = sessionMemory.computeFingerprint(rawContent);
            sessionMemory.recordAuditRun(fingerprint, report);
        }

        return report;
    }

    /**
     * Executes review on raw source code.
     */
    public ReviewReport auditSourceCode(String sourceCode, String simulatedPath) {
        Objects.requireNonNull(sourceCode, "sourceCode must not be null");
        String reportId = "REV-" + UUID.randomUUID().toString().substring(0, 8);
        String fingerprint = sessionMemory.computeFingerprint(sourceCode);

        if (sessionMemory.hasPreviousAudit(fingerprint)) {
            ReviewReport cached = sessionMemory.getPreviousAudit(fingerprint);
            if (cached != null) {
                return new ReviewReport(
                        reportId,
                        Instant.now(),
                        simulatedPath,
                        1,
                        cached.getVulnerabilityCount(),
                        cached.getStatus(),
                        true,
                        "Session Memory Hit: Unchanged source code retrieved from previous audit run.",
                        cached.getFindings(),
                        cached.getSuppressedFindings(),
                        cached.getPatches()
                );
            }
        }

        InspectedSource source = inspectionService.inspectSourceCode(sourceCode, simulatedPath);
        List<SecurityFinding> rawFindings = evaluationService.evaluate(source);

        List<SecurityFinding> activeFindings = new ArrayList<>();
        List<SuppressedFinding> suppressedFindings = new ArrayList<>();

        for (SecurityFinding finding : rawFindings) {
            SuppressionResult sup = suppressionManager.evaluateSuppression(finding, source, null);
            if (sup.isSuppressed()) {
                suppressedFindings.add(new SuppressedFinding(finding, sup.getReason(), sup.getType()));
            } else {
                activeFindings.add(finding);
            }
        }

        List<UnifiedDiffPatch> patches = patchService.generatePatches(source, activeFindings);

        String summary = String.format(
                "Audit completed for %s. Identified %d finding(s) (%d suppressed), generated %d patch(es).",
                simulatedPath, activeFindings.size(), suppressedFindings.size(), patches.size()
        );

        ReviewReport report = new ReviewReport(
                reportId,
                Instant.now(),
                simulatedPath,
                1,
                activeFindings.size(),
                "SUCCESS",
                false,
                summary,
                activeFindings,
                suppressedFindings,
                patches
        );

        sessionMemory.recordAuditRun(fingerprint, report);
        return report;
    }

    /**
     * Executes review on a target file or directory with incremental diff filtering.
     * Only findings touching the modified hunks of the diff remain active;
     * older pre-existing findings outside the diff are marked as baseline.
     */
    public ReviewReport auditPathWithDiff(Path targetPath, String diffContent) throws IOException {
        Objects.requireNonNull(targetPath, "targetPath must not be null");
        if (diffContent == null || diffContent.isBlank()) {
            return auditPath(targetPath);
        }

        String reportId = "REV-" + UUID.randomUUID().toString().substring(0, 8);
        if (!Files.exists(targetPath)) {
            throw new IllegalArgumentException("Target path does not exist: " + targetPath);
        }

        Map<String, FileDiff> diffs = diffScanner.parse(diffContent);
        List<InspectedSource> sources = inspectionService.inspectPath(targetPath);

        List<SecurityFinding> allActiveFindings = new ArrayList<>();
        List<SuppressedFinding> allSuppressedFindings = new ArrayList<>();
        List<UnifiedDiffPatch> allPatches = new ArrayList<>();

        for (InspectedSource source : sources) {
            List<SecurityFinding> rawFindings = evaluationService.evaluate(source, sources);

            List<SecurityFinding> activeSourceFindings = new ArrayList<>();
            for (SecurityFinding raw : rawFindings) {
                SecurityFinding enriched = causalAnalysisEngine.enrichFinding(raw, source);
                ConfidenceCalibrator.CalibrationResult cal = confidenceCalibrator.calibrate(enriched, source);
                SecurityFinding finding = enriched.withCalibratedConfidence(cal.getScore(), cal.getExploitabilityIndex());

                if (cal.isLowConfidence()) {
                    String reason = String.format("Calibrated confidence score (%.2f) below threshold (%.2f)",
                            cal.getScore(), confidenceCalibrator.getMinConfidenceThreshold());
                    allSuppressedFindings.add(new SuppressedFinding(finding, reason, ConfidenceCalibrator.LOW_CONFIDENCE_SUPPRESSION_TYPE));
                } else {
                    SuppressionResult sup = suppressionManager.evaluateSuppression(finding, source, targetPath);
                    if (sup.isSuppressed()) {
                        allSuppressedFindings.add(new SuppressedFinding(finding, sup.getReason(), sup.getType()));
                    } else if (diffScanner.isFindingInDiff(finding, diffs)) {
                        activeSourceFindings.add(finding);
                    } else {
                        allSuppressedFindings.add(new SuppressedFinding(
                                finding,
                                "Baseline finding outside incremental PR diff range",
                                "DIFF_BASELINE"
                        ));
                    }
                }
            }

            allActiveFindings.addAll(activeSourceFindings);

            if (!activeSourceFindings.isEmpty()) {
                List<UnifiedDiffPatch> patches = patchService.generatePatches(source, activeSourceFindings);
                allPatches.addAll(patches);
            }
        }

        String status = "SUCCESS";
        String summary = String.format(
                "Incremental diff audit completed. Scanned %d source file(s), identified %d active PR vulnerability finding(s) (%d suppressed/baseline), synthesized %d verified patch(es).",
                sources.size(), allActiveFindings.size(), allSuppressedFindings.size(), allPatches.size()
        );

        return new ReviewReport(
                reportId,
                Instant.now(),
                targetPath.toString(),
                sources.size(),
                allActiveFindings.size(),
                status,
                false,
                summary,
                allActiveFindings,
                allSuppressedFindings,
                allPatches
        );
    }

    public ReviewReport auditPathWithDiff(Path targetPath, Path diffFile) throws IOException {
        Objects.requireNonNull(diffFile, "diffFile must not be null");
        if (!Files.exists(diffFile)) {
            throw new IllegalArgumentException("Diff file does not exist: " + diffFile);
        }
        return auditPathWithDiff(targetPath, Files.readString(diffFile));
    }

    /**
     * Executes review on raw source code with incremental diff filtering.
     */
    public ReviewReport auditSourceCodeWithDiff(String sourceCode, String simulatedPath, String diffContent) {
        Objects.requireNonNull(sourceCode, "sourceCode must not be null");
        if (diffContent == null || diffContent.isBlank()) {
            return auditSourceCode(sourceCode, simulatedPath);
        }

        String reportId = "REV-" + UUID.randomUUID().toString().substring(0, 8);
        Map<String, FileDiff> diffs = diffScanner.parse(diffContent);
        InspectedSource source = inspectionService.inspectSourceCode(sourceCode, simulatedPath);
        List<SecurityFinding> rawFindings = evaluationService.evaluate(source);

        List<SecurityFinding> activeFindings = new ArrayList<>();
        List<SuppressedFinding> suppressedFindings = new ArrayList<>();

        for (SecurityFinding finding : rawFindings) {
            SuppressionResult sup = suppressionManager.evaluateSuppression(finding, source, null);
            if (sup.isSuppressed()) {
                suppressedFindings.add(new SuppressedFinding(finding, sup.getReason(), sup.getType()));
            } else if (diffScanner.isFindingInDiff(finding, diffs)) {
                activeFindings.add(finding);
            } else {
                suppressedFindings.add(new SuppressedFinding(
                        finding,
                        "Baseline finding outside incremental PR diff range",
                        "DIFF_BASELINE"
                ));
            }
        }

        List<UnifiedDiffPatch> patches = patchService.generatePatches(source, activeFindings);

        String summary = String.format(
                "Incremental audit completed for %s. Identified %d active finding(s) (%d suppressed/baseline), generated %d patch(es).",
                simulatedPath, activeFindings.size(), suppressedFindings.size(), patches.size()
        );

        return new ReviewReport(
                reportId,
                Instant.now(),
                simulatedPath,
                1,
                activeFindings.size(),
                "SUCCESS",
                false,
                summary,
                activeFindings,
                suppressedFindings,
                patches
        );
    }

    /**
     * Executes review with baseline snapshot filtering. Known defects in the baseline
     * are suppressed as {@code BASELINE_ACCEPTED}, and only new defects trigger active findings.
     */
    public ReviewReport auditPathWithBaseline(Path targetPath, Path baselinePath) throws IOException {
        return auditPathWithBaseline(targetPath, baselinePath, (com.sentinelpr.core.governance.policy.SentinelPolicy) null);
    }

    public ReviewReport auditPathWithBaseline(Path targetPath, Path baselinePath, com.sentinelpr.core.governance.policy.SentinelPolicy policy) throws IOException {
        Objects.requireNonNull(baselinePath, "baselinePath must not be null");
        BaselineSnapshot baseline = baselineManager.loadBaseline(baselinePath);
        return auditPathWithBaseline(targetPath, baseline, policy);
    }

    public ReviewReport auditPathWithBaseline(Path targetPath, BaselineSnapshot baseline) throws IOException {
        return auditPathWithBaseline(targetPath, baseline, null);
    }

    public ReviewReport auditPathWithBaseline(Path targetPath, BaselineSnapshot baseline, com.sentinelpr.core.governance.policy.SentinelPolicy policy) throws IOException {
        Objects.requireNonNull(targetPath, "targetPath must not be null");
        if (baseline == null || baseline.getEntries().isEmpty()) {
            return auditPath(targetPath);
        }

        String reportId = "REV-" + UUID.randomUUID().toString().substring(0, 8);
        if (!Files.exists(targetPath)) {
            throw new IllegalArgumentException("Target path does not exist: " + targetPath);
        }

        List<InspectedSource> sources = inspectionService.inspectPath(targetPath);
        List<SecurityFinding> allActiveFindings = new ArrayList<>();
        List<SuppressedFinding> allSuppressedFindings = new ArrayList<>();
        List<UnifiedDiffPatch> allPatches = new ArrayList<>();

        for (InspectedSource source : sources) {
            List<SecurityFinding> rawFindings = evaluationService.evaluate(source, sources);
            List<SecurityFinding> activeSourceFindings = new ArrayList<>();

            for (SecurityFinding raw : rawFindings) {
                SecurityFinding enriched = causalAnalysisEngine.enrichFinding(raw, source);
                ConfidenceCalibrator.CalibrationResult cal = confidenceCalibrator.calibrate(enriched, source);
                SecurityFinding finding = enriched.withCalibratedConfidence(cal.getScore(), cal.getExploitabilityIndex());

                if (cal.isLowConfidence()) {
                    String reason = String.format("Calibrated confidence score (%.2f) below threshold (%.2f)",
                            cal.getScore(), confidenceCalibrator.getMinConfidenceThreshold());
                    allSuppressedFindings.add(new SuppressedFinding(finding, reason, ConfidenceCalibrator.LOW_CONFIDENCE_SUPPRESSION_TYPE));
                } else {
                    SuppressionResult sup = suppressionManager.evaluateSuppression(finding, source, targetPath);
                    if (sup.isSuppressed()) {
                        allSuppressedFindings.add(new SuppressedFinding(finding, sup.getReason(), sup.getType()));
                    } else {
                        String ruleId = finding.getRule().getRuleId();
                        boolean isBlockedByPolicy = policy != null && policy.getBlockedRules() != null && policy.getBlockedRules().contains(ruleId);

                        if (isBlockedByPolicy) {
                            // Policy supremacy: Blocked rules cannot be suppressed by baseline debt
                            activeSourceFindings.add(finding);
                        } else {
                            Optional<BaselineEntry> match = baseline.findMatchingEntry(finding);
                            if (match.isPresent()) {
                                String reason = String.format("Accepted technical debt present in baseline snapshot (fingerprint: %s)", match.get().getFingerprint());
                                allSuppressedFindings.add(new SuppressedFinding(finding, reason, BaselineManager.SUPPRESSION_TYPE));
                            } else {
                                activeSourceFindings.add(finding);
                            }
                        }
                    }
                }
            }

            allActiveFindings.addAll(activeSourceFindings);

            if (!activeSourceFindings.isEmpty()) {
                List<UnifiedDiffPatch> patches = patchService.generatePatches(source, activeSourceFindings);
                allPatches.addAll(patches);
            }
        }

        String summary = String.format(
                "Baseline-aware audit completed. Scanned %d source file(s), identified %d new active finding(s) (%d suppressed/baseline-accepted), synthesized %d verified patch(es).",
                sources.size(), allActiveFindings.size(), allSuppressedFindings.size(), allPatches.size()
        );

        return new ReviewReport(
                reportId,
                Instant.now(),
                targetPath.toString(),
                sources.size(),
                allActiveFindings.size(),
                "SUCCESS",
                false,
                summary,
                allActiveFindings,
                allSuppressedFindings,
                allPatches
        );
    }

    /**
     * Executes review combining both incremental PR diff filtering and baseline snapshot filtering.
     */
    public ReviewReport auditPathWithDiffAndBaseline(Path targetPath, String diffContent, Path baselinePath) throws IOException {
        return auditPathWithDiffAndBaseline(targetPath, diffContent, baselinePath, null);
    }

    public ReviewReport auditPathWithDiffAndBaseline(Path targetPath, String diffContent, Path baselinePath, com.sentinelpr.core.governance.policy.SentinelPolicy policy) throws IOException {
        Objects.requireNonNull(targetPath, "targetPath must not be null");
        if (baselinePath == null || !Files.exists(baselinePath)) {
            return auditPathWithDiff(targetPath, diffContent);
        }
        if (diffContent == null || diffContent.isBlank()) {
            return auditPathWithBaseline(targetPath, baselinePath, policy);
        }

        String reportId = "REV-" + UUID.randomUUID().toString().substring(0, 8);
        BaselineSnapshot baseline = baselineManager.loadBaseline(baselinePath);
        Map<String, FileDiff> diffs = diffScanner.parse(diffContent);
        List<InspectedSource> sources = inspectionService.inspectPath(targetPath);

        List<SecurityFinding> allActiveFindings = new ArrayList<>();
        List<SuppressedFinding> allSuppressedFindings = new ArrayList<>();
        List<UnifiedDiffPatch> allPatches = new ArrayList<>();

        for (InspectedSource source : sources) {
            List<SecurityFinding> rawFindings = evaluationService.evaluate(source);
            List<SecurityFinding> activeSourceFindings = new ArrayList<>();

            for (SecurityFinding finding : rawFindings) {
                SuppressionResult sup = suppressionManager.evaluateSuppression(finding, source, targetPath);
                if (sup.isSuppressed()) {
                    allSuppressedFindings.add(new SuppressedFinding(finding, sup.getReason(), sup.getType()));
                } else if (!diffScanner.isFindingInDiff(finding, diffs)) {
                    allSuppressedFindings.add(new SuppressedFinding(finding, "Baseline finding outside incremental PR diff range", "DIFF_BASELINE"));
                } else {
                    String ruleId = finding.getRule().getRuleId();
                    boolean isBlockedByPolicy = policy != null && policy.getBlockedRules() != null && policy.getBlockedRules().contains(ruleId);

                    if (isBlockedByPolicy) {
                        activeSourceFindings.add(finding);
                    } else {
                        Optional<BaselineEntry> match = baseline.findMatchingEntry(finding);
                        if (match.isPresent()) {
                            String reason = String.format("Accepted technical debt present in baseline snapshot (fingerprint: %s)", match.get().getFingerprint());
                            allSuppressedFindings.add(new SuppressedFinding(finding, reason, BaselineManager.SUPPRESSION_TYPE));
                        } else {
                            activeSourceFindings.add(finding);
                        }
                    }
                }
            }

            allActiveFindings.addAll(activeSourceFindings);

            if (!activeSourceFindings.isEmpty()) {
                List<UnifiedDiffPatch> patches = patchService.generatePatches(source, activeSourceFindings);
                allPatches.addAll(patches);
            }
        }

        String summary = String.format(
                "Incremental diff & baseline audit completed. Scanned %d source file(s), identified %d net-new active finding(s) (%d suppressed/baseline), synthesized %d verified patch(es).",
                sources.size(), allActiveFindings.size(), allSuppressedFindings.size(), allPatches.size()
        );

        return new ReviewReport(
                reportId,
                Instant.now(),
                targetPath.toString(),
                sources.size(),
                allActiveFindings.size(),
                "SUCCESS",
                false,
                summary,
                allActiveFindings,
                allSuppressedFindings,
                allPatches
        );
    }

    public CodeInspectionService getInspectionService() {
        return inspectionService;
    }

    public RuleEvaluationService getEvaluationService() {
        return evaluationService;
    }

    public AutomatedPatchService getPatchService() {
        return patchService;
    }

    public ReviewSessionMemory getSessionMemory() {
        return sessionMemory;
    }

    public SuppressionManager getSuppressionManager() {
        return suppressionManager;
    }

    public DataflowTracker getDataflowTracker() {
        return dataflowTracker;
    }

    public IncrementalDiffScanner getDiffScanner() {
        return diffScanner;
    }

    public BaselineManager getBaselineManager() {
        return baselineManager;
    }

    public CausalAnalysisEngine getCausalAnalysisEngine() {
        return causalAnalysisEngine;
    }

    public ConfidenceCalibrator getConfidenceCalibrator() {
        return confidenceCalibrator;
    }

    public MultiFileFixPlanner getMultiFileFixPlanner() {
        return multiFileFixPlanner;
    }

    public Optional<CoordinatedPatchPlan> planCoordinatedFix(List<InspectedSource> sources, SecurityFinding finding) {
        return multiFileFixPlanner.planCoordinatedFix(sources, finding);
    }

    /**
     * Executes review across an in-memory collection of inspected sources.
     */
    public ReviewReport auditSources(List<InspectedSource> sources) {
        if (sources == null || sources.isEmpty()) {
            return new ReviewReport("REV-EMPTY", Instant.now(), "in-memory", 0, 0, "SUCCESS", false, "No sources provided", List.of(), List.of());
        }

        String reportId = "REV-" + UUID.randomUUID().toString().substring(0, 8);
        List<SecurityFinding> allActiveFindings = new ArrayList<>();
        List<SuppressedFinding> allSuppressedFindings = new ArrayList<>();
        List<UnifiedDiffPatch> allPatches = new ArrayList<>();

        for (InspectedSource source : sources) {
            List<SecurityFinding> rawFindings = evaluationService.evaluate(source, sources);
            List<SecurityFinding> activeSourceFindings = new ArrayList<>();

            for (SecurityFinding raw : rawFindings) {
                SecurityFinding enriched = causalAnalysisEngine.enrichFinding(raw, source);
                ConfidenceCalibrator.CalibrationResult cal = confidenceCalibrator.calibrate(enriched, source);
                SecurityFinding finding = enriched.withCalibratedConfidence(cal.getScore(), cal.getExploitabilityIndex());

                if (cal.isLowConfidence()) {
                    String reason = String.format("Calibrated confidence score (%.2f) below threshold (%.2f)",
                            cal.getScore(), confidenceCalibrator.getMinConfidenceThreshold());
                    allSuppressedFindings.add(new SuppressedFinding(finding, reason, ConfidenceCalibrator.LOW_CONFIDENCE_SUPPRESSION_TYPE));
                } else {
                    SuppressionResult sup = suppressionManager.evaluateSuppression(finding, source, null);
                    if (sup.isSuppressed()) {
                        allSuppressedFindings.add(new SuppressedFinding(finding, sup.getReason(), sup.getType()));
                    } else {
                        activeSourceFindings.add(finding);
                    }
                }
            }

            allActiveFindings.addAll(activeSourceFindings);

            if (!activeSourceFindings.isEmpty()) {
                List<UnifiedDiffPatch> patches = patchService.generatePatches(source, activeSourceFindings);
                allPatches.addAll(patches);
            }
        }

        String summary = String.format(
                "Multi-source audit completed. Scanned %d source file(s), identified %d active finding(s) (%d suppressed), synthesized %d verified patch(es).",
                sources.size(), allActiveFindings.size(), allSuppressedFindings.size(), allPatches.size()
        );

        return new ReviewReport(
                reportId,
                Instant.now(),
                "multi-source",
                sources.size(),
                allActiveFindings.size(),
                "SUCCESS",
                false,
                summary,
                allActiveFindings,
                allSuppressedFindings,
                allPatches
        );
    }
}
