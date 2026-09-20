package com.sentinelpr.core.service;

import com.sentinelpr.core.analysis.DataflowTracker;
import com.sentinelpr.core.analysis.SuppressionManager;
import com.sentinelpr.core.analysis.SuppressionResult;
import com.sentinelpr.core.model.InspectedSource;
import com.sentinelpr.core.model.ReviewReport;
import com.sentinelpr.core.model.SecurityFinding;
import com.sentinelpr.core.model.SuppressedFinding;
import com.sentinelpr.core.model.UnifiedDiffPatch;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
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
 *   <li>Atomic patch composition and regression verification</li>
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

    public SentinelAuditOrchestrator(
            CodeInspectionService inspectionService,
            RuleEvaluationService evaluationService,
            AutomatedPatchService patchService,
            ReviewSessionMemory sessionMemory
    ) {
        this(inspectionService, evaluationService, patchService, sessionMemory, new SuppressionManager(), new DataflowTracker());
    }

    public SentinelAuditOrchestrator(
            CodeInspectionService inspectionService,
            RuleEvaluationService evaluationService,
            AutomatedPatchService patchService,
            ReviewSessionMemory sessionMemory,
            SuppressionManager suppressionManager,
            DataflowTracker dataflowTracker
    ) {
        this.inspectionService = Objects.requireNonNull(inspectionService, "inspectionService must not be null");
        this.evaluationService = Objects.requireNonNull(evaluationService, "evaluationService must not be null");
        this.patchService = Objects.requireNonNull(patchService, "patchService must not be null");
        this.sessionMemory = Objects.requireNonNull(sessionMemory, "sessionMemory must not be null");
        this.suppressionManager = Objects.requireNonNull(suppressionManager, "suppressionManager must not be null");
        this.dataflowTracker = Objects.requireNonNull(dataflowTracker, "dataflowTracker must not be null");
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
            List<SecurityFinding> rawFindings = evaluationService.evaluate(source);

            List<SecurityFinding> activeSourceFindings = new ArrayList<>();
            for (SecurityFinding finding : rawFindings) {
                SuppressionResult sup = suppressionManager.evaluateSuppression(finding, source, targetPath);
                if (sup.isSuppressed()) {
                    allSuppressedFindings.add(new SuppressedFinding(finding, sup.getReason(), sup.getType()));
                } else {
                    activeSourceFindings.add(finding);
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
}
