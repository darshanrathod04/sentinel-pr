package com.sentinelpr.core.service;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ast.CompilationUnit;
import com.sentinelpr.client.DeveloperFacade;
import com.sentinelpr.client.SentinelClient;
import com.sentinelpr.core.model.InspectedSource;
import com.sentinelpr.core.model.SecurityFinding;
import com.sentinelpr.core.model.SecurityRule;
import com.sentinelpr.core.model.UnifiedDiffPatch;
import com.sentinelpr.core.remediation.PatchQualityMetrics;
import com.sentinelpr.core.remediation.PatchValidationStatus;
import com.sentinelpr.core.remediation.RemediationContext;
import com.sentinelpr.core.remediation.RemediationResult;
import com.sentinelpr.core.remediation.RemediationStrategy;
import com.sentinelpr.core.remediation.RemediationTemplateRegistry;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * <b>PatchComposer</b>
 *
 * <p>Atomic patch composition engine for SentinelPR. When a single source file contains
 * multiple security findings, PatchComposer applies all verified AST transformations
 * sequentially to a single in-memory source and generates ONE clean, unified diff per file,
 * followed by regression verification.</p>
 *
 * <p><b>H-2 Hardening:</b> Tracks cumulative line deltas and resolves findings dynamically
 * in current source to prevent line-shift corruption across sequential patch applications.</p>
 */
public class PatchComposer {

    private final DeveloperFacade developerFacade;
    private final PatchVerifier patchVerifier;
    private final JavaParser javaParser;

    public PatchComposer(DeveloperFacade developerFacade, PatchVerifier patchVerifier) {
        this.developerFacade = Objects.requireNonNull(developerFacade, "developerFacade must not be null");
        this.patchVerifier = Objects.requireNonNull(patchVerifier, "patchVerifier must not be null");
        ParserConfiguration config = new ParserConfiguration();
        config.setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_21);
        this.javaParser = new JavaParser(config);
    }

    public PatchComposer(SentinelClient client) {
        this(
                client.developer(),
                new PatchVerifier(new CodeInspectionService(client), new RuleEvaluationService(client))
        );
    }

    /**
     * Composes all fixes for the given findings into a single unified diff patch.
     *
     * @param source   original inspected source
     * @param findings list of security findings detected in this source
     * @return single composite UnifiedDiffPatch
     */
    public UnifiedDiffPatch compose(InspectedSource source, List<SecurityFinding> findings) {
        Objects.requireNonNull(source, "source must not be null");
        if (findings == null || findings.isEmpty()) {
            return null;
        }

        String originalSource = source.getRawSource();
        String targetFilePath = source.getFilePath() != null
                ? source.getFilePath().toString()
                : "VulnerableService.java";

        // Sort findings in deterministic order
        List<SecurityFinding> sortedFindings = new ArrayList<>(findings);
        sortedFindings.sort(Comparator.comparingInt(this::rulePriority));

        RemediationTemplateRegistry registry = RemediationTemplateRegistry.getInstance();
        RemediationContext context = new RemediationContext(targetFilePath, sortedFindings);
        List<String> appliedStrategies = new ArrayList<>();
        boolean anyFallbackUsed = false;
        List<SourceRange> modifiedRanges = new ArrayList<>();

        String currentSource = originalSource;
        int cumulativeLineDelta = 0;

        for (SecurityFinding originalFinding : sortedFindings) {
            // H-2: Dynamically resolve finding construct & coordinates in currentSource
            SecurityFinding finding = resolveFindingInCurrentSource(currentSource, originalFinding, cumulativeLineDelta);

            // Check for range conflict with previous transformations
            if (isRangeConflict(finding, modifiedRanges)) {
                if (!isSafeToApply(currentSource, finding)) {
                    continue;
                }
            }

            RemediationStrategy strategy = registry.getStrategy(finding.getRule());
            if (strategy != null) {
                int preLines = countLines(currentSource);
                RemediationResult result = strategy.remediate(currentSource, finding, source, context);
                if (result.isApplied() && isValidJava(result.getPatchedSource())) {
                    currentSource = result.getPatchedSource();
                    int postLines = countLines(currentSource);
                    cumulativeLineDelta += (postLines - preLines);

                    appliedStrategies.add(result.getStrategyName());
                    if (result.isFallbackUsed()) {
                        anyFallbackUsed = true;
                    }
                    int rStart = result.getStartLine() > 0 ? result.getStartLine() : finding.getStartLine();
                    int rEnd = result.getEndLine() >= rStart ? result.getEndLine() : finding.getEndLine();
                    if (rStart > 0 && rEnd >= rStart) {
                        modifiedRanges.add(new SourceRange(rStart, rEnd));
                    }
                }
            }
        }

        // Regression & AST Syntax Verification
        PatchVerificationResult verificationResult = patchVerifier.verify(currentSource, targetFilePath);

        String unifiedDiff = developerFacade.generateUnifiedDiff(originalSource, currentSource, targetFilePath);

        String combinedFindingIds = sortedFindings.stream()
                .map(SecurityFinding::getId)
                .collect(Collectors.joining(", "));

        String combinedRuleIds = sortedFindings.stream()
                .map(f -> f.getRule().getRuleId())
                .distinct()
                .collect(Collectors.joining(", "));

        boolean isModified = !currentSource.equals(originalSource);
        boolean isSuccess = verificationResult.isSyntaxValid() && isModified;
        UnifiedDiffPatch.Status status;
        String message;

        boolean hasDeferredArchFinding = sortedFindings.stream().anyMatch(f ->
                f.getRule() == SecurityRule.ARCH_CYCLIC_DEPENDENCY
                || f.getRule() == SecurityRule.ARCH_LEAKY_ABSTRACTION
                || f.getRule() == SecurityRule.ARCH_NON_DETERMINISTIC_CALL);

        if (isSuccess) {
            status = UnifiedDiffPatch.Status.SUCCESS;
            message = verificationResult.getMessage();
        } else if (isModified) {
            status = UnifiedDiffPatch.Status.PARTIAL;
            message = verificationResult.getMessage();
        } else if (hasDeferredArchFinding) {
            status = UnifiedDiffPatch.Status.DEFERRED_TO_MULTI_FILE_PLAN;
            message = "Architectural Refactor Plan: Leaky abstraction or cyclic dependency detected. No pre-existing DTO/Mapper resolved in single-file scope. Multi-file coordinated refactoring required across Controller, DTO, Mapper, and Service. Delegate to MultiFileFixPlanner.";
        } else {
            status = UnifiedDiffPatch.Status.FAILED;
            message = verificationResult.getMessage();
        }

        boolean verified = (status == UnifiedDiffPatch.Status.SUCCESS) && verificationResult.isSyntaxValid();
        boolean regressionVerified = verified && verificationResult.isRegressionVerified();
        String finalDiff = (status == UnifiedDiffPatch.Status.SUCCESS) ? unifiedDiff : "";

        PatchValidationStatus valStatus;
        if (!isModified) {
            valStatus = PatchValidationStatus.NOT_APPLICABLE;
        } else if (verificationResult.isSyntaxValid()) {
            valStatus = PatchValidationStatus.VALID_PATCH;
        } else {
            valStatus = PatchValidationStatus.INVALID_PATCH;
        }

        PatchQualityMetrics qualityMetrics = new PatchQualityMetrics(
                isModified,
                verificationResult.isSyntaxValid(),
                isModified && !verificationResult.isSyntaxValid(),
                anyFallbackUsed,
                String.join(", ", appliedStrategies),
                appliedStrategies,
                verificationResult.isSyntaxValid() ? "" : verificationResult.getMessage()
        );

        return new UnifiedDiffPatch(
                combinedFindingIds,
                combinedRuleIds,
                targetFilePath,
                finalDiff,
                currentSource,
                status,
                verified,
                regressionVerified,
                message,
                qualityMetrics,
                valStatus
        );
    }

    /**
     * Resolves the actual line coordinates of a finding in the current (potentially mutated) source.
     * Combines snippet-based search with cumulative line delta alignment.
     */
    private SecurityFinding resolveFindingInCurrentSource(
            String currentSource,
            SecurityFinding originalFinding,
            int cumulativeLineDelta
    ) {
        String snippet = originalFinding.getVulnerableSnippet();
        int origStart = originalFinding.getStartLine();
        int origEnd = originalFinding.getEndLine();
        int expectedStart = Math.max(1, origStart + cumulativeLineDelta);
        int expectedEnd = Math.max(expectedStart, origEnd + cumulativeLineDelta);

        if (currentSource == null || currentSource.isBlank()) {
            return originalFinding;
        }

        String[] lines = currentSource.split("\\r?\\n", -1);

        // 1. If snippet is available and non-blank, find its actual location in currentSource
        if (snippet != null && !snippet.isBlank()) {
            String trimmedSnippet = snippet.trim();

            // A. Check if the line at expectedStart contains the snippet
            int expectedIdx = expectedStart - 1;
            if (expectedIdx >= 0 && expectedIdx < lines.length && lines[expectedIdx].contains(trimmedSnippet)) {
                return originalFinding.withLines(expectedStart, expectedEnd);
            }

            // B. Search for the line containing trimmedSnippet closest to expectedStart
            int bestLine = -1;
            int minDistance = Integer.MAX_VALUE;
            for (int i = 0; i < lines.length; i++) {
                if (lines[i].contains(trimmedSnippet)) {
                    int lineNum = i + 1;
                    int distance = Math.abs(lineNum - expectedStart);
                    if (distance < minDistance) {
                        minDistance = distance;
                        bestLine = lineNum;
                    }
                }
            }

            if (bestLine != -1) {
                int lineSpan = Math.max(0, origEnd - origStart);
                return originalFinding.withLines(bestLine, bestLine + lineSpan);
            }

            // C. Multi-line snippet check
            if (trimmedSnippet.contains("\n")) {
                int idx = currentSource.indexOf(trimmedSnippet);
                if (idx != -1) {
                    int matchLine = countLines(currentSource.substring(0, idx));
                    int snippetLineSpan = countLines(trimmedSnippet) - 1;
                    return originalFinding.withLines(matchLine, matchLine + snippetLineSpan);
                }
            }
        }

        // 2. Fallback to cumulative delta
        return originalFinding.withLines(expectedStart, expectedEnd);
    }

    private int countLines(String text) {
        if (text == null || text.isEmpty()) return 0;
        int count = 1;
        for (int i = 0; i < text.length(); i++) {
            if (text.charAt(i) == '\n') count++;
        }
        return count;
    }

    private record SourceRange(int startLine, int endLine) {
        boolean overlaps(int start, int end) {
            if (start <= 0 || end <= 0) return false;
            return this.startLine <= end && start <= this.endLine;
        }
    }

    private boolean isRangeConflict(SecurityFinding finding, List<SourceRange> modifiedRanges) {
        int fStart = finding.getStartLine();
        int fEnd = finding.getEndLine();
        if (fStart <= 0 || fEnd <= 0) return false;
        for (SourceRange r : modifiedRanges) {
            if (r.overlaps(fStart, fEnd)) {
                return true;
            }
        }
        return false;
    }

    private boolean isSafeToApply(String currentSource, SecurityFinding finding) {
        String snippet = finding.getVulnerableSnippet();
        return snippet != null && !snippet.isBlank() && currentSource.contains(snippet);
    }

    private int rulePriority(SecurityFinding f) {
        return switch (f.getRule()) {
            case VOLATILE_COMPOUND_OP -> 1;
            case UNCLOSED_IO_STREAM -> 2;
            case FAIL_OPEN_SECURITY -> 3;
            case UNISOLATED_SUBPROCESS -> 4;
            case SQL_INJECTION -> 5;
            case PATH_TRAVERSAL -> 6;
            case INSECURE_DESERIALIZATION -> 7;
            case HARDCODED_SECRET -> 8;
            case SPRING_SECURITY_CSRF_DISABLED -> 9;
            case SPRING_PERMISSIVE_CORS -> 10;
            case ARCH_CYCLIC_DEPENDENCY -> 11;
            case ARCH_LEAKY_ABSTRACTION -> 12;
            case ARCH_NON_DETERMINISTIC_CALL -> 13;
        };
    }

    private boolean isValidJava(String code) {
        if (code == null || code.isBlank()) return false;
        try {
            Optional<CompilationUnit> result = javaParser.parse(code).getResult();
            return result.isPresent();
        } catch (Exception e) {
            return false;
        }
    }
}
