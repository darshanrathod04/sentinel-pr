package com.sentinelpr.core.remediation;

import java.util.Objects;

/**
 * <b>RemediationResult</b>
 *
 * <p>Result of applying a {@link RemediationStrategy} to a Java source file.</p>
 */
public class RemediationResult {

    private final String patchedSource;
    private final boolean applied;
    private final boolean fallbackUsed;
    private final String strategyName;
    private final String message;
    private final int startLine;
    private final int endLine;

    public RemediationResult(
            String patchedSource,
            boolean applied,
            boolean fallbackUsed,
            String strategyName,
            String message,
            int startLine,
            int endLine
    ) {
        this.patchedSource = Objects.requireNonNull(patchedSource, "patchedSource must not be null");
        this.applied = applied;
        this.fallbackUsed = fallbackUsed;
        this.strategyName = strategyName != null ? strategyName : "UNKNOWN";
        this.message = message != null ? message : "";
        this.startLine = startLine;
        this.endLine = endLine;
    }

    public static RemediationResult success(String patchedSource, String strategyName, String message, int startLine, int endLine) {
        return new RemediationResult(patchedSource, true, false, strategyName, message, startLine, endLine);
    }

    public static RemediationResult fallback(String patchedSource, String strategyName, String message, int startLine, int endLine) {
        return new RemediationResult(patchedSource, true, true, strategyName, message, startLine, endLine);
    }

    public static RemediationResult unapplied(String originalSource, String strategyName, String reason) {
        return new RemediationResult(originalSource, false, false, strategyName, reason, -1, -1);
    }

    public String getPatchedSource() {
        return patchedSource;
    }

    public boolean isApplied() {
        return applied;
    }

    public boolean isFallbackUsed() {
        return fallbackUsed;
    }

    public String getStrategyName() {
        return strategyName;
    }

    public String getMessage() {
        return message;
    }

    public int getStartLine() {
        return startLine;
    }

    public int getEndLine() {
        return endLine;
    }
}
