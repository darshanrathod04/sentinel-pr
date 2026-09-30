package com.sentinelpr.core.remediation;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.Collections;
import java.util.List;

/**
 * <b>PatchQualityMetrics</b>
 *
 * <p>Internal telemetry tracking patch synthesis quality, validation outcomes,
 * deterministic fallback activation, and strategy usage.</p>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class PatchQualityMetrics {

    private final boolean patchGenerated;
    private final boolean patchValidated;
    private final boolean patchRejected;
    private final boolean fallbackUsed;
    private final String strategyUsed;
    private final List<String> appliedStrategies;
    private final String rejectionReason;

    public PatchQualityMetrics(
            boolean patchGenerated,
            boolean patchValidated,
            boolean patchRejected,
            boolean fallbackUsed,
            String strategyUsed,
            List<String> appliedStrategies,
            String rejectionReason
    ) {
        this.patchGenerated = patchGenerated;
        this.patchValidated = patchValidated;
        this.patchRejected = patchRejected;
        this.fallbackUsed = fallbackUsed;
        this.strategyUsed = strategyUsed != null ? strategyUsed : "NONE";
        this.appliedStrategies = appliedStrategies != null ? Collections.unmodifiableList(appliedStrategies) : List.of();
        this.rejectionReason = rejectionReason != null ? rejectionReason : "";
    }

    public static PatchQualityMetrics none() {
        return new PatchQualityMetrics(false, false, false, false, "NONE", List.of(), "");
    }

    public boolean isPatchGenerated() {
        return patchGenerated;
    }

    public boolean isPatchValidated() {
        return patchValidated;
    }

    public boolean isPatchRejected() {
        return patchRejected;
    }

    public boolean isFallbackUsed() {
        return fallbackUsed;
    }

    public String getStrategyUsed() {
        return strategyUsed;
    }

    public List<String> getAppliedStrategies() {
        return appliedStrategies;
    }

    public String getRejectionReason() {
        return rejectionReason;
    }

    @Override
    public String toString() {
        return "PatchQualityMetrics{" +
                "patchGenerated=" + patchGenerated +
                ", patchValidated=" + patchValidated +
                ", patchRejected=" + patchRejected +
                ", fallbackUsed=" + fallbackUsed +
                ", strategyUsed='" + strategyUsed + '\'' +
                ", appliedStrategies=" + appliedStrategies +
                ", rejectionReason='" + rejectionReason + '\'' +
                '}';
    }
}
