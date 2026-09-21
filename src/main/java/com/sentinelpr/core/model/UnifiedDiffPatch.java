package com.sentinelpr.core.model;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.Objects;

/**
 * <b>UnifiedDiffPatch</b>
 *
 * <p>Verified code patch represented in unified diff format, with both AST syntax
 * verification and post-patch regression validation tracking.</p>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class UnifiedDiffPatch {

    public enum Status {
        SUCCESS,
        PARTIAL,
        FAILED,
        SKIPPED,
        DEFERRED_TO_MULTI_FILE_PLAN
    }

    private final String findingId;
    private final String ruleId;
    private final String targetFile;
    private final String unifiedDiff;
    private final String patchedSource;
    private final Status status;
    private final boolean verified;
    private final boolean regressionVerified;
    private final String verificationMessage;

    public UnifiedDiffPatch(
            String findingId,
            String ruleId,
            String targetFile,
            String unifiedDiff,
            String patchedSource,
            Status status,
            boolean verified,
            String verificationMessage
    ) {
        this(findingId, ruleId, targetFile, unifiedDiff, patchedSource, status, verified, false, verificationMessage);
    }

    public UnifiedDiffPatch(
            String findingId,
            String ruleId,
            String targetFile,
            String unifiedDiff,
            String patchedSource,
            Status status,
            boolean verified,
            boolean regressionVerified,
            String verificationMessage
    ) {
        this.findingId = Objects.requireNonNull(findingId, "findingId must not be null");
        this.ruleId = ruleId != null ? ruleId : "";
        this.targetFile = targetFile != null ? targetFile : "";
        this.unifiedDiff = unifiedDiff != null ? unifiedDiff : "";
        this.patchedSource = patchedSource != null ? patchedSource : "";
        this.status = status != null ? status : Status.SUCCESS;
        boolean diffValid = !this.unifiedDiff.isBlank();
        boolean statusSuccess = this.status == Status.SUCCESS;
        this.verified = statusSuccess && diffValid && verified;
        this.regressionVerified = this.verified && regressionVerified;
        this.verificationMessage = verificationMessage != null ? verificationMessage : "";
    }

    public String getFindingId() {
        return findingId;
    }

    public String getRuleId() {
        return ruleId;
    }

    public String getTargetFile() {
        return targetFile;
    }

    public String getUnifiedDiff() {
        return unifiedDiff;
    }

    public String getPatchedSource() {
        return patchedSource;
    }

    public Status getStatus() {
        return status;
    }

    public boolean isVerified() {
        return verified;
    }

    public boolean isAstValid() {
        return verified;
    }

    public boolean isRegressionVerified() {
        return regressionVerified;
    }

    public String getVerificationMessage() {
        return verificationMessage;
    }

    @Override
    public String toString() {
        return "UnifiedDiffPatch{" +
                "findingId='" + findingId + '\'' +
                ", ruleId='" + ruleId + '\'' +
                ", targetFile='" + targetFile + '\'' +
                ", status=" + status +
                ", verified=" + verified +
                ", regressionVerified=" + regressionVerified +
                '}';
    }
}
