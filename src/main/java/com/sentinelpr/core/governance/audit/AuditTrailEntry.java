package com.sentinelpr.core.governance.audit;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;

/**
 * <b>AuditTrailEntry</b>
 *
 * <p>Immutable audit ledger entry recording execution integrity, operator identity,
 * and cryptographic SHA-256 signatures for SOC2 / ISO27001 compliance.</p>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AuditTrailEntry {

    private final String runId;
    private final Instant timestamp;
    private final String targetPath;
    private final String commitId;
    private final String branch;
    private final String operator;
    private final String inputFingerprint;
    private final String reportSignature;
    private final String memoryKernelFingerprint;
    private final int rulesActive;
    private final String modelProvider;
    private final String policyStatus;
    private final int totalFindings;
    private final int totalPatches;

    @JsonCreator
    public AuditTrailEntry(
            @JsonProperty("runId") String runId,
            @JsonProperty("timestamp") Instant timestamp,
            @JsonProperty("targetPath") String targetPath,
            @JsonProperty("commitId") String commitId,
            @JsonProperty("branch") String branch,
            @JsonProperty("operator") String operator,
            @JsonProperty("inputFingerprint") String inputFingerprint,
            @JsonProperty("reportSignature") String reportSignature,
            @JsonProperty("memoryKernelFingerprint") String memoryKernelFingerprint,
            @JsonProperty("rulesActive") int rulesActive,
            @JsonProperty("modelProvider") String modelProvider,
            @JsonProperty("policyStatus") String policyStatus,
            @JsonProperty("totalFindings") int totalFindings,
            @JsonProperty("totalPatches") int totalPatches
    ) {
        this.runId = runId != null ? runId : "";
        this.timestamp = timestamp != null ? timestamp : Instant.now();
        this.targetPath = targetPath != null ? targetPath : "";
        this.commitId = commitId != null ? commitId : "HEAD";
        this.branch = branch != null ? branch : "main";
        this.operator = operator != null ? operator : "sentinel-agent";
        this.inputFingerprint = inputFingerprint != null ? inputFingerprint : "";
        this.reportSignature = reportSignature != null ? reportSignature : "";
        this.memoryKernelFingerprint = memoryKernelFingerprint != null ? memoryKernelFingerprint : "";
        this.rulesActive = rulesActive;
        this.modelProvider = modelProvider != null ? modelProvider : "Shree AI OS (deterministic)";
        this.policyStatus = policyStatus != null ? policyStatus : "NOT_EVALUATED";
        this.totalFindings = totalFindings;
        this.totalPatches = totalPatches;
    }

    public String getRunId() {
        return runId;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public String getTargetPath() {
        return targetPath;
    }

    public String getCommitId() {
        return commitId;
    }

    public String getBranch() {
        return branch;
    }

    public String getOperator() {
        return operator;
    }

    public String getInputFingerprint() {
        return inputFingerprint;
    }

    public String getReportSignature() {
        return reportSignature;
    }

    public String getMemoryKernelFingerprint() {
        return memoryKernelFingerprint;
    }

    public int getRulesActive() {
        return rulesActive;
    }

    public String getModelProvider() {
        return modelProvider;
    }

    public String getPolicyStatus() {
        return policyStatus;
    }

    public int getTotalFindings() {
        return totalFindings;
    }

    public int getTotalPatches() {
        return totalPatches;
    }
}
