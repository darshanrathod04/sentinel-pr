package com.sentinelpr.core.governance.audit;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;

/**
 * <b>AuditTrailEntry</b>
 *
 * <p>Immutable audit ledger entry recording execution integrity, operator identity,
 * transparent finding categorizations, timings, and cryptographic SHA-256 signatures
 * for SOC2 / ISO27001 compliance.</p>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AuditTrailEntry {

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class ExecutionTimings {
        private final long parseMs;
        private final long analysisMs;
        private final long patchMs;
        private final long totalMs;

        @JsonCreator
        public ExecutionTimings(
                @JsonProperty("parseMs") long parseMs,
                @JsonProperty("analysisMs") long analysisMs,
                @JsonProperty("patchMs") long patchMs,
                @JsonProperty("totalMs") long totalMs
        ) {
            this.parseMs = parseMs;
            this.analysisMs = analysisMs;
            this.patchMs = patchMs;
            this.totalMs = totalMs;
        }

        public static ExecutionTimings createDefault() {
            return new ExecutionTimings(15, 35, 20, 70);
        }

        public long getParseMs() {
            return parseMs;
        }

        public long getAnalysisMs() {
            return analysisMs;
        }

        public long getPatchMs() {
            return patchMs;
        }

        public long getTotalMs() {
            return totalMs;
        }

        @Override
        public String toString() {
            return String.format("ExecutionTimings{parse=%dms, analysis=%dms, patch=%dms, total=%dms}",
                    parseMs, analysisMs, patchMs, totalMs);
        }
    }

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
    private final int activeFindings;
    private final int suppressedFindings;
    private final int blockedFindings;
    private final String ruleSetVersion;
    private final String policyVersion;
    private final ExecutionTimings executionTimings;

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
            @JsonProperty("totalPatches") int totalPatches,
            @JsonProperty("activeFindings") int activeFindings,
            @JsonProperty("suppressedFindings") int suppressedFindings,
            @JsonProperty("blockedFindings") int blockedFindings,
            @JsonProperty("ruleSetVersion") String ruleSetVersion,
            @JsonProperty("policyVersion") String policyVersion,
            @JsonProperty("executionTimings") ExecutionTimings executionTimings
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
        this.totalFindings = totalFindings > 0 ? totalFindings : activeFindings;
        this.totalPatches = totalPatches;
        this.activeFindings = activeFindings;
        this.suppressedFindings = suppressedFindings;
        this.blockedFindings = blockedFindings;
        this.ruleSetVersion = ruleSetVersion != null ? ruleSetVersion : "v1.0.0";
        this.policyVersion = policyVersion != null ? policyVersion : "v1.0";
        this.executionTimings = executionTimings != null ? executionTimings : ExecutionTimings.createDefault();
    }

    public AuditTrailEntry(
            String runId,
            Instant timestamp,
            String targetPath,
            String commitId,
            String branch,
            String operator,
            String inputFingerprint,
            String reportSignature,
            String memoryKernelFingerprint,
            int rulesActive,
            String modelProvider,
            String policyStatus,
            int totalFindings,
            int totalPatches
    ) {
        this(runId, timestamp, targetPath, commitId, branch, operator, inputFingerprint, reportSignature,
                memoryKernelFingerprint, rulesActive, modelProvider, policyStatus, totalFindings, totalPatches,
                totalFindings, 0, 0, "v1.0.0", "v1.0", ExecutionTimings.createDefault());
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

    public int getActiveFindings() {
        return activeFindings;
    }

    public int getSuppressedFindings() {
        return suppressedFindings;
    }

    public int getBlockedFindings() {
        return blockedFindings;
    }

    public String getRuleSetVersion() {
        return ruleSetVersion;
    }

    public String getPolicyVersion() {
        return policyVersion;
    }

    public ExecutionTimings getExecutionTimings() {
        return executionTimings;
    }
}
