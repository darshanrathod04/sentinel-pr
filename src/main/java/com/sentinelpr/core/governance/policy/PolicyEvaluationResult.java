package com.sentinelpr.core.governance.policy;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * <b>PolicyEvaluationResult</b>
 *
 * <p>Result of evaluating a security review report against an enterprise compliance policy.</p>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class PolicyEvaluationResult {

    public enum Status {
        PASSED,
        PASSED_WITH_BASELINE,
        FAILED,
        BREACHED
    }

    private final Status status;
    private final String policyName;
    private final List<String> violations;
    private final int criticalCount;
    private final int highCount;
    private final int mediumCount;
    private final int unverifiedPatchCount;
    private final int blockedCount;
    private final String summary;

    @JsonCreator
    public PolicyEvaluationResult(
            @JsonProperty("status") Status status,
            @JsonProperty("policyName") String policyName,
            @JsonProperty("violations") List<String> violations,
            @JsonProperty("criticalCount") int criticalCount,
            @JsonProperty("highCount") int highCount,
            @JsonProperty("mediumCount") int mediumCount,
            @JsonProperty("unverifiedPatchCount") int unverifiedPatchCount,
            @JsonProperty("blockedCount") int blockedCount,
            @JsonProperty("summary") String summary
    ) {
        this.status = status != null ? status : Status.PASSED;
        this.policyName = policyName != null ? policyName : "";
        this.violations = violations != null ? Collections.unmodifiableList(new ArrayList<>(violations)) : List.of();
        this.criticalCount = criticalCount;
        this.highCount = highCount;
        this.mediumCount = mediumCount;
        this.unverifiedPatchCount = unverifiedPatchCount;
        this.blockedCount = blockedCount;
        this.summary = summary != null ? summary : "";
    }

    public PolicyEvaluationResult(
            Status status,
            String policyName,
            List<String> violations,
            int criticalCount,
            int highCount,
            int mediumCount,
            int unverifiedPatchCount,
            String summary
    ) {
        this(status, policyName, violations, criticalCount, highCount, mediumCount, unverifiedPatchCount, 0, summary);
    }

    public static PolicyEvaluationResult passed(String policyName, int criticalCount, int highCount, int mediumCount, String summary) {
        return new PolicyEvaluationResult(Status.PASSED, policyName, List.of(), criticalCount, highCount, mediumCount, 0, 0, summary);
    }

    public static PolicyEvaluationResult passedWithBaseline(String policyName, int criticalCount, int highCount, int mediumCount, int baselineCount, String summary) {
        return new PolicyEvaluationResult(Status.PASSED_WITH_BASELINE, policyName, List.of(), criticalCount, highCount, mediumCount, 0, 0, summary);
    }

    public static PolicyEvaluationResult breached(
            String policyName,
            List<String> violations,
            int criticalCount,
            int highCount,
            int mediumCount,
            int unverifiedPatchCount,
            int blockedCount,
            String summary
    ) {
        return new PolicyEvaluationResult(Status.BREACHED, policyName, violations, criticalCount, highCount, mediumCount, unverifiedPatchCount, blockedCount, summary);
    }

    public static PolicyEvaluationResult breached(
            String policyName,
            List<String> violations,
            int criticalCount,
            int highCount,
            int mediumCount,
            int unverifiedPatchCount,
            String summary
    ) {
        return breached(policyName, violations, criticalCount, highCount, mediumCount, unverifiedPatchCount, 0, summary);
    }

    public static PolicyEvaluationResult failed(String policyName, String summary) {
        return new PolicyEvaluationResult(Status.FAILED, policyName, List.of(summary), 0, 0, 0, 0, 0, summary);
    }

    public boolean isPassed() {
        return status == Status.PASSED || status == Status.PASSED_WITH_BASELINE;
    }

    public boolean isPassedWithBaseline() {
        return status == Status.PASSED_WITH_BASELINE;
    }

    public boolean isBreached() {
        return status == Status.BREACHED;
    }

    public boolean isFailed() {
        return status == Status.FAILED;
    }

    /**
     * Standard CLI exit code:
     * <ul>
     *   <li>0 if policy PASSED or PASSED_WITH_BASELINE</li>
     *   <li>1 if policy BREACHED (defect thresholds / blocked rules)</li>
     *   <li>2 if internal engine error (FAILED)</li>
     *   <li>4 if patch generation / verification failure</li>
     * </ul>
     */
    public int getExitCode() {
        if (isPassed()) return 0;
        if (isBreached()) {
            if (unverifiedPatchCount > 0) {
                return 4;
            }
            return 1;
        }
        return 2;
    }

    public Status getStatus() {
        return status;
    }

    public String getPolicyName() {
        return policyName;
    }

    public List<String> getViolations() {
        return violations;
    }

    public int getCriticalCount() {
        return criticalCount;
    }

    public int getHighCount() {
        return highCount;
    }

    public int getMediumCount() {
        return mediumCount;
    }

    public int getUnverifiedPatchCount() {
        return unverifiedPatchCount;
    }

    public int getBlockedCount() {
        return blockedCount;
    }

    public String getSummary() {
        return summary;
    }

    @Override
    public String toString() {
        return "PolicyEvaluationResult{" +
                "status=" + status +
                ", policyName='" + policyName + '\'' +
                ", violations=" + violations.size() +
                ", blockedCount=" + blockedCount +
                ", exitCode=" + getExitCode() +
                '}';
    }
}
