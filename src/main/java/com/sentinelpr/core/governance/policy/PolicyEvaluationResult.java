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
        BREACHED
    }

    private final Status status;
    private final String policyName;
    private final List<String> violations;
    private final int criticalCount;
    private final int highCount;
    private final int mediumCount;
    private final int unverifiedPatchCount;
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
            @JsonProperty("summary") String summary
    ) {
        this.status = status != null ? status : Status.PASSED;
        this.policyName = policyName != null ? policyName : "";
        this.violations = violations != null ? Collections.unmodifiableList(new ArrayList<>(violations)) : List.of();
        this.criticalCount = criticalCount;
        this.highCount = highCount;
        this.mediumCount = mediumCount;
        this.unverifiedPatchCount = unverifiedPatchCount;
        this.summary = summary != null ? summary : "";
    }

    public static PolicyEvaluationResult passed(String policyName, int criticalCount, int highCount, int mediumCount, String summary) {
        return new PolicyEvaluationResult(Status.PASSED, policyName, List.of(), criticalCount, highCount, mediumCount, 0, summary);
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
        return new PolicyEvaluationResult(Status.BREACHED, policyName, violations, criticalCount, highCount, mediumCount, unverifiedPatchCount, summary);
    }

    public boolean isPassed() {
        return status == Status.PASSED;
    }

    public boolean isBreached() {
        return status == Status.BREACHED;
    }

    /**
     * Standard CLI exit code:
     * <ul>
     *   <li>0 if policy PASSED</li>
     *   <li>1 if policy BREACHED</li>
     * </ul>
     */
    public int getExitCode() {
        return isPassed() ? 0 : 1;
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

    public String getSummary() {
        return summary;
    }

    @Override
    public String toString() {
        return "PolicyEvaluationResult{" +
                "status=" + status +
                ", policyName='" + policyName + '\'' +
                ", violations=" + violations.size() +
                ", exitCode=" + getExitCode() +
                '}';
    }
}
