package com.sentinelpr.benchmark.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.Collections;
import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public class BenchmarkGroundTruth {

    private boolean expectedFinding;
    private String expectedSeverity;
    private String targetConstruct;
    private boolean expectedRemediation;
    private List<String> requiredRemediationTokens = Collections.emptyList();
    private List<String> forbiddenRemediationTokens = Collections.emptyList();

    public BenchmarkGroundTruth() {}

    public boolean isExpectedFinding() {
        return expectedFinding;
    }

    public void setExpectedFinding(boolean expectedFinding) {
        this.expectedFinding = expectedFinding;
    }

    public String getExpectedSeverity() {
        return expectedSeverity;
    }

    public void setExpectedSeverity(String expectedSeverity) {
        this.expectedSeverity = expectedSeverity;
    }

    public String getTargetConstruct() {
        return targetConstruct;
    }

    public void setTargetConstruct(String targetConstruct) {
        this.targetConstruct = targetConstruct;
    }

    public boolean isExpectedRemediation() {
        return expectedRemediation;
    }

    public void setExpectedRemediation(boolean expectedRemediation) {
        this.expectedRemediation = expectedRemediation;
    }

    public List<String> getRequiredRemediationTokens() {
        return requiredRemediationTokens != null ? requiredRemediationTokens : Collections.emptyList();
    }

    public void setRequiredRemediationTokens(List<String> requiredRemediationTokens) {
        this.requiredRemediationTokens = requiredRemediationTokens;
    }

    public List<String> getForbiddenRemediationTokens() {
        return forbiddenRemediationTokens != null ? forbiddenRemediationTokens : Collections.emptyList();
    }

    public void setForbiddenRemediationTokens(List<String> forbiddenRemediationTokens) {
        this.forbiddenRemediationTokens = forbiddenRemediationTokens;
    }
}
