package com.sentinelpr.api.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.sentinelpr.core.governance.policy.SentinelPolicy;
import com.sentinelpr.core.model.ReviewReport;

/**
 * Request payload for POST /api/v1/sentinel/policy/evaluate.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class PolicyEvaluateRequest {

    private ReviewReport report;
    private SentinelPolicy policy;
    private String targetPath;

    public PolicyEvaluateRequest() {
    }

    public PolicyEvaluateRequest(ReviewReport report, SentinelPolicy policy) {
        this.report = report;
        this.policy = policy;
    }

    public PolicyEvaluateRequest(String targetPath, SentinelPolicy policy) {
        this.targetPath = targetPath;
        this.policy = policy;
    }

    public ReviewReport getReport() {
        return report;
    }

    public void setReport(ReviewReport report) {
        this.report = report;
    }

    public SentinelPolicy getPolicy() {
        return policy;
    }

    public void setPolicy(SentinelPolicy policy) {
        this.policy = policy;
    }

    public String getTargetPath() {
        return targetPath;
    }

    public void setTargetPath(String targetPath) {
        this.targetPath = targetPath;
    }
}
