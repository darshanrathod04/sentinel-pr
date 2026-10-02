package com.sentinelpr.benchmark.model;

public class RuleRemediationStats {

    private String ruleId;
    private int remediationAttempted;
    private int successCount;
    private int compileSuccessCount;
    private int regressionFreeCount;
    private boolean applicable;

    public RuleRemediationStats() {}

    public RuleRemediationStats(String ruleId, int remediationAttempted, int successCount, int compileSuccessCount, int regressionFreeCount, boolean applicable) {
        this.ruleId = ruleId;
        this.remediationAttempted = remediationAttempted;
        this.successCount = successCount;
        this.compileSuccessCount = compileSuccessCount;
        this.regressionFreeCount = regressionFreeCount;
        this.applicable = applicable;
    }

    public String getRuleId() { return ruleId; }
    public void setRuleId(String ruleId) { this.ruleId = ruleId; }

    public int getRemediationAttempted() { return remediationAttempted; }
    public void setRemediationAttempted(int remediationAttempted) { this.remediationAttempted = remediationAttempted; }

    public int getSuccessCount() { return successCount; }
    public void setSuccessCount(int successCount) { this.successCount = successCount; }

    public int getCompileSuccessCount() { return compileSuccessCount; }
    public void setCompileSuccessCount(int compileSuccessCount) { this.compileSuccessCount = compileSuccessCount; }

    public int getRegressionFreeCount() { return regressionFreeCount; }
    public void setRegressionFreeCount(int regressionFreeCount) { this.regressionFreeCount = regressionFreeCount; }

    public boolean isApplicable() { return applicable; }
    public void setApplicable(boolean applicable) { this.applicable = applicable; }
}
