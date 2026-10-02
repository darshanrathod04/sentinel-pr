package com.sentinelpr.benchmark.model;

import java.util.ArrayList;
import java.util.List;

public class BenchmarkExecutionResult {

    private String caseId;
    private String ruleId;
    private String caseType;
    private String classification; // TRUE_POSITIVE, FALSE_POSITIVE, TRUE_NEGATIVE, FALSE_NEGATIVE
    private boolean detectionSuccess;
    private String detectionMismatch;
    private RemediationEvaluationResult remediationResult;

    // Timing measurements in nanoseconds
    private long inspectionDurationNs;
    private long evaluationDurationNs;
    private long remediationDurationNs;
    private long compilationDurationNs;
    private long totalDurationNs;

    private BenchmarkCase benchmarkCase;
    private List<String> diagnostics = new ArrayList<>();

    public BenchmarkExecutionResult() {}

    public BenchmarkCase getBenchmarkCase() { return benchmarkCase; }
    public void setBenchmarkCase(BenchmarkCase benchmarkCase) { this.benchmarkCase = benchmarkCase; }

    public boolean isTruePositive() { return "TRUE_POSITIVE".equalsIgnoreCase(classification); }
    public boolean isFalsePositive() { return "FALSE_POSITIVE".equalsIgnoreCase(classification); }
    public boolean isTrueNegative() { return "TRUE_NEGATIVE".equalsIgnoreCase(classification); }
    public boolean isFalseNegative() { return "FALSE_NEGATIVE".equalsIgnoreCase(classification); }

    public double getInspectionDurationMs() { return inspectionDurationNs / 1_000_000.0; }
    public double getEvaluationDurationMs() { return evaluationDurationNs / 1_000_000.0; }
    public double getRemediationDurationMs() { return remediationDurationNs / 1_000_000.0; }
    public double getCompilationDurationMs() { return compilationDurationNs / 1_000_000.0; }

    public String getCaseId() { return caseId; }
    public void setCaseId(String caseId) { this.caseId = caseId; }

    public String getRuleId() { return ruleId; }
    public void setRuleId(String ruleId) { this.ruleId = ruleId; }

    public String getCaseType() { return caseType; }
    public void setCaseType(String caseType) { this.caseType = caseType; }

    public String getClassification() { return classification; }
    public void setClassification(String classification) { this.classification = classification; }

    public boolean isDetectionSuccess() { return detectionSuccess; }
    public void setDetectionSuccess(boolean detectionSuccess) { this.detectionSuccess = detectionSuccess; }

    public String getDetectionMismatch() { return detectionMismatch; }
    public void setDetectionMismatch(String detectionMismatch) { this.detectionMismatch = detectionMismatch; }

    public RemediationEvaluationResult getRemediationResult() { return remediationResult; }
    public void setRemediationResult(RemediationEvaluationResult remediationResult) { this.remediationResult = remediationResult; }

    public long getInspectionDurationNs() { return inspectionDurationNs; }
    public void setInspectionDurationNs(long inspectionDurationNs) { this.inspectionDurationNs = inspectionDurationNs; }

    public long getEvaluationDurationNs() { return evaluationDurationNs; }
    public void setEvaluationDurationNs(long evaluationDurationNs) { this.evaluationDurationNs = evaluationDurationNs; }

    public long getRemediationDurationNs() { return remediationDurationNs; }
    public void setRemediationDurationNs(long remediationDurationNs) { this.remediationDurationNs = remediationDurationNs; }

    public long getCompilationDurationNs() { return compilationDurationNs; }
    public void setCompilationDurationNs(long compilationDurationNs) { this.compilationDurationNs = compilationDurationNs; }

    public long getTotalDurationNs() { return totalDurationNs; }
    public void setTotalDurationNs(long totalDurationNs) { this.totalDurationNs = totalDurationNs; }

    public double getTotalDurationMs() { return totalDurationNs / 1_000_000.0; }

    public List<String> getDiagnostics() { return diagnostics; }
    public void setDiagnostics(List<String> diagnostics) { this.diagnostics = diagnostics; }
}
