package com.sentinelpr.benchmark.model;

import java.util.List;
import java.util.Map;

public class BenchmarkReport {

    private String benchmarkVersion;
    private String timestamp;
    private Map<String, String> environment;

    // Summaries
    private BenchmarkSummary canonicalSummary;
    private BenchmarkSummary adversarialSummary;
    private BenchmarkSummary realisticSummary;
    private BenchmarkSummary crossFileSummary;
    private BenchmarkSummary combinedSummary;
    private BenchmarkSummary summary; // backward compatibility

    // Per-rule metrics
    private Map<String, ConfusionMatrix> perRuleMetrics;
    private Map<String, RuleRemediationStats> perRuleRemediation;

    // All execution results
    private List<BenchmarkExecutionResult> caseResults;

    public BenchmarkReport() {}

    public BenchmarkReport(String benchmarkVersion,
                           String timestamp,
                           Map<String, String> environment,
                           BenchmarkSummary canonicalSummary,
                           BenchmarkSummary adversarialSummary,
                           BenchmarkSummary combinedSummary,
                           Map<String, ConfusionMatrix> perRuleMetrics,
                           Map<String, RuleRemediationStats> perRuleRemediation,
                           List<BenchmarkExecutionResult> caseResults) {
        this(benchmarkVersion, timestamp, environment, canonicalSummary, adversarialSummary, null, null,
                combinedSummary, perRuleMetrics, perRuleRemediation, caseResults);
    }

    public BenchmarkReport(String benchmarkVersion,
                           String timestamp,
                           Map<String, String> environment,
                           BenchmarkSummary canonicalSummary,
                           BenchmarkSummary adversarialSummary,
                           BenchmarkSummary realisticSummary,
                           BenchmarkSummary combinedSummary,
                           Map<String, ConfusionMatrix> perRuleMetrics,
                           Map<String, RuleRemediationStats> perRuleRemediation,
                           List<BenchmarkExecutionResult> caseResults) {
        this(benchmarkVersion, timestamp, environment, canonicalSummary, adversarialSummary, realisticSummary, null,
                combinedSummary, perRuleMetrics, perRuleRemediation, caseResults);
    }

    public BenchmarkReport(String benchmarkVersion,
                           String timestamp,
                           Map<String, String> environment,
                           BenchmarkSummary canonicalSummary,
                           BenchmarkSummary adversarialSummary,
                           BenchmarkSummary realisticSummary,
                           BenchmarkSummary crossFileSummary,
                           BenchmarkSummary combinedSummary,
                           Map<String, ConfusionMatrix> perRuleMetrics,
                           Map<String, RuleRemediationStats> perRuleRemediation,
                           List<BenchmarkExecutionResult> caseResults) {
        this.benchmarkVersion = benchmarkVersion;
        this.timestamp = timestamp;
        this.environment = environment;
        this.canonicalSummary = canonicalSummary;
        this.adversarialSummary = adversarialSummary;
        this.realisticSummary = realisticSummary;
        this.crossFileSummary = crossFileSummary;
        this.combinedSummary = combinedSummary;
        this.summary = combinedSummary;
        this.perRuleMetrics = perRuleMetrics;
        this.perRuleRemediation = perRuleRemediation;
        this.caseResults = caseResults;
    }

    public String getBenchmarkVersion() { return benchmarkVersion; }
    public void setBenchmarkVersion(String benchmarkVersion) { this.benchmarkVersion = benchmarkVersion; }

    public String getTimestamp() { return timestamp; }
    public void setTimestamp(String timestamp) { this.timestamp = timestamp; }

    public Map<String, String> getEnvironment() { return environment; }
    public void setEnvironment(Map<String, String> environment) { this.environment = environment; }

    public BenchmarkSummary getCanonicalSummary() { return canonicalSummary; }
    public void setCanonicalSummary(BenchmarkSummary canonicalSummary) { this.canonicalSummary = canonicalSummary; }

    public BenchmarkSummary getAdversarialSummary() { return adversarialSummary; }
    public void setAdversarialSummary(BenchmarkSummary adversarialSummary) { this.adversarialSummary = adversarialSummary; }

    public BenchmarkSummary getRealisticSummary() { return realisticSummary; }
    public void setRealisticSummary(BenchmarkSummary realisticSummary) { this.realisticSummary = realisticSummary; }

    public BenchmarkSummary getCrossFileSummary() { return crossFileSummary; }
    public void setCrossFileSummary(BenchmarkSummary crossFileSummary) { this.crossFileSummary = crossFileSummary; }

    public BenchmarkSummary getCombinedSummary() { return combinedSummary; }
    public void setCombinedSummary(BenchmarkSummary combinedSummary) {
        this.combinedSummary = combinedSummary;
        this.summary = combinedSummary;
    }

    public BenchmarkSummary getSummary() {
        return combinedSummary != null ? combinedSummary : summary;
    }

    public void setSummary(BenchmarkSummary summary) {
        this.summary = summary;
        if (this.combinedSummary == null) {
            this.combinedSummary = summary;
        }
    }

    public Map<String, ConfusionMatrix> getPerRuleMetrics() { return perRuleMetrics; }
    public void setPerRuleMetrics(Map<String, ConfusionMatrix> perRuleMetrics) { this.perRuleMetrics = perRuleMetrics; }

    public Map<String, RuleRemediationStats> getPerRuleRemediation() { return perRuleRemediation; }
    public void setPerRuleRemediation(Map<String, RuleRemediationStats> perRuleRemediation) { this.perRuleRemediation = perRuleRemediation; }

    public List<BenchmarkExecutionResult> getCaseResults() { return caseResults; }
    public void setCaseResults(List<BenchmarkExecutionResult> caseResults) { this.caseResults = caseResults; }
}
