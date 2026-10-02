package com.sentinelpr.benchmark.model;

public class BenchmarkSummary {

    private int totalCases;
    private int vulnerableCases;
    private int safeCases;

    // Detection Confusion Matrix
    private int truePositives;
    private int falsePositives;
    private int trueNegatives;
    private int falseNegatives;

    private double precision;
    private double recall;
    private double f1Score;
    private double falsePositiveRate;
    private double falseNegativeRate;

    // Remediation Metrics
    private int remediationAttempted;
    private int patchesGenerated;
    private int patchesValid;
    private int astValidPatches;
    private int cleanApplyingPatches;
    private int compilablePatches;
    private int targetFindingRemovedPatches;
    private int regressionFreePatches;
    private int fullySuccessfulRemediations;
    private double remediationSuccessRate;
    private double compilationSuccessRate;
    private double regressionFreeRate;

    // Explicit Regression Metrics
    private int newCriticalFindings;
    private int newHighFindings;
    private int newMediumFindings;
    private int newLowFindings;

    // Performance Metrics
    private double totalDurationMs;
    private double meanInspectionDurationMs;
    private double meanEvaluationDurationMs;
    private double meanRemediationDurationMs;
    private double meanCompilationDurationMs;
    private double throughputCasesPerSec;

    public BenchmarkSummary() {}

    public int getTotalCases() { return totalCases; }
    public void setTotalCases(int totalCases) { this.totalCases = totalCases; }

    public int getVulnerableCases() { return vulnerableCases; }
    public void setVulnerableCases(int vulnerableCases) { this.vulnerableCases = vulnerableCases; }

    public int getSafeCases() { return safeCases; }
    public void setSafeCases(int safeCases) { this.safeCases = safeCases; }

    public int getTruePositives() { return truePositives; }
    public void setTruePositives(int truePositives) { this.truePositives = truePositives; }

    public int getFalsePositives() { return falsePositives; }
    public void setFalsePositives(int falsePositives) { this.falsePositives = falsePositives; }

    public int getTrueNegatives() { return trueNegatives; }
    public void setTrueNegatives(int trueNegatives) { this.trueNegatives = trueNegatives; }

    public int getFalseNegatives() { return falseNegatives; }
    public void setFalseNegatives(int falseNegatives) { this.falseNegatives = falseNegatives; }

    public double getPrecision() { return precision; }
    public void setPrecision(double precision) { this.precision = precision; }

    public double getRecall() { return recall; }
    public void setRecall(double recall) { this.recall = recall; }

    public double getF1Score() { return f1Score; }
    public void setF1Score(double f1Score) { this.f1Score = f1Score; }

    public double getFalsePositiveRate() { return falsePositiveRate; }
    public void setFalsePositiveRate(double falsePositiveRate) { this.falsePositiveRate = falsePositiveRate; }

    public double getFalseNegativeRate() { return falseNegativeRate; }
    public void setFalseNegativeRate(double falseNegativeRate) { this.falseNegativeRate = falseNegativeRate; }

    public int getRemediationAttempted() { return remediationAttempted; }
    public void setRemediationAttempted(int remediationAttempted) { this.remediationAttempted = remediationAttempted; }

    public int getPatchesGenerated() { return patchesGenerated; }
    public void setPatchesGenerated(int patchesGenerated) { this.patchesGenerated = patchesGenerated; }

    public int getAstValidPatches() { return astValidPatches; }
    public void setAstValidPatches(int astValidPatches) { this.astValidPatches = astValidPatches; }

    public int getCleanApplyingPatches() { return cleanApplyingPatches; }
    public void setCleanApplyingPatches(int cleanApplyingPatches) { this.cleanApplyingPatches = cleanApplyingPatches; }

    public int getCompilablePatches() { return compilablePatches; }
    public void setCompilablePatches(int compilablePatches) { this.compilablePatches = compilablePatches; }

    public int getRegressionFreePatches() { return regressionFreePatches; }
    public void setRegressionFreePatches(int regressionFreePatches) { this.regressionFreePatches = regressionFreePatches; }

    public int getFullySuccessfulRemediations() { return fullySuccessfulRemediations; }
    public void setFullySuccessfulRemediations(int fullySuccessfulRemediations) { this.fullySuccessfulRemediations = fullySuccessfulRemediations; }

    public double getRemediationSuccessRate() { return remediationSuccessRate; }
    public void setRemediationSuccessRate(double remediationSuccessRate) { this.remediationSuccessRate = remediationSuccessRate; }

    public double getCompilationSuccessRate() { return compilationSuccessRate; }
    public void setCompilationSuccessRate(double compilationSuccessRate) { this.compilationSuccessRate = compilationSuccessRate; }

    public double getRegressionFreeRate() { return regressionFreeRate; }
    public void setRegressionFreeRate(double regressionFreeRate) { this.regressionFreeRate = regressionFreeRate; }

    public double getTotalDurationMs() { return totalDurationMs; }
    public void setTotalDurationMs(double totalDurationMs) { this.totalDurationMs = totalDurationMs; }

    public double getMeanInspectionDurationMs() { return meanInspectionDurationMs; }
    public void setMeanInspectionDurationMs(double meanInspectionDurationMs) { this.meanInspectionDurationMs = meanInspectionDurationMs; }

    public double getMeanEvaluationDurationMs() { return meanEvaluationDurationMs; }
    public void setMeanEvaluationDurationMs(double meanEvaluationDurationMs) { this.meanEvaluationDurationMs = meanEvaluationDurationMs; }

    public double getMeanRemediationDurationMs() { return meanRemediationDurationMs; }
    public void setMeanRemediationDurationMs(double meanRemediationDurationMs) { this.meanRemediationDurationMs = meanRemediationDurationMs; }

    public double getMeanCompilationDurationMs() { return meanCompilationDurationMs; }
    public void setMeanCompilationDurationMs(double meanCompilationDurationMs) { this.meanCompilationDurationMs = meanCompilationDurationMs; }

    public double getThroughputCasesPerSec() { return throughputCasesPerSec; }
    public void setThroughputCasesPerSec(double throughputCasesPerSec) { this.throughputCasesPerSec = throughputCasesPerSec; }

    public int getPatchesValid() { return patchesValid; }
    public void setPatchesValid(int patchesValid) { this.patchesValid = patchesValid; }

    public int getTargetFindingRemovedPatches() { return targetFindingRemovedPatches; }
    public void setTargetFindingRemovedPatches(int targetFindingRemovedPatches) { this.targetFindingRemovedPatches = targetFindingRemovedPatches; }

    public int getNewCriticalFindings() { return newCriticalFindings; }
    public void setNewCriticalFindings(int newCriticalFindings) { this.newCriticalFindings = newCriticalFindings; }

    public int getNewHighFindings() { return newHighFindings; }
    public void setNewHighFindings(int newHighFindings) { this.newHighFindings = newHighFindings; }

    public int getNewMediumFindings() { return newMediumFindings; }
    public void setNewMediumFindings(int newMediumFindings) { this.newMediumFindings = newMediumFindings; }

    public int getNewLowFindings() { return newLowFindings; }
    public void setNewLowFindings(int newLowFindings) { this.newLowFindings = newLowFindings; }
}
