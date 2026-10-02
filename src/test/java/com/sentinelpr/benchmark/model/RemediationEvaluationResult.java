package com.sentinelpr.benchmark.model;

import java.util.ArrayList;
import java.util.List;

public class RemediationEvaluationResult {

    private boolean patchGenerated;
    private boolean unifiedDiffValid;
    private boolean appliesCleanly;
    private boolean astValid;
    private boolean compilesSuccessfully;
    private boolean targetFindingRemoved;
    private boolean regressionFree;
    private boolean tokenIntegrityVerified;
    private boolean overallSuccess;
    private String failureStage;
    private String failureReason;
    private String generatedDiff;
    private List<String> compilerDiagnostics = new ArrayList<>();
    private double remediationDurationMs;
    private double compilationDurationMs;

    // Explicit regression metrics
    private int newCriticalFindings;
    private int newHighFindings;
    private int newMediumFindings;
    private int newLowFindings;
    private List<String> newRegressedFindingDetails = new ArrayList<>();

    public RemediationEvaluationResult() {}

    public int getNewCriticalFindings() { return newCriticalFindings; }
    public void setNewCriticalFindings(int newCriticalFindings) { this.newCriticalFindings = newCriticalFindings; }

    public int getNewHighFindings() { return newHighFindings; }
    public void setNewHighFindings(int newHighFindings) { this.newHighFindings = newHighFindings; }

    public int getNewMediumFindings() { return newMediumFindings; }
    public void setNewMediumFindings(int newMediumFindings) { this.newMediumFindings = newMediumFindings; }

    public int getNewLowFindings() { return newLowFindings; }
    public void setNewLowFindings(int newLowFindings) { this.newLowFindings = newLowFindings; }

    public List<String> getNewRegressedFindingDetails() { return newRegressedFindingDetails; }
    public void setNewRegressedFindingDetails(List<String> newRegressedFindingDetails) { this.newRegressedFindingDetails = newRegressedFindingDetails; }

    public double getRemediationDurationMs() { return remediationDurationMs; }
    public void setRemediationDurationMs(double remediationDurationMs) { this.remediationDurationMs = remediationDurationMs; }

    public double getCompilationDurationMs() { return compilationDurationMs; }
    public void setCompilationDurationMs(double compilationDurationMs) { this.compilationDurationMs = compilationDurationMs; }

    public boolean isPatchGenerated() { return patchGenerated; }
    public void setPatchGenerated(boolean patchGenerated) { this.patchGenerated = patchGenerated; }

    public boolean isUnifiedDiffValid() { return unifiedDiffValid; }
    public void setUnifiedDiffValid(boolean unifiedDiffValid) { this.unifiedDiffValid = unifiedDiffValid; }

    public boolean isAppliesCleanly() { return appliesCleanly; }
    public void setAppliesCleanly(boolean appliesCleanly) { this.appliesCleanly = appliesCleanly; }

    public boolean isAstValid() { return astValid; }
    public void setAstValid(boolean astValid) { this.astValid = astValid; }

    public boolean isCompilesSuccessfully() { return compilesSuccessfully; }
    public void setCompilesSuccessfully(boolean compilesSuccessfully) { this.compilesSuccessfully = compilesSuccessfully; }

    public boolean isTargetFindingRemoved() { return targetFindingRemoved; }
    public void setTargetFindingRemoved(boolean targetFindingRemoved) { this.targetFindingRemoved = targetFindingRemoved; }

    public boolean isRegressionFree() { return regressionFree; }
    public void setRegressionFree(boolean regressionFree) { this.regressionFree = regressionFree; }

    public boolean isTokenIntegrityVerified() { return tokenIntegrityVerified; }
    public void setTokenIntegrityVerified(boolean tokenIntegrityVerified) { this.tokenIntegrityVerified = tokenIntegrityVerified; }

    public boolean isOverallSuccess() { return overallSuccess; }
    public void setOverallSuccess(boolean overallSuccess) { this.overallSuccess = overallSuccess; }

    public String getFailureStage() { return failureStage; }
    public void setFailureStage(String failureStage) { this.failureStage = failureStage; }

    public String getFailureReason() { return failureReason; }
    public void setFailureReason(String failureReason) { this.failureReason = failureReason; }

    public String getGeneratedDiff() { return generatedDiff; }
    public void setGeneratedDiff(String generatedDiff) { this.generatedDiff = generatedDiff; }

    public List<String> getCompilerDiagnostics() { return compilerDiagnostics; }
    public void setCompilerDiagnostics(List<String> compilerDiagnostics) { this.compilerDiagnostics = compilerDiagnostics; }
}
