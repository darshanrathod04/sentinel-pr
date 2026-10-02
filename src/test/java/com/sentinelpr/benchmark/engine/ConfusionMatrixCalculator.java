package com.sentinelpr.benchmark.engine;

import com.sentinelpr.benchmark.model.*;

import java.util.*;

public class ConfusionMatrixCalculator {

    public Map<String, ConfusionMatrix> computePerRuleMetrics(List<BenchmarkExecutionResult> results) {
        Map<String, ConfusionMatrix> map = new TreeMap<>();
        for (BenchmarkExecutionResult res : results) {
            String ruleId = res.getBenchmarkCase().getTargetRuleId();
            ConfusionMatrix cm = map.computeIfAbsent(ruleId, k -> new ConfusionMatrix());
            if (res.isTruePositive()) {
                cm.incrementTP();
            } else if (res.isFalsePositive()) {
                cm.incrementFP();
            } else if (res.isTrueNegative()) {
                cm.incrementTN();
            } else if (res.isFalseNegative()) {
                cm.incrementFN();
            }
        }
        return map;
    }

    public Map<String, RuleRemediationStats> computePerRuleRemediation(List<BenchmarkExecutionResult> results) {
        Map<String, RuleRemediationStats> map = new TreeMap<>();
        for (BenchmarkExecutionResult res : results) {
            String ruleId = res.getBenchmarkCase().getTargetRuleId();
            RuleRemediationStats stats = map.computeIfAbsent(ruleId, k -> {
                boolean applicable = !k.contains("ARCH-001") && !k.contains("ARCH-003");
                return new RuleRemediationStats(k, 0, 0, 0, 0, applicable);
            });

            RemediationEvaluationResult rem = res.getRemediationResult();
            if (rem != null) {
                stats.setRemediationAttempted(stats.getRemediationAttempted() + 1);
                if (rem.isOverallSuccess()) {
                    stats.setSuccessCount(stats.getSuccessCount() + 1);
                }
                if (rem.isCompilesSuccessfully()) {
                    stats.setCompileSuccessCount(stats.getCompileSuccessCount() + 1);
                }
                if (rem.isRegressionFree()) {
                    stats.setRegressionFreeCount(stats.getRegressionFreeCount() + 1);
                }
            }
        }
        return map;
    }

    public BenchmarkSummary computeSummary(List<BenchmarkExecutionResult> results, double totalDurationMs) {
        BenchmarkSummary summary = new BenchmarkSummary();
        summary.setTotalCases(results.size());
        summary.setTotalDurationMs(totalDurationMs);

        int vulnCases = 0;
        int safeCases = 0;
        int tp = 0;
        int fp = 0;
        int tn = 0;
        int fn = 0;

        int remediationAttempted = 0;
        int patchesGenerated = 0;
        int patchesValid = 0;
        int astValid = 0;
        int cleanApplying = 0;
        int compilable = 0;
        int targetFindingRemoved = 0;
        int regressionFree = 0;
        int fullySuccessful = 0;

        int newCritical = 0;
        int newHigh = 0;
        int newMedium = 0;
        int newLow = 0;

        double sumInspectionMs = 0;
        double sumEvaluationMs = 0;
        double sumRemediationMs = 0;
        double sumCompilationMs = 0;
        int remediationCount = 0;
        int compilationCount = 0;

        for (BenchmarkExecutionResult res : results) {
            if (res.getBenchmarkCase().isVulnerable()) {
                vulnCases++;
            } else {
                safeCases++;
            }

            if (res.isTruePositive()) tp++;
            if (res.isFalsePositive()) fp++;
            if (res.isTrueNegative()) tn++;
            if (res.isFalseNegative()) fn++;

            sumInspectionMs += res.getInspectionDurationMs();
            sumEvaluationMs += res.getEvaluationDurationMs();

            RemediationEvaluationResult rem = res.getRemediationResult();
            if (rem != null) {
                remediationAttempted++;
                sumRemediationMs += rem.getRemediationDurationMs();
                remediationCount++;

                if (rem.isPatchGenerated()) patchesGenerated++;
                if (rem.isUnifiedDiffValid() && rem.isAstValid()) patchesValid++;
                if (rem.isAstValid()) astValid++;
                if (rem.isAppliesCleanly()) cleanApplying++;
                if (rem.isCompilesSuccessfully()) compilable++;
                if (rem.isTargetFindingRemoved()) targetFindingRemoved++;
                if (rem.isRegressionFree()) regressionFree++;
                if (rem.isOverallSuccess()) fullySuccessful++;

                newCritical += rem.getNewCriticalFindings();
                newHigh += rem.getNewHighFindings();
                newMedium += rem.getNewMediumFindings();
                newLow += rem.getNewLowFindings();

                if (rem.getCompilationDurationMs() > 0) {
                    sumCompilationMs += rem.getCompilationDurationMs();
                    compilationCount++;
                }
            }
        }

        summary.setVulnerableCases(vulnCases);
        summary.setSafeCases(safeCases);
        summary.setTruePositives(tp);
        summary.setFalsePositives(fp);
        summary.setTrueNegatives(tn);
        summary.setFalseNegatives(fn);

        // Rates
        int posDenom = tp + fp;
        summary.setPrecision(posDenom > 0 ? (double) tp / posDenom : (fn == 0 ? 1.0 : 0.0));

        int recallDenom = tp + fn;
        summary.setRecall(recallDenom > 0 ? (double) tp / recallDenom : 1.0);

        double p = summary.getPrecision();
        double r = summary.getRecall();
        summary.setF1Score((p + r > 0) ? (2.0 * p * r) / (p + r) : 0.0);

        int fprDenom = fp + tn;
        summary.setFalsePositiveRate(fprDenom > 0 ? (double) fp / fprDenom : 0.0);

        int fnrDenom = fn + tp;
        summary.setFalseNegativeRate(fnrDenom > 0 ? (double) fn / fnrDenom : 0.0);

        // Remediation metrics
        summary.setRemediationAttempted(remediationAttempted);
        summary.setPatchesGenerated(patchesGenerated);
        summary.setPatchesValid(patchesValid);
        summary.setAstValidPatches(astValid);
        summary.setCleanApplyingPatches(cleanApplying);
        summary.setCompilablePatches(compilable);
        summary.setTargetFindingRemovedPatches(targetFindingRemoved);
        summary.setRegressionFreePatches(regressionFree);
        summary.setFullySuccessfulRemediations(fullySuccessful);

        summary.setNewCriticalFindings(newCritical);
        summary.setNewHighFindings(newHigh);
        summary.setNewMediumFindings(newMedium);
        summary.setNewLowFindings(newLow);

        if (remediationAttempted > 0) {
            summary.setRemediationSuccessRate((double) fullySuccessful / remediationAttempted);
            summary.setCompilationSuccessRate((double) compilable / remediationAttempted);
            summary.setRegressionFreeRate((double) regressionFree / remediationAttempted);
        }

        // Performance metrics
        int n = results.isEmpty() ? 1 : results.size();
        summary.setMeanInspectionDurationMs(sumInspectionMs / n);
        summary.setMeanEvaluationDurationMs(sumEvaluationMs / n);
        summary.setMeanRemediationDurationMs(remediationCount > 0 ? sumRemediationMs / remediationCount : 0.0);
        summary.setMeanCompilationDurationMs(compilationCount > 0 ? sumCompilationMs / compilationCount : 0.0);

        if (totalDurationMs > 0) {
            summary.setThroughputCasesPerSec((results.size() * 1000.0) / totalDurationMs);
        }

        return summary;
    }
}
