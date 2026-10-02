package com.sentinelpr.benchmark.report;

import com.sentinelpr.benchmark.model.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

public class MarkdownBenchmarkReporter {

    public void writeReport(BenchmarkReport report, Path outputPath) throws IOException {
        if (outputPath.getParent() != null && !Files.exists(outputPath.getParent())) {
            Files.createDirectories(outputPath.getParent());
        }
        String md = generateMarkdown(report);
        Files.writeString(outputPath, md);
    }

    public String generateMarkdown(BenchmarkReport report) {
        StringBuilder sb = new StringBuilder();

        sb.append("# SentinelPR v1.2 Reliability & Benchmarking Report\n\n");
        sb.append("**Evaluation Date:** ").append(report.getTimestamp()).append("  \n");
        sb.append("**Benchmark Version:** v").append(report.getBenchmarkVersion()).append("  \n");

        if (report.getEnvironment() != null) {
            sb.append("**Environment:** `")
              .append(report.getEnvironment().getOrDefault("os.name", "Unknown OS")).append(" ")
              .append(report.getEnvironment().getOrDefault("os.arch", "")).append("`, Java `")
              .append(report.getEnvironment().getOrDefault("java.version", "Unknown")).append("` (")
              .append(report.getEnvironment().getOrDefault("java.vendor", "")).append("), ")
              .append(report.getEnvironment().getOrDefault("availableProcessors", "?")).append(" cores, max memory: ")
              .append(report.getEnvironment().getOrDefault("maxMemoryMb", "?")).append(" MB\n\n");
        }

        sb.append("---\n\n");

        // 1. CANONICAL BASELINE
        if (report.getCanonicalSummary() != null) {
            sb.append("## 1. Canonical Baseline Suite (26 Cases)\n\n");
            renderSummaryBlock(sb, report.getCanonicalSummary(), "Canonical Baseline");
            sb.append("---\n\n");
        }

        // 2. ADVERSARIAL SUITE
        if (report.getAdversarialSummary() != null && report.getAdversarialSummary().getTotalCases() > 0) {
            sb.append("## 2. Adversarial Evaluation Suite (50 Cases)\n\n");
            renderSummaryBlock(sb, report.getAdversarialSummary(), "Adversarial Suite");
            sb.append("---\n\n");
        }

        // 3. REALISTIC SUITE
        if (report.getRealisticSummary() != null && report.getRealisticSummary().getTotalCases() > 0) {
            sb.append(String.format("## 3. Realistic Enterprise Suite (%d Cases)\n\n", report.getRealisticSummary().getTotalCases()));
            renderSummaryBlock(sb, report.getRealisticSummary(), "Realistic Enterprise Suite");
            sb.append("---\n\n");
        }

        // 4. CROSS-FILE SUITE
        if (report.getCrossFileSummary() != null && report.getCrossFileSummary().getTotalCases() > 0) {
            sb.append(String.format("## 4. True Cross-File Inter-Procedural Suite (%d Cases)\n\n", report.getCrossFileSummary().getTotalCases()));
            renderSummaryBlock(sb, report.getCrossFileSummary(), "Cross-File Suite");
            sb.append("---\n\n");
        }

        // 5. COMBINED RESULT
        BenchmarkSummary combined = report.getCombinedSummary() != null ? report.getCombinedSummary() : report.getSummary();
        if (combined != null) {
            int combinedSectionNum = (report.getCrossFileSummary() != null && report.getCrossFileSummary().getTotalCases() > 0) ? 5 : 4;
            sb.append(String.format("## %d. Combined Benchmark Results\n\n", combinedSectionNum));
            renderSummaryBlock(sb, combined, "Combined Suite");
            sb.append("---\n\n");
        }

        int ruleMetricsSectionNum = (report.getCrossFileSummary() != null && report.getCrossFileSummary().getTotalCases() > 0) ? 6 : 5;
        sb.append(String.format("## %d. Per-Rule Detection Confusion Matrix Breakdown\n\n", ruleMetricsSectionNum));
        sb.append("| Rule Identifier | TP | FP | TN | FN | Precision | Recall | F1 | FPR | FNR |\n");
        sb.append("| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |\n");

        if (report.getPerRuleMetrics() != null) {
            for (Map.Entry<String, ConfusionMatrix> entry : report.getPerRuleMetrics().entrySet()) {
                String rule = entry.getKey();
                ConfusionMatrix cm = entry.getValue();
                sb.append(String.format("| `%s` | %d | %d | %d | %d | %.1f%% | %.1f%% | %.1f%% | %.1f%% | %.1f%% |\n",
                        rule,
                        cm.getTruePositives(),
                        cm.getFalsePositives(),
                        cm.getTrueNegatives(),
                        cm.getFalseNegatives(),
                        cm.getPrecision() * 100.0,
                        cm.getRecall() * 100.0,
                        cm.getF1Score() * 100.0,
                        cm.getFalsePositiveRate() * 100.0,
                        cm.getFalseNegativeRate() * 100.0));
            }
        }
        sb.append("\n");

        int remSectionNum = (report.getCrossFileSummary() != null && report.getCrossFileSummary().getTotalCases() > 0) ? 7 : 6;
        sb.append(String.format("## %d. Per-Rule Remediation Quality Breakdown\n\n", remSectionNum));
        sb.append("| Rule Identifier | Attempted | Success | Compile Success | Regression-Free | Status |\n");
        sb.append("| :--- | :---: | :---: | :---: | :---: | :---: |\n");

        if (report.getPerRuleRemediation() != null) {
            for (Map.Entry<String, RuleRemediationStats> entry : report.getPerRuleRemediation().entrySet()) {
                RuleRemediationStats rrs = entry.getValue();
                if (!rrs.isApplicable() || rrs.getRemediationAttempted() == 0) {
                    sb.append(String.format("| `%s` | 0 | N/A | N/A | N/A | N/A (Architecture / Non-Remediable) |\n", entry.getKey()));
                } else {
                    sb.append(String.format("| `%s` | %d | %d (%.0f%%) | %d (%.0f%%) | %d (%.0f%%) | %s |\n",
                            entry.getKey(),
                            rrs.getRemediationAttempted(),
                            rrs.getSuccessCount(),
                            (double) rrs.getSuccessCount() * 100.0 / rrs.getRemediationAttempted(),
                            rrs.getCompileSuccessCount(),
                            (double) rrs.getCompileSuccessCount() * 100.0 / rrs.getRemediationAttempted(),
                            rrs.getRegressionFreeCount(),
                            (double) rrs.getRegressionFreeCount() * 100.0 / rrs.getRemediationAttempted(),
                            rrs.getSuccessCount() == rrs.getRemediationAttempted() ? "PASS" : "INSPECT"));
                }
            }
        }
        sb.append("\n");

        int logSectionNum = (report.getCrossFileSummary() != null && report.getCrossFileSummary().getTotalCases() > 0) ? 8 : 7;
        sb.append(String.format("## %d. Detailed Case-by-Case Execution Log\n\n", logSectionNum));
        sb.append("| Case ID | Suite | Rule | Type | Classification | Remediation | Regressions (C/H/M/L) | Time |\n");
        sb.append("| :--- | :--- | :--- | :--- | :--- | :--- | :---: | :---: |\n");

        if (report.getCaseResults() != null) {
            for (BenchmarkExecutionResult res : report.getCaseResults()) {
                String suite = res.getBenchmarkCase() != null ? res.getBenchmarkCase().getSuite() : "UNKNOWN";
                String remStatus = "N/A";
                String regCounts = "0/0/0/0";
                if (res.getRemediationResult() != null) {
                    RemediationEvaluationResult rem = res.getRemediationResult();
                    remStatus = rem.isOverallSuccess() ? "SUCCESS" : "FAILED (" + rem.getFailureStage() + ")";
                    regCounts = String.format("%d/%d/%d/%d",
                            rem.getNewCriticalFindings(),
                            rem.getNewHighFindings(),
                            rem.getNewMediumFindings(),
                            rem.getNewLowFindings());
                }
                sb.append(String.format("| `%s` | %s | `%s` | %s | **%s** | %s | `%s` | %.1f ms |\n",
                        res.getCaseId(),
                        suite,
                        res.getRuleId(),
                        res.getCaseType(),
                        res.getClassification(),
                        remStatus,
                        regCounts,
                        res.getTotalDurationMs()));
            }
        }

        return sb.toString();
    }

    private void renderSummaryBlock(StringBuilder sb, BenchmarkSummary s, String title) {
        sb.append("### ").append(title).append(" — Detection Confusion Matrix\n\n");
        sb.append("| Metric | Count / Value | Description |\n");
        sb.append("| :--- | :--- | :--- |\n");
        sb.append(String.format("| **Total Test Cases** | `%d` | %d Vulnerable + %d Safe Fixtures |\n",
                s.getTotalCases(), s.getVulnerableCases(), s.getSafeCases()));
        sb.append(String.format("| **True Positives (TP)** | `%d` | Vulnerable cases correctly flagged |\n", s.getTruePositives()));
        sb.append(String.format("| **False Positives (FP)** | `%d` | Safe cases incorrectly flagged |\n", s.getFalsePositives()));
        sb.append(String.format("| **True Negatives (TN)** | `%d` | Safe cases correctly passed |\n", s.getTrueNegatives()));
        sb.append(String.format("| **False Negatives (FN)** | `%d` | Vulnerable cases missed |\n", s.getFalseNegatives()));
        sb.append(String.format("| **Precision** | `%.2f%%` | TP / (TP + FP) |\n", s.getPrecision() * 100.0));
        sb.append(String.format("| **Recall** | `%.2f%%` | TP / (TP + FN) |\n", s.getRecall() * 100.0));
        sb.append(String.format("| **F1-Score** | `%.2f%%` | Harmonic mean of Precision and Recall |\n", s.getF1Score() * 100.0));
        sb.append(String.format("| **False Positive Rate (FPR)** | `%.2f%%` | FP / (FP + TN) |\n", s.getFalsePositiveRate() * 100.0));
        sb.append(String.format("| **False Negative Rate (FNR)** | `%.2f%%` | FN / (FN + TP) |\n", s.getFalseNegativeRate() * 100.0));
        sb.append("\n");

        sb.append("### ").append(title).append(" — Automated Remediation Quality\n\n");
        sb.append("| Stage / Metric | Count / Rate | Target Threshold | Status |\n");
        sb.append("| :--- | :--- | :--- | :--- |\n");
        sb.append(String.format("| **Remediation Attempted** | `%d` | N/A | Completed |\n", s.getRemediationAttempted()));
        sb.append(String.format("| **Patch Generated** | `%d / %d` | 100%% | %s |\n",
                s.getPatchesGenerated(), s.getRemediationAttempted(),
                s.getPatchesGenerated() == s.getRemediationAttempted() ? "PASS" : "WARN"));
        sb.append(String.format("| **Patch Valid (Diff + AST)** | `%d / %d` | 100%% | %s |\n",
                s.getAstValidPatches(), s.getRemediationAttempted(),
                s.getAstValidPatches() == s.getRemediationAttempted() ? "PASS" : "WARN"));
        sb.append(String.format("| **Clean Application** | `%d / %d` | 100%% | %s |\n",
                s.getCleanApplyingPatches(), s.getRemediationAttempted(),
                s.getCleanApplyingPatches() == s.getRemediationAttempted() ? "PASS" : "WARN"));
        sb.append(String.format("| **In-Memory Compilation** | `%d / %d` | 100%% | %s |\n",
                s.getCompilablePatches(), s.getRemediationAttempted(),
                s.getCompilablePatches() == s.getRemediationAttempted() ? "PASS" : "WARN"));
        sb.append(String.format("| **Target Finding Removed** | `%d / %d` | 100%% | %s |\n",
                s.getTargetFindingRemovedPatches(), s.getRemediationAttempted(),
                s.getTargetFindingRemovedPatches() == s.getRemediationAttempted() ? "PASS" : "WARN"));
        sb.append(String.format("| **Regression-Free (C/H/M = 0)** | `%d / %d` | 100%% | %s |\n",
                s.getRegressionFreePatches(), s.getRemediationAttempted(),
                s.getRegressionFreePatches() == s.getRemediationAttempted() ? "PASS" : "WARN"));
        sb.append(String.format("| **Full Remediation Success** | `%.2f%%` (`%d / %d`) | 100%% | %s |\n",
                s.getRemediationSuccessRate() * 100.0, s.getFullySuccessfulRemediations(), s.getRemediationAttempted(),
                s.getFullySuccessfulRemediations() == s.getRemediationAttempted() ? "PASS" : "INSPECT"));
        sb.append("\n");

        sb.append("### ").append(title).append(" — Regressions Introduced\n\n");
        sb.append("| Severity | Count | Classification |\n");
        sb.append("| :--- | :---: | :--- |\n");
        sb.append(String.format("| **New Critical Findings** | `%d` | Blocking Regression |\n", s.getNewCriticalFindings()));
        sb.append(String.format("| **New High Findings** | `%d` | Blocking Regression |\n", s.getNewHighFindings()));
        sb.append(String.format("| **New Medium Findings** | `%d` | Blocking Regression |\n", s.getNewMediumFindings()));
        sb.append(String.format("| **New Low Findings** | `%d` | Tracked Separately (Non-Blocking) |\n", s.getNewLowFindings()));
        sb.append("\n");

        sb.append("### ").append(title).append(" — Latency Profile\n\n");
        sb.append("| Execution Phase | Mean Latency | Details |\n");
        sb.append("| :--- | :--- | :--- |\n");
        sb.append(String.format("| **AST & Source Inspection** | `%.2f ms` | Java AST parsing & model instantiation |\n", s.getMeanInspectionDurationMs()));
        sb.append(String.format("| **Security Rule Evaluation** | `%.2f ms` | Pattern matching & taint reasoning |\n", s.getMeanEvaluationDurationMs()));
        sb.append(String.format("| **Remediation & Patching** | `%.2f ms` | AST rewrite & diff generation |\n", s.getMeanRemediationDurationMs()));
        sb.append(String.format("| **In-Memory Compilation** | `%.2f ms` | JDK javax.tools compilation |\n", s.getMeanCompilationDurationMs()));
        sb.append(String.format("| **Total Suite Time** | `%.2f ms` | Total execution duration |\n", s.getTotalDurationMs()));
        sb.append(String.format("| **Throughput** | `%.2f cases/sec` | Cases processed per second |\n", s.getThroughputCasesPerSec()));
        sb.append("\n\n");
    }
}
