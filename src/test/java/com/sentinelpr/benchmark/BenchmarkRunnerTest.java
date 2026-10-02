package com.sentinelpr.benchmark;

import com.sentinelpr.benchmark.engine.BenchmarkEngine;
import com.sentinelpr.benchmark.model.BenchmarkExecutionResult;
import com.sentinelpr.benchmark.model.BenchmarkReport;
import com.sentinelpr.benchmark.model.BenchmarkSummary;
import com.sentinelpr.benchmark.report.JsonBenchmarkReporter;
import com.sentinelpr.benchmark.report.MarkdownBenchmarkReporter;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

public class BenchmarkRunnerTest {

    @Test
    @DisplayName("Execute Full Reliability Benchmark Suite: Canonical Baseline (26) + Adversarial Suite (50) + Realistic Enterprise Suite (30) + Cross-File Pilot (2) = 108 Cases")
    void executeReliabilityBenchmark() throws Exception {
        BenchmarkEngine engine = new BenchmarkEngine();
        BenchmarkReport report = engine.runBenchmark();

        assertNotNull(report, "Benchmark report should not be null");

        BenchmarkSummary canonical = report.getCanonicalSummary();
        BenchmarkSummary adversarial = report.getAdversarialSummary();
        BenchmarkSummary realistic = report.getRealisticSummary();
        BenchmarkSummary crossFile = report.getCrossFileSummary();
        BenchmarkSummary combined = report.getCombinedSummary();

        assertNotNull(canonical, "Canonical summary should not be null");
        assertNotNull(adversarial, "Adversarial summary should not be null");
        assertNotNull(realistic, "Realistic summary should not be null");
        assertNotNull(crossFile, "Cross-file summary should not be null");
        assertNotNull(combined, "Combined summary should not be null");

        // 1. Verify Canonical Baseline Preservation
        assertEquals(26, canonical.getTotalCases(), "Canonical baseline must contain exactly 26 atomic cases");
        assertEquals(13, canonical.getVulnerableCases(), "Canonical baseline must contain exactly 13 vulnerable fixtures");
        assertEquals(13, canonical.getSafeCases(), "Canonical baseline must contain exactly 13 safe fixtures");
        assertEquals(13, canonical.getTruePositives(), "Canonical baseline TP must be exactly 13");
        assertEquals(0, canonical.getFalsePositives(), "Canonical baseline FP must be exactly 0");
        assertEquals(13, canonical.getTrueNegatives(), "Canonical baseline TN must be exactly 13");
        assertEquals(0, canonical.getFalseNegatives(), "Canonical baseline FN must be exactly 0");
        assertEquals(1.0, canonical.getPrecision(), 1e-6, "Canonical baseline precision must be 1.0 (100%)");
        assertEquals(1.0, canonical.getRecall(), 1e-6, "Canonical baseline recall must be 1.0 (100%)");
        assertEquals(11, canonical.getRemediationAttempted(), "Canonical baseline must attempt 11 remediations");
        assertEquals(11, canonical.getFullySuccessfulRemediations(), "Canonical baseline must achieve 11 full remediation successes");
        assertEquals(0, canonical.getNewCriticalFindings(), "Canonical baseline must introduce 0 critical regressions");
        assertEquals(0, canonical.getNewHighFindings(), "Canonical baseline must introduce 0 high regressions");
        assertEquals(0, canonical.getNewMediumFindings(), "Canonical baseline must introduce 0 medium regressions");
        assertEquals(0, canonical.getNewLowFindings(), "Canonical baseline must introduce 0 low regressions");

        // 2. Verify Adversarial Suite Counts
        assertEquals(50, adversarial.getTotalCases(), "Adversarial suite must contain exactly 50 cases");

        // 3. Verify Realistic Enterprise Suite Counts
        assertEquals(30, realistic.getTotalCases(), "Realistic enterprise suite must contain exactly 30 cases");
        assertEquals(17, realistic.getVulnerableCases(), "Realistic suite must contain exactly 17 vulnerable fixtures");
        assertEquals(13, realistic.getSafeCases(), "Realistic suite must contain exactly 13 safe fixtures");

        // 4. Verify Cross-File Suite Counts
        assertEquals(2, crossFile.getTotalCases(), "Cross-file suite must contain exactly 2 pilot cases");
        assertEquals(1, crossFile.getVulnerableCases(), "Cross-file suite must contain 1 vulnerable case");
        assertEquals(1, crossFile.getSafeCases(), "Cross-file suite must contain 1 safe case");
        assertEquals(1, crossFile.getTruePositives(), "Cross-file suite TP must be 1");
        assertEquals(0, crossFile.getFalsePositives(), "Cross-file suite FP must be 0");
        assertEquals(1, crossFile.getTrueNegatives(), "Cross-file suite TN must be 1");
        assertEquals(0, crossFile.getFalseNegatives(), "Cross-file suite FN must be 0");
        assertEquals(1.0, crossFile.getPrecision(), 1e-6, "Cross-file suite precision must be 1.0 (100%)");
        assertEquals(1.0, crossFile.getRecall(), 1e-6, "Cross-file suite recall must be 1.0 (100%)");
        assertEquals(1, crossFile.getRemediationAttempted(), "Cross-file suite must attempt 1 remediation");
        assertEquals(1, crossFile.getFullySuccessfulRemediations(), "Cross-file suite must achieve 1 full remediation success");
        assertEquals(0, crossFile.getNewCriticalFindings(), "Cross-file suite must introduce 0 critical regressions");
        assertEquals(0, crossFile.getNewHighFindings(), "Cross-file suite must introduce 0 high regressions");
        assertEquals(0, crossFile.getNewMediumFindings(), "Cross-file suite must introduce 0 medium regressions");
        assertEquals(0, crossFile.getNewLowFindings(), "Cross-file suite must introduce 0 low regressions");

        // 5. Verify Combined Suite Counts
        assertEquals(108, combined.getTotalCases(), "Combined suite must contain exactly 108 cases (26 + 50 + 30 + 2)");
        assertEquals(canonical.getVulnerableCases() + adversarial.getVulnerableCases() + realistic.getVulnerableCases() + crossFile.getVulnerableCases(), combined.getVulnerableCases());
        assertEquals(canonical.getSafeCases() + adversarial.getSafeCases() + realistic.getSafeCases() + crossFile.getSafeCases(), combined.getSafeCases());

        // 6. Export reports
        Path reportDir = Path.of("benchmark/reports");
        if (!Files.exists(reportDir)) {
            Files.createDirectories(reportDir);
        }
        Path jsonPath = reportDir.resolve("benchmark-report-v1.2.json");
        Path mdPath = reportDir.resolve("benchmark-report-v1.2.md");

        new JsonBenchmarkReporter().writeReport(report, jsonPath);
        new MarkdownBenchmarkReporter().writeReport(report, mdPath);

        assertTrue(Files.exists(jsonPath), "JSON benchmark report must be generated");
        assertTrue(Files.exists(mdPath), "Markdown benchmark report must be generated");

        // Print Scorecard to console
        System.out.println("===============================================================================");
        System.out.println("                 SENTINELPR v1.2 RELIABILITY BENCHMARK SCORECARD               ");
        System.out.println("===============================================================================");
        printSummarySection("CANONICAL BASELINE (26 CASES)", canonical);
        printSummarySection("ADVERSARIAL SUITE (50 CASES)", adversarial);
        printSummarySection("REALISTIC ENTERPRISE SUITE (30 CASES)", realistic);
        printSummarySection("TRUE CROSS-FILE PILOT SUITE (2 CASES)", crossFile);
        printSummarySection("COMBINED SUITE (108 CASES)", combined);
        System.out.println("===============================================================================");

        // Report any detection mismatches or remediation failures for visibility
        for (BenchmarkExecutionResult r : report.getCaseResults()) {
            if (!r.isDetectionSuccess()) {
                System.err.printf("[DETECTION MISMATCH] Suite=%s Case=%s (%s): %s%n",
                        r.getBenchmarkCase().getSuite(), r.getCaseId(), r.getRuleId(), r.getDetectionMismatch());
            }
            if (r.getRemediationResult() != null && !r.getRemediationResult().isOverallSuccess()) {
                System.err.printf("[REMEDIATION FAILED] Suite=%s Case=%s (%s) at stage %s: %s%n",
                        r.getBenchmarkCase().getSuite(), r.getCaseId(), r.getRuleId(),
                        r.getRemediationResult().getFailureStage(), r.getRemediationResult().getFailureReason());
            }
        }
    }

    private void printSummarySection(String title, BenchmarkSummary summary) {
        System.out.println("-------------------------------------------------------------------------------");
        System.out.println("  " + title);
        System.out.println("-------------------------------------------------------------------------------");
        System.out.printf("Total Cases: %d (Vulnerable: %d, Safe: %d)%n",
                summary.getTotalCases(), summary.getVulnerableCases(), summary.getSafeCases());
        System.out.printf("Detection Matrix: TP=%d, FP=%d, TN=%d, FN=%d%n",
                summary.getTruePositives(), summary.getFalsePositives(), summary.getTrueNegatives(), summary.getFalseNegatives());
        System.out.printf("Precision: %.2f%% | Recall: %.2f%% | F1-Score: %.2f%%%n",
                summary.getPrecision() * 100.0, summary.getRecall() * 100.0, summary.getF1Score() * 100.0);
        System.out.printf("False Positive Rate (FPR): %.2f%% | False Negative Rate (FNR): %.2f%%%n",
                summary.getFalsePositiveRate() * 100.0, summary.getFalseNegativeRate() * 100.0);
        System.out.printf("Remediations Attempted: %d | Patches Generated: %d%n",
                summary.getRemediationAttempted(), summary.getPatchesGenerated());
        System.out.printf("AST Valid: %d | Clean Applying: %d | Compilable: %d | Regression-Free: %d%n",
                summary.getAstValidPatches(), summary.getCleanApplyingPatches(),
                summary.getCompilablePatches(), summary.getRegressionFreePatches());
        System.out.printf("Full Remediation Success: %d / %d (%.2f%%)%n",
                summary.getFullySuccessfulRemediations(), summary.getRemediationAttempted(),
                summary.getRemediationSuccessRate() * 100.0);
        System.out.printf("Regressions Introduced: Critical=%d, High=%d, Medium=%d, Low=%d%n",
                summary.getNewCriticalFindings(), summary.getNewHighFindings(),
                summary.getNewMediumFindings(), summary.getNewLowFindings());
        System.out.printf("Performance: Total Time=%.2f ms | Throughput=%.2f cases/sec%n",
                summary.getTotalDurationMs(), summary.getThroughputCasesPerSec());
    }
}
