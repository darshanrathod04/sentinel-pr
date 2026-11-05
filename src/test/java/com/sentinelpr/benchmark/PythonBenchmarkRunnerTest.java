package com.sentinelpr.benchmark;

import com.sentinelpr.core.model.InspectedSource;
import com.sentinelpr.core.model.SecurityFinding;
import com.sentinelpr.core.model.UnifiedDiffPatch;
import com.sentinelpr.core.service.CodeInspectionService;
import com.sentinelpr.core.service.PatchComposer;
import com.sentinelpr.core.service.RuleEvaluationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Phase 5: Python Curated Security Benchmark Suite (20 Cases)")
public class PythonBenchmarkRunnerTest {

    private CodeInspectionService inspectionService;
    private RuleEvaluationService evaluationService;
    private PatchComposer patchComposer;

    private static final Path BENCHMARK_DIR = Path.of("benchmark/cases/python");

    @BeforeEach
    void setUp() {
        this.inspectionService = new CodeInspectionService();
        this.evaluationService = new RuleEvaluationService();
        this.patchComposer = new PatchComposer(com.sentinelpr.client.SentinelClient.getInstance());
    }

    @Test
    @DisplayName("Evaluate 20-Case Python Benchmark Suite Ground Truth (10 Vuln, 10 Safe)")
    void testPythonBenchmarkGroundTruth() throws IOException {
        Path vulnDir = BENCHMARK_DIR.resolve("vulnerable");
        Path safeDir = BENCHMARK_DIR.resolve("safe");

        assertTrue(Files.exists(vulnDir), "Vulnerable benchmark directory must exist");
        assertTrue(Files.exists(safeDir), "Safe benchmark directory must exist");

        List<Path> vulnFiles;
        try (Stream<Path> s = Files.list(vulnDir)) {
            vulnFiles = s.filter(p -> p.toString().endsWith(".py")).sorted().toList();
        }

        List<Path> safeFiles;
        try (Stream<Path> s = Files.list(safeDir)) {
            safeFiles = s.filter(p -> p.toString().endsWith(".py")).sorted().toList();
        }

        assertEquals(10, vulnFiles.size(), "Benchmark must contain exactly 10 vulnerable fixtures");
        assertEquals(10, safeFiles.size(), "Benchmark must contain exactly 10 safe control fixtures");

        int tp = 0;
        int fn = 0;
        int fp = 0;
        int tn = 0;
        int manualRemediationCount = 0;

        System.out.println("===============================================================================");
        System.out.println("                 SENTINELPR PYTHON SECURITY BENCHMARK SCORECARD               ");
        System.out.println("===============================================================================");

        // 1. Evaluate Vulnerable Cases (Expect Findings)
        System.out.println("--- VULNERABLE FIXTURES (10 CASES) ---");
        for (Path file : vulnFiles) {
            InspectedSource source = inspectionService.inspectFile(file);
            List<SecurityFinding> findings = evaluationService.evaluate(source);

            if (!findings.isEmpty()) {
                tp++;
                System.out.println(" [PASS - TP] " + file.getFileName() + " -> " + findings.size() + " finding(s) [" + findings.get(0).getRule().getRuleId() + "]");

                // Verify remediation boundary
                UnifiedDiffPatch patch = patchComposer.compose(source, findings);
                if (patch.getStatus() == UnifiedDiffPatch.Status.MANUAL_REMEDIATION_REQUIRED && patch.getUnifiedDiff().isEmpty()) {
                    manualRemediationCount++;
                }
            } else {
                fn++;
                System.err.println(" [FAIL - FN] " + file.getFileName() + " -> Expected finding but none detected!");
            }
        }

        // 2. Evaluate Safe Cases (Expect Zero Findings)
        System.out.println("\n--- SAFE CONTROL FIXTURES (10 CASES) ---");
        for (Path file : safeFiles) {
            InspectedSource source = inspectionService.inspectFile(file);
            List<SecurityFinding> findings = evaluationService.evaluate(source);

            if (findings.isEmpty()) {
                tn++;
                System.out.println(" [PASS - TN] " + file.getFileName() + " -> Clean (0 findings)");
            } else {
                fp++;
                System.err.println(" [FAIL - FP] " + file.getFileName() + " -> False positive detected: " + findings.get(0).getDescription());
            }
        }

        // Metrics calculation
        double precision = (tp + fp) > 0 ? (double) tp / (tp + fp) * 100.0 : 0.0;
        double recall = (tp + fn) > 0 ? (double) tp / (tp + fn) * 100.0 : 0.0;
        double specificity = (tn + fp) > 0 ? (double) tn / (tn + fp) * 100.0 : 0.0;
        double accuracy = (tp + tn + fp + fn) > 0 ? (double) (tp + tn) / (tp + tn + fp + fn) * 100.0 : 0.0;

        System.out.println("===============================================================================");
        System.out.printf("Detection Matrix: TP=%d, FP=%d, TN=%d, FN=%d%n", tp, fp, tn, fn);
        System.out.printf("Precision: %.2f%% | Recall: %.2f%% | Specificity: %.2f%% | Accuracy: %.2f%%%n",
                precision, recall, specificity, accuracy);
        System.out.printf("Manual Remediation Boundary Enforcement: %d / %d (100.00%%)%n", manualRemediationCount, tp);
        System.out.println("===============================================================================");

        // Enforce strict release gates
        assertEquals(10, tp, "All 10 vulnerable fixtures must be detected (TP=10)");
        assertEquals(0, fp, "Zero false alarms allowed on safe fixtures (FP=0)");
        assertEquals(10, tn, "All 10 safe fixtures must pass cleanly (TN=10)");
        assertEquals(0, fn, "Zero false negatives allowed (FN=0)");
        assertEquals(100.0, precision, 0.001, "Precision must be 100.00%");
        assertEquals(100.0, recall, 0.001, "Recall must be 100.00%");
        assertEquals(100.0, specificity, 0.001, "Specificity must be 100.00%");
        assertEquals(10, manualRemediationCount, "100% of Python findings must enforce MANUAL_REMEDIATION_REQUIRED");
    }
}
