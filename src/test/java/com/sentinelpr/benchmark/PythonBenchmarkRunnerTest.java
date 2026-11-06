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
import java.util.*;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Phase 5.2: Hardened Python Security Benchmark Suite (50 Cases)")
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
    @DisplayName("Evaluate Hardened Python Benchmark Suite Ground Truth (25 Vuln, 25 Safe)")
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

        assertEquals(25, vulnFiles.size(), "Benchmark must contain exactly 25 vulnerable fixtures");
        assertEquals(25, safeFiles.size(), "Benchmark must contain exactly 25 safe control fixtures");

        int tp = 0;
        int fn = 0;
        int fp = 0;
        int tn = 0;
        int manualRemediationCount = 0;
        Map<String, Integer> perRuleTp = new TreeMap<>();

        System.out.println("===============================================================================");
        System.out.println("            SENTINELPR GOVERNED PYTHON SECURITY BENCHMARK SCORECARD            ");
        System.out.println("===============================================================================");

        // 1. Evaluate Vulnerable Cases (Expect Findings)
        System.out.printf("--- VULNERABLE FIXTURES (%d CASES) ---%n", vulnFiles.size());
        for (Path file : vulnFiles) {
            InspectedSource source = inspectionService.inspectFile(file);
            List<SecurityFinding> findings = evaluationService.evaluate(source);

            if (!findings.isEmpty()) {
                tp++;
                String ruleId = findings.get(0).getRule().getRuleId();
                perRuleTp.put(ruleId, perRuleTp.getOrDefault(ruleId, 0) + 1);
                System.out.println(" [PASS - TP] " + file.getFileName() + " -> " + findings.size() + " finding(s) [" + ruleId + "]");

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
        System.out.printf("%n--- SAFE CONTROL FIXTURES (%d CASES) ---%n", safeFiles.size());
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
        double f1 = (precision + recall) > 0 ? 2 * (precision * recall) / (precision + recall) : 0.0;

        System.out.println("===============================================================================");
        System.out.printf("Detection Matrix: TP=%d, FP=%d, TN=%d, FN=%d%n", tp, fp, tn, fn);
        System.out.printf("Precision: %.2f%% | Recall: %.2f%% | Specificity: %.2f%% | Accuracy: %.2f%%%n",
                precision, recall, specificity, accuracy);
        System.out.printf("F1-Score: %.2f%% | Manual Remediation Boundary: %d / %d (100.00%%)%n", f1, manualRemediationCount, tp);
        System.out.println("--- PER-RULE DETECTION BREAKDOWN ---");
        perRuleTp.forEach((rule, count) -> System.out.printf("  %-30s : %d detection(s)%n", rule, count));
        System.out.println("===============================================================================");

        // Enforce honest ground-truth benchmark metrics
        assertEquals(25, tp, "All 25 vulnerable fixtures detected in Phase 5.2 hardened baseline (TP=25)");
        assertEquals(0, fp, "Zero false alarms allowed on safe fixtures (FP=0)");
        assertEquals(25, tn, "All 25 safe fixtures must pass cleanly (TN=25)");
        assertEquals(0, fn, "Zero false negatives allowed in hardened baseline (FN=0)");
        assertEquals(100.0, precision, 0.001, "Precision must be 100.00%");
        assertEquals(100.0, recall, 0.001, "Recall must be 100.00%");
        assertEquals(100.0, specificity, 0.001, "Specificity must be 100.00%");
        assertEquals(100.0, f1, 0.01, "F1-Score must be 100.00%");
        assertEquals(25, manualRemediationCount, "100% of detected Python findings must enforce MANUAL_REMEDIATION_REQUIRED");
    }
}
