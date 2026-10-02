package com.sentinelpr.benchmark;

import com.sentinelpr.benchmark.engine.RemediationBenchmarkEvaluator;
import com.sentinelpr.benchmark.model.RemediationEvaluationResult;
import com.sentinelpr.core.model.SecurityFinding;
import com.sentinelpr.core.model.SecurityRule;
import com.sentinelpr.core.model.Severity;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class RegressionMetricSemanticsTest {

    private SecurityFinding createFinding(String id, SecurityRule rule, Severity severity, int startLine, int endLine, String snippet) {
        return createFinding(id, rule, severity, "testMethod", startLine, endLine, snippet);
    }

    private SecurityFinding createFinding(String id, SecurityRule rule, Severity severity, String methodName, int startLine, int endLine, String snippet) {
        return new SecurityFinding(
                id,
                rule,
                severity,
                "TestClass.java",
                "TestClass",
                methodName,
                startLine,
                endLine,
                snippet,
                "Test finding: " + snippet,
                "Test rationale",
                "Test remediation",
                0.95
        );
    }

    @Test
    @DisplayName("Pre-existing findings persisting post-patch are NOT counted as regressions")
    void testPreExistingFindingsNotCountedAsRegressions() {
        SecurityFinding f1 = createFinding("F1", SecurityRule.SQL_INJECTION, Severity.CRITICAL, 10, 12, "select * from users");
        SecurityFinding f2 = createFinding("F2", SecurityRule.UNCLOSED_IO_STREAM, Severity.HIGH, 20, 22, "new FileInputStream()");

        List<SecurityFinding> pre = List.of(f1, f2);
        List<SecurityFinding> post = List.of(f2); // f1 removed, f2 persisted

        RemediationEvaluationResult result = new RemediationEvaluationResult();
        RemediationBenchmarkEvaluator.computeRegressions(pre, post, result);

        assertTrue(result.isRegressionFree(), "Persisting pre-existing finding should not be flagged as regression");
        assertEquals(0, result.getNewCriticalFindings());
        assertEquals(0, result.getNewHighFindings());
        assertEquals(0, result.getNewMediumFindings());
        assertEquals(0, result.getNewLowFindings());
        assertTrue(result.getNewRegressedFindingDetails().isEmpty());
    }

    @Test
    @DisplayName("New Critical finding triggers regression failure")
    void testNewCriticalRegressionDetected() {
        SecurityFinding pre = createFinding("PRE-1", SecurityRule.SQL_INJECTION, Severity.CRITICAL, 10, 12, "select * from users");
        SecurityFinding newCrit = createFinding("POST-1", SecurityRule.FAIL_OPEN_SECURITY, Severity.CRITICAL, 35, 38, "catch(Exception e) { return true; }");

        RemediationEvaluationResult result = new RemediationEvaluationResult();
        RemediationBenchmarkEvaluator.computeRegressions(List.of(pre), List.of(newCrit), result);

        assertFalse(result.isRegressionFree(), "New Critical finding must cause regressionFree == false");
        assertEquals(1, result.getNewCriticalFindings());
        assertEquals(0, result.getNewHighFindings());
        assertEquals(0, result.getNewMediumFindings());
        assertEquals(0, result.getNewLowFindings());
        assertEquals(1, result.getNewRegressedFindingDetails().size());
    }

    @Test
    @DisplayName("New High finding triggers regression failure")
    void testNewHighRegressionDetected() {
        SecurityFinding pre = createFinding("PRE-1", SecurityRule.SQL_INJECTION, Severity.CRITICAL, 10, 12, "select * from users");
        SecurityFinding newHigh = createFinding("POST-1", SecurityRule.UNCLOSED_IO_STREAM, Severity.HIGH, 25, 28, "new FileOutputStream(path)");

        RemediationEvaluationResult result = new RemediationEvaluationResult();
        RemediationBenchmarkEvaluator.computeRegressions(List.of(pre), List.of(newHigh), result);

        assertFalse(result.isRegressionFree(), "New High finding must cause regressionFree == false");
        assertEquals(0, result.getNewCriticalFindings());
        assertEquals(1, result.getNewHighFindings());
        assertEquals(0, result.getNewMediumFindings());
        assertEquals(0, result.getNewLowFindings());
    }

    @Test
    @DisplayName("New Medium finding triggers regression failure")
    void testNewMediumRegressionDetected() {
        SecurityFinding pre = createFinding("PRE-1", SecurityRule.SQL_INJECTION, Severity.CRITICAL, 10, 12, "select * from users");
        SecurityFinding newMed = createFinding("POST-1", SecurityRule.ARCH_NON_DETERMINISTIC_CALL, Severity.MEDIUM, 40, 42, "System.currentTimeMillis()");

        RemediationEvaluationResult result = new RemediationEvaluationResult();
        RemediationBenchmarkEvaluator.computeRegressions(List.of(pre), List.of(newMed), result);

        assertFalse(result.isRegressionFree(), "New Medium finding must cause regressionFree == false");
        assertEquals(0, result.getNewCriticalFindings());
        assertEquals(0, result.getNewHighFindings());
        assertEquals(1, result.getNewMediumFindings());
        assertEquals(0, result.getNewLowFindings());
    }

    @Test
    @DisplayName("New Low finding is reported separately and does NOT fail regressionFree")
    void testNewLowFindingDoesNotBreakRegressionFree() {
        SecurityFinding pre = createFinding("PRE-1", SecurityRule.SQL_INJECTION, Severity.CRITICAL, "queryDatabase", 10, 12, "select * from users");
        SecurityFinding newLow = createFinding("POST-1", SecurityRule.SQL_INJECTION, Severity.LOW, "auditLog", 50, 52, "logger.debug(query)");

        RemediationEvaluationResult result = new RemediationEvaluationResult();
        RemediationBenchmarkEvaluator.computeRegressions(List.of(pre), List.of(newLow), result);

        assertTrue(result.isRegressionFree(), "New Low finding must NOT break regressionFree (C/H/M only)");
        assertEquals(0, result.getNewCriticalFindings());
        assertEquals(0, result.getNewHighFindings());
        assertEquals(0, result.getNewMediumFindings());
        assertEquals(1, result.getNewLowFindings());
    }
}
