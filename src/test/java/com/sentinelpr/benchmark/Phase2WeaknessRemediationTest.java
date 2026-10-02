package com.sentinelpr.benchmark;

import com.github.javaparser.JavaParser;
import com.sentinelpr.benchmark.engine.InMemoryCompilationVerifier;
import com.sentinelpr.core.analysis.FrameworkContextAnalyzer;
import com.sentinelpr.core.model.InspectedSource;
import com.sentinelpr.core.model.SecurityFinding;
import com.sentinelpr.core.model.SecurityRule;
import com.sentinelpr.core.remediation.PathTraversalRemediationStrategy;
import com.sentinelpr.core.remediation.RemediationContext;
import com.sentinelpr.core.remediation.RemediationResult;
import com.sentinelpr.core.remediation.SqlInjectionRemediationStrategy;
import com.sentinelpr.core.remediation.UnclosedStreamRemediationStrategy;
import com.sentinelpr.core.service.CodeInspectionService;
import com.sentinelpr.core.service.RuleEvaluationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * <b>Phase2WeaknessRemediationTest</b>
 *
 * <p>Regression tests for the 6 weaknesses discovered during Phase 2 benchmarking:</p>
 * <ol>
 *   <li>SEC-005 multiline SQL remediation failure (ADV-SEC005-V06)</li>
 *   <li>SEC-005 nested SQL expression remediation failure (ADV-SEC005-V08)</li>
 *   <li>SEC-006 String-vs-Path remediation compilation failure (ADV-SEC006-V04)</li>
 *   <li>SEC-002 nested unclosed stream remediation failure (ADV-SEC002-V02)</li>
 *   <li>SEC-002 false positive for traditional try/finally close() (ADV-SEC002-S01)</li>
 *   <li>SEC-009 false negative for standalone SecurityFilterChain configuration (ADV-SEC009-V01)</li>
 * </ol>
 */
public class Phase2WeaknessRemediationTest {

    private CodeInspectionService inspectionService;
    private RuleEvaluationService evaluationService;
    private InMemoryCompilationVerifier compiler;
    private JavaParser javaParser;

    @BeforeEach
    void setUp() {
        this.inspectionService = new CodeInspectionService();
        this.evaluationService = new RuleEvaluationService();
        this.compiler = new InMemoryCompilationVerifier();
        this.javaParser = new JavaParser();
    }

    @Test
    @DisplayName("Weakness 1: SEC-005 multiline SQL remediation generates valid, compilable patch (ADV-SEC005-V06)")
    void testSec005MultilineSqlRemediation() throws Exception {
        Path fixturePath = Path.of("benchmark/cases/SEC-005/ADV-SEC005-V06.java");
        InspectedSource source = inspectionService.inspectFile(fixturePath);
        List<SecurityFinding> findings = evaluationService.evaluateRule(source, SecurityRule.SQL_INJECTION);
        assertFalse(findings.isEmpty(), "Should detect SQL injection in multiline query");

        SecurityFinding finding = findings.get(0);
        SqlInjectionRemediationStrategy strategy = new SqlInjectionRemediationStrategy();
        RemediationResult result = strategy.remediate(source.getRawSource(), finding, source, new RemediationContext(fixturePath.toString(), findings));

        assertTrue(result.isApplied(), "Patch must be generated");
        assertTrue(javaParser.parse(result.getPatchedSource()).getResult().isPresent(), "Patch must be valid Java AST");
        assertTrue(result.getPatchedSource().contains("prepareStatement"), "Patch must use prepareStatement");
        assertTrue(result.getPatchedSource().contains("?"), "Patch must parameterize SQL query with ?");

        InMemoryCompilationVerifier.CompilationResult compResult = compiler.compileSingle(result.getPatchedSource());
        assertTrue(compResult.isSuccess(), "Patched multiline SQL source must compile without errors: " + compResult.getDiagnostics());
    }

    @Test
    @DisplayName("Weakness 2: SEC-005 nested ternary/parenthesized SQL remediation generates valid, compilable patch (ADV-SEC005-V08)")
    void testSec005NestedExpressionRemediation() throws Exception {
        Path fixturePath = Path.of("benchmark/cases/SEC-005/ADV-SEC005-V08.java");
        InspectedSource source = inspectionService.inspectFile(fixturePath);
        List<SecurityFinding> findings = evaluationService.evaluateRule(source, SecurityRule.SQL_INJECTION);
        assertFalse(findings.isEmpty(), "Should detect SQL injection in nested expression query");

        SecurityFinding finding = findings.get(0);
        SqlInjectionRemediationStrategy strategy = new SqlInjectionRemediationStrategy();
        RemediationResult result = strategy.remediate(source.getRawSource(), finding, source, new RemediationContext(fixturePath.toString(), findings));

        assertTrue(result.isApplied(), "Patch must be generated");
        assertTrue(javaParser.parse(result.getPatchedSource()).getResult().isPresent(), "Patch must be valid Java AST");
        assertTrue(result.getPatchedSource().contains("prepareStatement"), "Patch must use prepareStatement");
        assertTrue(result.getPatchedSource().contains("?"), "Patch must parameterize SQL query with ?");

        InMemoryCompilationVerifier.CompilationResult compResult = compiler.compileSingle(result.getPatchedSource());
        assertTrue(compResult.isSuccess(), "Patched nested SQL expression source must compile without errors: " + compResult.getDiagnostics());
    }

    @Test
    @DisplayName("Weakness 3: SEC-006 String baseDirectory remediation compiles cleanly with Path.of normalization (ADV-SEC006-V04)")
    void testSec006StringVsPathRemediation() throws Exception {
        Path fixturePath = Path.of("benchmark/cases/SEC-006/ADV-SEC006-V04.java");
        InspectedSource source = inspectionService.inspectFile(fixturePath);
        List<SecurityFinding> findings = evaluationService.evaluateRule(source, SecurityRule.PATH_TRAVERSAL);
        assertFalse(findings.isEmpty(), "Should detect path traversal in Path.of resolution");

        SecurityFinding finding = findings.get(0);
        PathTraversalRemediationStrategy strategy = new PathTraversalRemediationStrategy();
        RemediationResult result = strategy.remediate(source.getRawSource(), finding, source, new RemediationContext(fixturePath.toString(), findings));

        assertTrue(result.isApplied(), "Patch must be generated");
        assertTrue(javaParser.parse(result.getPatchedSource()).getResult().isPresent(), "Patch must be valid Java AST");
        assertTrue(result.getPatchedSource().contains("normalize"), "Patch must normalize path");
        assertTrue(result.getPatchedSource().contains("startsWith"), "Patch must check startsWith");

        InMemoryCompilationVerifier.CompilationResult compResult = compiler.compileSingle(result.getPatchedSource());
        assertTrue(compResult.isSuccess(), "Patched String-vs-Path source must compile without errors: " + compResult.getDiagnostics());
    }

    @Test
    @DisplayName("Weakness 4: SEC-002 nested stream remediation wraps only outermost decorator in try-with-resources (ADV-SEC002-V02)")
    void testSec002NestedStreamRemediation() throws Exception {
        Path fixturePath = Path.of("benchmark/cases/SEC-002/ADV-SEC002-V02.java");
        InspectedSource source = inspectionService.inspectFile(fixturePath);
        List<SecurityFinding> findings = evaluationService.evaluateRule(source, SecurityRule.UNCLOSED_IO_STREAM);

        // Exactly one finding on the outer stream decorator, avoiding duplicate nested try corruption
        assertEquals(1, findings.size(), "Should produce exactly 1 finding for outermost stream in nested decorator chain");

        SecurityFinding finding = findings.get(0);
        UnclosedStreamRemediationStrategy strategy = new UnclosedStreamRemediationStrategy();
        RemediationResult result = strategy.remediate(source.getRawSource(), finding, source, new RemediationContext(fixturePath.toString(), findings));

        assertTrue(result.isApplied(), "Patch must be generated");
        assertTrue(javaParser.parse(result.getPatchedSource()).getResult().isPresent(), "Patch must be valid Java AST");
        assertTrue(result.getPatchedSource().contains("try (BufferedReader"), "Patch must enclose in try (BufferedReader...)");

        InMemoryCompilationVerifier.CompilationResult compResult = compiler.compileSingle(result.getPatchedSource());
        assertTrue(compResult.isSuccess(), "Patched nested stream source must compile without errors: " + compResult.getDiagnostics());
    }

    @Test
    @DisplayName("Weakness 5: SEC-002 try/finally close() is recognized as safe and does not emit false positive (ADV-SEC002-S01)")
    void testSec002TryFinallySafeResourceDetection() throws Exception {
        Path fixturePath = Path.of("benchmark/cases/SEC-002/ADV-SEC002-S01.java");
        InspectedSource source = inspectionService.inspectFile(fixturePath);
        List<SecurityFinding> findings = evaluationService.evaluateRule(source, SecurityRule.UNCLOSED_IO_STREAM);

        assertTrue(findings.isEmpty(), "Stream closed deterministically in finally block must NOT trigger UNCLOSED_IO_STREAM finding");
    }

    @Test
    @DisplayName("Weakness 6: SEC-009 standalone SecurityFilterChain with STATELESS in comments is correctly flagged (ADV-SEC009-V01)")
    void testSec009CsrfDisabledWithCommentsNotStateless() throws Exception {
        Path fixturePath = Path.of("benchmark/cases/SEC-009/ADV-SEC009-V01.java");
        InspectedSource source = inspectionService.inspectFile(fixturePath);
        FrameworkContextAnalyzer analyzer = new FrameworkContextAnalyzer();
        List<SecurityFinding> findings = analyzer.evaluateCsrfDisabled(source);

        assertFalse(findings.isEmpty(), "CSRF explicitly disabled without AST-level stateless configuration must be flagged");
        assertEquals(SecurityRule.SPRING_SECURITY_CSRF_DISABLED, findings.get(0).getRule());
    }
}
