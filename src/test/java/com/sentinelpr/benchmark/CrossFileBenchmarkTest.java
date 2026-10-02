package com.sentinelpr.benchmark;

import com.sentinelpr.benchmark.engine.BenchmarkEngine;
import com.sentinelpr.benchmark.engine.InMemoryCompilationVerifier;
import com.sentinelpr.benchmark.model.BenchmarkCase;
import com.sentinelpr.benchmark.model.BenchmarkExecutionResult;
import com.sentinelpr.core.model.InspectedSource;
import com.sentinelpr.core.model.SecurityFinding;
import com.sentinelpr.core.model.SecurityRule;
import com.sentinelpr.core.service.CodeInspectionService;
import com.sentinelpr.core.service.RuleEvaluationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class CrossFileBenchmarkTest {

    private BenchmarkEngine benchmarkEngine;
    private CodeInspectionService inspectionService;
    private RuleEvaluationService evaluationService;
    private InMemoryCompilationVerifier compiler;

    @BeforeEach
    void setUp() {
        this.benchmarkEngine = new BenchmarkEngine();
        this.inspectionService = new CodeInspectionService();
        this.evaluationService = new RuleEvaluationService();
        this.compiler = new InMemoryCompilationVerifier();
    }

    @Test
    @DisplayName("Test A: XFILE-SEC005-V01 with full project context detects cross-file taint with multi-hop trace")
    void testVulnerableCrossFileWithFullContext() throws Exception {
        Path controllerPath = Path.of("benchmark/cases/cross_file/XFILE-SEC005-V01/OrderSearchController.java");
        Path servicePath = Path.of("benchmark/cases/cross_file/XFILE-SEC005-V01/OrderQueryService.java");
        Path repoPath = Path.of("benchmark/cases/cross_file/XFILE-SEC005-V01/OrderDynamicRepository.java");

        InspectedSource controllerSource = inspectionService.inspectFile(controllerPath);
        InspectedSource serviceSource = inspectionService.inspectFile(servicePath);
        InspectedSource repoSource = inspectionService.inspectFile(repoPath);

        List<InspectedSource> allSources = List.of(controllerSource, serviceSource, repoSource);

        List<SecurityFinding> findings = evaluationService.evaluate(controllerSource, allSources);

        assertFalse(findings.isEmpty(), "Cross-file taint flow must be detected from controller entry point");
        SecurityFinding finding = findings.stream()
                .filter(f -> f.getRule() == SecurityRule.SQL_INJECTION)
                .findFirst()
                .orElse(null);

        assertNotNull(finding, "Must detect SEC-005 SQL injection finding");
        assertEquals("OrderSearchController", finding.getClassName());
        assertEquals("searchOrders", finding.getMethodName());
        assertTrue(finding.getConfidence() >= 0.95, "Confidence should reflect verified multi-hop taint trace");
        assertTrue(finding.getCausalRationale().contains("OrderSearchController"), "Rationale must reference controller");
        assertTrue(finding.getCausalRationale().contains("OrderQueryService"), "Rationale must trace through service layer");
        assertTrue(finding.getCausalRationale().contains("OrderDynamicRepository"), "Rationale must reach repository sink");
    }

    @Test
    @DisplayName("Test B: XFILE-SEC005-V01 controller in isolation yields 0 findings (requires downstream context)")
    void testControllerInIsolationYieldsNoFindings() throws Exception {
        Path controllerPath = Path.of("benchmark/cases/cross_file/XFILE-SEC005-V01/OrderSearchController.java");
        InspectedSource controllerSource = inspectionService.inspectFile(controllerPath);

        // Controller alone has no local SQL sink and cannot resolve callee without context
        List<SecurityFinding> findings = evaluationService.evaluate(controllerSource, List.of(controllerSource));

        assertTrue(findings.isEmpty(), "Controller evaluated without service/repository context must yield 0 findings");
    }

    @Test
    @DisplayName("Test C: XFILE-SEC005-S01 with full context yields 0 findings (True Negative via allowlist mapping)")
    void testSafeCrossFileWithFullContextYieldsZeroFindings() throws Exception {
        Path controllerPath = Path.of("benchmark/cases/cross_file/XFILE-SEC005-S01/OrderSearchController.java");
        Path servicePath = Path.of("benchmark/cases/cross_file/XFILE-SEC005-S01/OrderQueryService.java");
        Path repoPath = Path.of("benchmark/cases/cross_file/XFILE-SEC005-S01/OrderDynamicRepository.java");

        InspectedSource controllerSource = inspectionService.inspectFile(controllerPath);
        InspectedSource serviceSource = inspectionService.inspectFile(servicePath);
        InspectedSource repoSource = inspectionService.inspectFile(repoPath);

        List<InspectedSource> allSources = List.of(controllerSource, serviceSource, repoSource);

        List<SecurityFinding> findings = evaluationService.evaluate(controllerSource, allSources);

        assertTrue(findings.isEmpty(), "Safe cross-file preset mapping must yield 0 findings (True Negative)");
    }

    @Test
    @DisplayName("Test D: In-memory compilation succeeds for both vulnerable and safe cross-file fixture suites")
    void testFixturesCompileInMemory() throws Exception {
        Path vController = Path.of("benchmark/cases/cross_file/XFILE-SEC005-V01/OrderSearchController.java");
        Path vService = Path.of("benchmark/cases/cross_file/XFILE-SEC005-V01/OrderQueryService.java");
        Path vRepo = Path.of("benchmark/cases/cross_file/XFILE-SEC005-V01/OrderDynamicRepository.java");

        InspectedSource isVc = inspectionService.inspectFile(vController);
        InspectedSource isVs = inspectionService.inspectFile(vService);
        InspectedSource isVr = inspectionService.inspectFile(vRepo);

        InMemoryCompilationVerifier.CompilationResult vComp = compiler.compileSources(
                List.of(isVc.getRawSource(), isVs.getRawSource(), isVr.getRawSource()));
        assertTrue(vComp.isSuccess(), "Vulnerable 3-tier fixtures must compile cleanly: " + String.join("; ", vComp.getDiagnostics()));

        Path sController = Path.of("benchmark/cases/cross_file/XFILE-SEC005-S01/OrderSearchController.java");
        Path sService = Path.of("benchmark/cases/cross_file/XFILE-SEC005-S01/OrderQueryService.java");
        Path sRepo = Path.of("benchmark/cases/cross_file/XFILE-SEC005-S01/OrderDynamicRepository.java");

        InspectedSource isSc = inspectionService.inspectFile(sController);
        InspectedSource isSs = inspectionService.inspectFile(sService);
        InspectedSource isSr = inspectionService.inspectFile(sRepo);

        InMemoryCompilationVerifier.CompilationResult sComp = compiler.compileSources(
                List.of(isSc.getRawSource(), isSs.getRawSource(), isSr.getRawSource()));
        assertTrue(sComp.isSuccess(), "Safe 3-tier fixtures must compile cleanly: " + String.join("; ", sComp.getDiagnostics()));
    }

    @Test
    @DisplayName("Test E: Full BenchmarkEngine execution of XFILE-SEC005-V01 achieves True Positive and 100% verified remediation")
    void testBenchmarkEngineExecutionVulnerable() throws Exception {
        List<BenchmarkCase> catalog = benchmarkEngine.loadCatalog(Path.of("benchmark/ground-truth/ground-truth-catalog.json"));
        BenchmarkCase vCase = catalog.stream()
                .filter(c -> "XFILE-SEC005-V01".equals(c.getCaseId()))
                .findFirst()
                .orElseThrow(() -> new AssertionError("XFILE-SEC005-V01 not found in catalog"));

        assertTrue(vCase.isCrossFile(), "Case must be identified as cross-file");
        assertEquals("CROSS_FILE", vCase.getSuite());

        BenchmarkExecutionResult res = benchmarkEngine.executeCase(vCase);

        assertTrue(res.isDetectionSuccess(), "Detection must succeed: " + res.getDetectionMismatch());
        assertEquals("TRUE_POSITIVE", res.getClassification());

        assertNotNull(res.getRemediationResult(), "Remediation result must not be null");
        assertTrue(res.getRemediationResult().isOverallSuccess(),
                "Remediation must succeed: " + res.getRemediationResult().getFailureReason());
        assertTrue(res.getRemediationResult().isPatchGenerated(), "Patch must be generated");
        assertTrue(res.getRemediationResult().isAstValid(), "Patched source AST must be valid");
        assertTrue(res.getRemediationResult().isAppliesCleanly(), "Patch must apply cleanly");
        assertTrue(res.getRemediationResult().isCompilesSuccessfully(), "Patched source must compile cleanly");
        assertTrue(res.getRemediationResult().isTargetFindingRemoved(), "Target SQL injection finding must be removed");
        assertTrue(res.getRemediationResult().isRegressionFree(), "Remediation must be regression-free");
        assertEquals(0, res.getRemediationResult().getNewCriticalFindings());
        assertEquals(0, res.getRemediationResult().getNewHighFindings());
        assertEquals(0, res.getRemediationResult().getNewMediumFindings());
        assertEquals(0, res.getRemediationResult().getNewLowFindings());
    }

    @Test
    @DisplayName("Test F: Full BenchmarkEngine execution of XFILE-SEC005-S01 achieves True Negative")
    void testBenchmarkEngineExecutionSafe() throws Exception {
        List<BenchmarkCase> catalog = benchmarkEngine.loadCatalog(Path.of("benchmark/ground-truth/ground-truth-catalog.json"));
        BenchmarkCase sCase = catalog.stream()
                .filter(c -> "XFILE-SEC005-S01".equals(c.getCaseId()))
                .findFirst()
                .orElseThrow(() -> new AssertionError("XFILE-SEC005-S01 not found in catalog"));

        assertTrue(sCase.isCrossFile(), "Case must be identified as cross-file");
        assertEquals("CROSS_FILE", sCase.getSuite());

        BenchmarkExecutionResult res = benchmarkEngine.executeCase(sCase);

        assertTrue(res.isDetectionSuccess(), "Detection must succeed: " + res.getDetectionMismatch());
        assertEquals("TRUE_NEGATIVE", res.getClassification());
        assertNull(res.getRemediationResult(), "No remediation expected on safe case");
    }
}
