package com.sentinelpr;

import com.sentinelpr.client.SentinelClient;
import com.sentinelpr.core.analysis.architecture.ArchitectureReviewEngine;
import com.sentinelpr.core.analysis.calibration.ConfidenceCalibrator;
import com.sentinelpr.core.analysis.calibration.ConfidenceCalibrator.CalibrationResult;
import com.sentinelpr.core.analysis.causal.CausalAnalysisEngine;
import com.sentinelpr.core.analysis.causal.CausalChain;
import com.sentinelpr.core.model.CoordinatedPatchPlan;
import com.sentinelpr.core.model.ExploitabilityIndex;
import com.sentinelpr.core.model.InspectedSource;
import com.sentinelpr.core.model.ReviewReport;
import com.sentinelpr.core.model.SecurityFinding;
import com.sentinelpr.core.model.SecurityRule;
import com.sentinelpr.core.model.Severity;
import com.sentinelpr.core.model.SuppressedFinding;
import com.sentinelpr.core.service.AutomatedPatchService;
import com.sentinelpr.core.service.CodeInspectionService;
import com.sentinelpr.core.service.MultiFileFixPlanner;
import com.sentinelpr.core.service.ReviewSessionMemory;
import com.sentinelpr.core.service.RuleEvaluationService;
import com.sentinelpr.core.service.SentinelAuditOrchestrator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * <b>SentinelPrP4IntelligenceVerificationTest</b>
 *
 * <p>Integration test suite validating P4 AI Intelligence & Deep Cognitive Reasoning capabilities:</p>
 * <ol>
 *   <li>Deep Root-Cause Causal Reasoning (CausalAnalysisEngine & CausalChain)</li>
 *   <li>Calibrated Confidence & Exploitability Scoring (ConfidenceCalibrator & ExploitabilityIndex)</li>
 *   <li>Multi-File Coordinated Fix Planner (MultiFileFixPlanner & CoordinatedPatchPlan)</li>
 *   <li>Architectural Hygiene & Anti-Pattern Review (ArchitectureReviewEngine: ARCH-001, ARCH-002, ARCH-003)</li>
 * </ol>
 */
class SentinelPrP4IntelligenceVerificationTest {

    private SentinelClient client;
    private CodeInspectionService inspectionService;
    private RuleEvaluationService evaluationService;
    private SentinelAuditOrchestrator orchestrator;
    private CausalAnalysisEngine causalEngine;
    private ConfidenceCalibrator calibrator;
    private ArchitectureReviewEngine architectureEngine;
    private MultiFileFixPlanner fixPlanner;

    private Path vulnerableServicePath;
    private Path enterpriseVulnerablePath;
    private Path coupledRepoPath;
    private Path coupledServicePath;
    private Path coupledControllerPath;
    private Path cyclicAPath;
    private Path cyclicBPath;

    @BeforeEach
    void setUp() {
        client = SentinelClient.bootstrap("local");
        inspectionService = new CodeInspectionService(client);
        evaluationService = new RuleEvaluationService(client);
        AutomatedPatchService patchService = new AutomatedPatchService(client);
        ReviewSessionMemory sessionMemory = new ReviewSessionMemory(client);

        orchestrator = new SentinelAuditOrchestrator(
                inspectionService,
                evaluationService,
                patchService,
                sessionMemory
        );
        orchestrator.getSessionMemory().clearCache();

        causalEngine = orchestrator.getCausalAnalysisEngine();
        calibrator = orchestrator.getConfidenceCalibrator();
        architectureEngine = evaluationService.getArchitectureEngine();
        fixPlanner = orchestrator.getMultiFileFixPlanner();

        vulnerableServicePath = Path.of("src/test/java/com/sentinelpr/fixture/VulnerableService.java");
        enterpriseVulnerablePath = Path.of("src/test/java/com/sentinelpr/fixture/EnterpriseSecurityVulnerableService.java");
        coupledRepoPath = Path.of("src/test/java/com/sentinelpr/fixture/coupled/CoupledRepository.java");
        coupledServicePath = Path.of("src/test/java/com/sentinelpr/fixture/coupled/CoupledService.java");
        coupledControllerPath = Path.of("src/test/java/com/sentinelpr/fixture/coupled/CoupledController.java");
        cyclicAPath = Path.of("src/test/java/com/sentinelpr/fixture/coupled/cyclic/CyclicComponentA.java");
        cyclicBPath = Path.of("src/test/java/com/sentinelpr/fixture/coupled/cyclic/CyclicComponentB.java");

        assertTrue(Files.exists(vulnerableServicePath), "Fixture must exist: " + vulnerableServicePath);
        assertTrue(Files.exists(coupledServicePath), "Fixture must exist: " + coupledServicePath);
        assertTrue(Files.exists(coupledControllerPath), "Fixture must exist: " + coupledControllerPath);
        assertTrue(Files.exists(cyclicAPath), "Fixture must exist: " + cyclicAPath);
        assertTrue(Files.exists(cyclicBPath), "Fixture must exist: " + cyclicBPath);
    }

    @Test
    @DisplayName("P4-1: CausalAnalysisEngine builds multi-hop causal chains with blast radius and exploit vectors")
    void testCausalChainSynthesisAndBlastRadius() throws IOException {
        InspectedSource source = inspectionService.inspectFile(vulnerableServicePath);
        List<SecurityFinding> findings = evaluationService.evaluate(source);

        assertFalse(findings.isEmpty(), "Must discover vulnerabilities in VulnerableService");

        // 1. Validate Fail-Open Causal Chain
        SecurityFinding failOpenFinding = findings.stream()
                .filter(f -> f.getRule() == SecurityRule.FAIL_OPEN_SECURITY)
                .findFirst()
                .orElseThrow();

        CausalChain failOpenChain = causalEngine.analyzeCausalChain(failOpenFinding, source);
        assertNotNull(failOpenChain);
        assertNotNull(failOpenChain.getTrigger());
        assertTrue(failOpenChain.getTrigger().contains("authorization"));
        assertTrue(failOpenChain.getRootCauseElement().contains("CatchClause"));
        assertTrue(failOpenChain.getPropagationHops().size() >= 4, "Must contain at least 4 propagation hops");
        assertFalse(failOpenChain.getExploitVector().isBlank());
        assertFalse(failOpenChain.getBusinessImpact().isBlank());
        assertEquals(CausalChain.BlastRadius.TENANT_DATA, failOpenChain.getBlastRadius());
        assertTrue(failOpenChain.isActivelyReachable(), "Public checkUserAuthorization should be reachable");

        // 2. Validate Unclosed Stream Causal Chain
        SecurityFinding streamFinding = findings.stream()
                .filter(f -> f.getRule() == SecurityRule.UNCLOSED_IO_STREAM)
                .findFirst()
                .orElseThrow();

        CausalChain streamChain = causalEngine.analyzeCausalChain(streamFinding, source);
        assertNotNull(streamChain);
        assertEquals(CausalChain.BlastRadius.SERVICE_COMPONENT, streamChain.getBlastRadius());
        assertTrue(streamChain.getBusinessImpact().contains("Denial of Service") || streamChain.getBusinessImpact().contains("file descriptor"));

        // 3. Validate SQL Injection Causal Chain from Enterprise fixture
        if (Files.exists(enterpriseVulnerablePath)) {
            InspectedSource entSource = inspectionService.inspectFile(enterpriseVulnerablePath);
            List<SecurityFinding> entFindings = evaluationService.evaluate(entSource);
            SecurityFinding sqlFinding = entFindings.stream()
                    .filter(f -> f.getRule() == SecurityRule.SQL_INJECTION)
                    .findFirst()
                    .orElse(null);

            if (sqlFinding != null) {
                CausalChain sqlChain = causalEngine.analyzeCausalChain(sqlFinding, entSource);
                assertEquals(CausalChain.BlastRadius.TENANT_DATA, sqlChain.getBlastRadius());
                assertTrue(sqlChain.getExploitVector().contains("SQL"));
            }
        }
    }

    @Test
    @DisplayName("P4-2: ConfidenceCalibrator computes 4-factor score, assigns ExploitabilityIndex, and suppresses low-confidence heuristics")
    void testConfidenceCalibrationAndHeuristicSuppression() throws IOException {
        InspectedSource source = inspectionService.inspectFile(vulnerableServicePath);
        List<SecurityFinding> findings = evaluationService.evaluate(source);

        // Verify factor weights sum to 1.00
        double totalWeights = ConfidenceCalibrator.WEIGHT_TAINT_PATH
                + ConfidenceCalibrator.WEIGHT_AST_PRECISION
                + ConfidenceCalibrator.WEIGHT_ABSENCE_OF_SANITIZERS
                + ConfidenceCalibrator.WEIGHT_PUBLIC_REACHABILITY;
        assertEquals(1.00, totalWeights, 0.001, "Confidence calibrator weights must sum to exactly 1.00");

        // Case 1: High-fidelity finding (Fail-Open on public method without sanitizers)
        SecurityFinding failOpen = findings.stream()
                .filter(f -> f.getRule() == SecurityRule.FAIL_OPEN_SECURITY)
                .findFirst()
                .orElseThrow();

        CalibrationResult highResult = calibrator.calibrate(failOpen, source);
        assertNotNull(highResult);
        assertTrue(highResult.getScore() >= 0.85, "High-fidelity finding score should be >= 0.85");
        assertTrue(highResult.isMeetsThreshold(), "Score >= 0.70 must meet threshold");
        assertEquals(ExploitabilityIndex.CRITICAL, highResult.getExploitabilityIndex());
        assertEquals(4, highResult.getFactorScores().size());

        // Case 2: Low-confidence heuristic simulation (private method with partial sanitizers)
        SecurityFinding weakFinding = new SecurityFinding(
                "FND-WEAK",
                SecurityRule.SQL_INJECTION,
                Severity.LOW,
                source.getFilePath().toString(),
                source.getPrimaryClassName(),
                "privateHelperMethod",
                10,
                12,
                "query = query.replace(\"'\", \"\");",
                "Weak heuristic potential SQL query construction",
                "Theoretical concern",
                "Review parameter",
                0.50
        );

        CalibrationResult lowResult = calibrator.calibrate(weakFinding, source);
        assertNotNull(lowResult);
        assertTrue(lowResult.isLowConfidence(), "Weak heuristic finding must be below threshold 0.70");
        assertTrue(lowResult.getScore() < calibrator.getMinConfidenceThreshold());

        // Case 3: Verify automatic suppression in audit pipeline
        ReviewReport report = orchestrator.auditPath(vulnerableServicePath);
        assertNotNull(report);
        // All active findings in report must have calibrated confidence >= 0.70
        for (SecurityFinding f : report.getFindings()) {
            assertTrue(f.getConfidence() >= 0.70, "Active findings must meet confidence threshold");
            assertNotNull(f.getExploitabilityIndex(), "Active finding must have ExploitabilityIndex");
            assertNotNull(f.getCausalChain(), "Active finding must have CausalChain attached");
        }
    }

    @Test
    @DisplayName("P4-3: MultiFileFixPlanner synthesizes coordinated multi-file PatchPlan across CoupledService and CoupledController")
    void testMultiFileCoordinatedFixPlanner() throws IOException {
        InspectedSource serviceSource = inspectionService.inspectFile(coupledServicePath);
        InspectedSource controllerSource = inspectionService.inspectFile(coupledControllerPath);

        // Plan coordinated change: changing getUser in CoupledService to UserDto and updating CoupledController
        String provTarget = "public UserEntity getUser(String id) {\n        return repository.findById(id).orElse(null);\n    }";
        String provReplacement = "public UserDto getUser(String id) {\n        return repository.findById(id).map(UserDto::fromEntity).orElse(null);\n    }";

        String consTarget = "public UserEntity getUser(@PathVariable(\"id\") String id) {\n        return coupledService.getUser(id);\n    }";
        String consReplacement = "public UserDto getUser(@PathVariable(\"id\") String id) {\n        return coupledService.getUser(id);\n    }";

        CoordinatedPatchPlan plan = fixPlanner.planCoordinatedRefactoring(
                serviceSource,
                controllerSource,
                "getUser",
                provTarget,
                provReplacement,
                consTarget,
                consReplacement,
                "Decouple database entity UserEntity to UserDto across Service and Controller"
        );

        assertNotNull(plan);
        assertTrue(plan.isVerified(), "Multi-file refactoring must pass AST verification on both files simultaneously");
        assertEquals(2, plan.getTotalTouchedFiles(), "Plan must touch exactly 2 files");
        assertTrue(plan.getImpactedFiles().contains(coupledServicePath.toString()));
        assertTrue(plan.getImpactedFiles().contains(coupledControllerPath.toString()));

        assertEquals(2, plan.getFilePatches().size(), "Plan must produce 2 UnifiedDiffPatches");

        // Verify provider patch
        var provPatch = plan.getFilePatches().get(0);
        assertTrue(provPatch.getUnifiedDiff().contains("--- a/"));
        assertTrue(provPatch.getUnifiedDiff().contains("+++ b/"));
        assertTrue(provPatch.getUnifiedDiff().contains("UserDto"));
        assertTrue(provPatch.isVerified());

        // Verify consumer patch
        var consPatch = plan.getFilePatches().get(1);
        assertTrue(consPatch.getUnifiedDiff().contains("UserDto"));
        assertTrue(consPatch.isVerified());

        // Verify underlying Shree AI OS PatchPlan
        assertNotNull(plan.getShreePatchPlan());
        assertEquals(2, plan.getShreePatchPlan().patches().size());
        assertEquals(com.shreeai.os.platform.kernels.developer.codegen.model.PatchPlan.Status.READY,
                plan.getShreePatchPlan().status());
    }

    @Test
    @DisplayName("P4-4: ArchitectureReviewEngine detects ARCH-001 (cyclic), ARCH-002 (leaky entity), and ARCH-003 (non-deterministic calls)")
    void testArchitectureReviewEngineHygiene() throws IOException {
        // 1. Test ARCH-002: Leaky Entity Abstraction in CoupledController
        InspectedSource controllerSource = inspectionService.inspectFile(coupledControllerPath);
        List<SecurityFinding> controllerFindings = architectureEngine.evaluateLeakyAbstractions(controllerSource);

        assertFalse(controllerFindings.isEmpty(), "Must detect ARCH-002 on CoupledController");
        SecurityFinding leakyFinding = controllerFindings.get(0);
        assertEquals(SecurityRule.ARCH_LEAKY_ABSTRACTION, leakyFinding.getRule());
        assertEquals(Severity.HIGH, leakyFinding.getSeverity());
        assertTrue(leakyFinding.getDescription().contains("UserEntity"));
        assertTrue(leakyFinding.getRemediation().contains("DTO"));

        // 2. Test ARCH-003: Non-deterministic System.currentTimeMillis() and Random in CoupledService
        InspectedSource serviceSource = inspectionService.inspectFile(coupledServicePath);
        List<SecurityFinding> serviceFindings = architectureEngine.evaluateNonDeterministicCalls(serviceSource);

        assertFalse(serviceFindings.isEmpty(), "Must detect ARCH-003 on CoupledService");
        boolean hasClockFinding = serviceFindings.stream()
                .anyMatch(f -> f.getVulnerableSnippet().contains("System.currentTimeMillis()"));
        boolean hasRandomFinding = serviceFindings.stream()
                .anyMatch(f -> f.getVulnerableSnippet().contains("Random"));

        assertTrue(hasClockFinding, "Must detect System.currentTimeMillis() call");
        assertTrue(hasRandomFinding, "Must detect Random instantiation");

        for (SecurityFinding f : serviceFindings) {
            assertEquals(SecurityRule.ARCH_NON_DETERMINISTIC_CALL, f.getRule());
            assertTrue(f.getRemediation().contains("Clock") || f.getRemediation().contains("SecureRandom"));
        }

        // 3. Test ARCH-001: Cyclic Dependency between CyclicComponentA and CyclicComponentB
        InspectedSource sourceA = inspectionService.inspectFile(cyclicAPath);
        InspectedSource sourceB = inspectionService.inspectFile(cyclicBPath);

        List<SecurityFinding> cyclicFindings = architectureEngine.evaluateCyclicDependencies(sourceA, List.of(sourceA, sourceB));
        assertFalse(cyclicFindings.isEmpty(), "Must detect ARCH-001 cyclic dependency");
        SecurityFinding cyclicFinding = cyclicFindings.get(0);
        assertEquals(SecurityRule.ARCH_CYCLIC_DEPENDENCY, cyclicFinding.getRule());
        assertTrue(cyclicFinding.getDescription().contains("CyclicComponentA"));
        assertTrue(cyclicFinding.getDescription().contains("CyclicComponentB"));
        assertTrue(cyclicFinding.getRemediation().contains("Dependency Inversion") || cyclicFinding.getRemediation().contains("interface"));
    }

    @Test
    @DisplayName("P4-5: Multi-source audit integrates architectural rules, causal chains, and calibrated confidence")
    void testMultiSourceAuditIntegration() throws IOException {
        InspectedSource controllerSource = inspectionService.inspectFile(coupledControllerPath);
        InspectedSource serviceSource = inspectionService.inspectFile(coupledServicePath);
        InspectedSource repoSource = inspectionService.inspectFile(coupledRepoPath);

        ReviewReport report = orchestrator.auditSources(List.of(controllerSource, serviceSource, repoSource));

        assertNotNull(report);
        assertEquals(3, report.getScannedFileCount());
        assertTrue(report.getVulnerabilityCount() > 0, "Audit must discover vulnerabilities across coupled files");

        // Verify architectural findings are captured in report
        boolean hasLeakyAbstraction = report.getFindings().stream()
                .anyMatch(f -> f.getRule() == SecurityRule.ARCH_LEAKY_ABSTRACTION);
        boolean hasNonDeterministic = report.getFindings().stream()
                .anyMatch(f -> f.getRule() == SecurityRule.ARCH_NON_DETERMINISTIC_CALL);
        boolean hasFailOpen = report.getFindings().stream()
                .anyMatch(f -> f.getRule() == SecurityRule.FAIL_OPEN_SECURITY);

        assertTrue(hasLeakyAbstraction, "Report must capture ARCH-002 Leaky Abstraction");
        assertTrue(hasNonDeterministic, "Report must capture ARCH-003 Non-Deterministic Call");
        assertTrue(hasFailOpen, "Report must capture SEC-001 Fail-Open Security");

        // Verify every active finding has causal chain and calibrated confidence
        for (SecurityFinding f : report.getFindings()) {
            assertNotNull(f.getCausalChain(), "Finding must have CausalChain attached");
            assertNotNull(f.getExploitabilityIndex(), "Finding must have ExploitabilityIndex");
            assertTrue(f.getConfidence() >= 0.70, "Active finding must meet confidence threshold");
        }
    }
}
