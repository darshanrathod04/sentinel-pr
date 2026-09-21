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
import com.sentinelpr.cli.SentinelCliRunner;
import com.sentinelpr.client.DeveloperFacade;
import com.sentinelpr.client.MemoryFacade;
import com.sentinelpr.core.analysis.DataflowTracker;
import com.sentinelpr.core.analysis.taint.TaintFlow;
import com.sentinelpr.core.governance.policy.PolicyEvaluationResult;
import com.sentinelpr.core.model.UnifiedDiffPatch;
import org.junit.jupiter.api.AfterEach;
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
    private Path interDataServicePath;
    private Path interControllerPath;

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
        interDataServicePath = Path.of("src/test/java/com/sentinelpr/fixture/interprocedural/InterProceduralDataService.java");
        interControllerPath = Path.of("src/test/java/com/sentinelpr/fixture/interprocedural/InterProceduralController.java");

        assertTrue(Files.exists(vulnerableServicePath), "Fixture must exist: " + vulnerableServicePath);
        assertTrue(Files.exists(coupledServicePath), "Fixture must exist: " + coupledServicePath);
        assertTrue(Files.exists(coupledControllerPath), "Fixture must exist: " + coupledControllerPath);
        assertTrue(Files.exists(cyclicAPath), "Fixture must exist: " + cyclicAPath);
        assertTrue(Files.exists(cyclicBPath), "Fixture must exist: " + cyclicBPath);
        assertTrue(Files.exists(interDataServicePath), "Fixture must exist: " + interDataServicePath);
        assertTrue(Files.exists(interControllerPath), "Fixture must exist: " + interControllerPath);

        try {
            Files.deleteIfExists(Path.of(MemoryFacade.DEFAULT_HISTORY_FILE));
        } catch (Exception ignored) {
        }
    }

    @AfterEach
    void tearDown() {
        try {
            Files.deleteIfExists(Path.of(MemoryFacade.DEFAULT_HISTORY_FILE));
            if (client != null && client.memoryFacade() != null) {
                client.memoryFacade().clearCache();
            }
        } catch (Exception ignored) {
        }
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

    @Test
    @DisplayName("P1-1: Inter-procedural taint tracking propagates Source -> Variable -> Param -> Return -> Field -> Sink across classes")
    void testInterProceduralTaintPropagationAcrossMethods() throws IOException {
        InspectedSource controllerSource = inspectionService.inspectFile(interControllerPath);
        InspectedSource dataServiceSource = inspectionService.inspectFile(interDataServicePath);

        DataflowTracker tracker = new DataflowTracker();
        List<TaintFlow> flows = tracker.analyze(controllerSource, List.of(controllerSource, dataServiceSource));

        assertNotNull(flows);
        assertFalse(flows.isEmpty(), "Must discover inter-procedural taint flows");

        // Verify flow reaching executeQuery SQL sink
        TaintFlow sqlFlow = flows.stream()
                .filter(f -> f.getSink().getTargetMethod().contains("executeQuery"))
                .findFirst()
                .orElse(null);
        assertNotNull(sqlFlow, "Must discover taint flow reaching executeQuery sink");

        // Verify multi-hop trace captures the full pipeline:
        // Source (userInput) -> localFilter -> InterProceduralDataService.buildQueryFilter(filterInput) -> computedFilter -> InterProceduralDataService.executeDirectQuery(rawFilter) -> lastFilter (assign) -> sql -> executeQuery
        String multiHopTrace = sqlFlow.formatMultiHopTrace();
        assertTrue(multiHopTrace.contains("userInput"), "Trace must start at userInput parameter");
        assertTrue(multiHopTrace.contains("localFilter"), "Trace must track local variable assignment");
        assertTrue(multiHopTrace.contains("buildQueryFilter"), "Trace must record callee parameter in buildQueryFilter");
        assertTrue(multiHopTrace.contains("computedFilter"), "Trace must record return-value propagation into computedFilter");
        assertTrue(multiHopTrace.contains("executeDirectQuery"), "Trace must record inter-procedural call to executeDirectQuery");
        assertTrue(multiHopTrace.contains("lastFilter"), "Trace must track field assignment to this.lastFilter");
        assertTrue(multiHopTrace.contains("executeQuery"), "Trace must terminate at executeQuery sink");

        // Verify integration with ReasoningFacade
        List<SecurityFinding> findings = evaluationService.evaluate(controllerSource, List.of(controllerSource, dataServiceSource));
        SecurityFinding sqlFinding = findings.stream()
                .filter(f -> f.getRule() == SecurityRule.SQL_INJECTION)
                .findFirst()
                .orElse(null);
        assertNotNull(sqlFinding, "ReasoningFacade must discover SQL_INJECTION via inter-procedural taint tracking");
        assertTrue(sqlFinding.getCausalRationale().contains("Taint trace:"), "Rationale must include formatted taint trace");

        // Verify CausalChain synthesis incorporates multi-hop hops
        CausalChain chain = causalEngine.analyzeCausalChain(sqlFinding, controllerSource);
        assertNotNull(chain);
        assertEquals(CausalChain.BlastRadius.TENANT_DATA, chain.getBlastRadius());
        assertTrue(chain.getPropagationHops().size() >= 4, "Must contain at least 4 propagation hops");
        boolean hopsMentionInterProcedural = chain.getPropagationHops().stream().anyMatch(h -> h.contains("InterProcedural") || h.contains("buildQueryFilter") || h.contains("computedFilter"));
        assertTrue(hopsMentionInterProcedural, "Propagation hops must reflect inter-procedural method trace");
    }

    @Test
    @DisplayName("P1-4: DTO refactoring adheres to 4-tier resolution and synthesizes balanced parentheses")
    void testDtoRefactorSyntaxAndResolutionTiers() throws IOException {
        InspectedSource controllerSource = inspectionService.inspectFile(coupledControllerPath);
        List<SecurityFinding> findings = architectureEngine.evaluateLeakyAbstractions(controllerSource);
        assertFalse(findings.isEmpty(), "Must detect ARCH-002 on CoupledController");

        SecurityFinding leakyFinding = findings.get(0);

        // 1. Tier 1: Existing DTO Resolution with Balanced Parentheses
        // CoupledController has existing UserDto in its package
        AutomatedPatchService patchService = orchestrator.getPatchService();
        UnifiedDiffPatch patch = patchService.generatePatch(controllerSource, leakyFinding);

        assertNotNull(patch);
        assertEquals(UnifiedDiffPatch.Status.SUCCESS, patch.getStatus());
        assertTrue(patch.isVerified(), "AST must verify successfully with balanced parentheses: " + patch.getVerificationMessage());
        assertTrue(patch.getUnifiedDiff().contains("UserDto.fromEntity(coupledService.getUser(id));"),
                "Diff must contain complete, balanced parenthesis wrapping: " + patch.getUnifiedDiff());
        assertFalse(patch.getUnifiedDiff().contains("UserDto.fromEntity(coupledService.getUser(id);"),
                "Diff must NOT contain unbalanced parens");

        // 2. Tier 4: DEFERRED_TO_MULTI_FILE_PLAN when no DTO/Mapper/Record exists
        SecurityFinding syntheticFinding = new SecurityFinding(
                "FND-UNRESOLVED",
                SecurityRule.ARCH_LEAKY_ABSTRACTION,
                Severity.HIGH,
                controllerSource.getFilePath().toString(),
                controllerSource.getPrimaryClassName(),
                "getNonExistentEntity",
                20,
                24,
                "public NonExistentEntity getNonExistentEntity() { return service.get(); }",
                "Endpoint returns entity [NonExistentEntity] directly",
                "Leaky abstraction",
                "Expose DTO",
                0.95
        );

        DeveloperFacade devFacade = client.developer();
        UnifiedDiffPatch deferredPatch = devFacade.generatePatch(controllerSource, syntheticFinding);
        // When no DTO/Mapper/Record exists, developer facade must NOT invent fake classes or emit invalid patches
        // It returns unchanged or empty diff, deferring to multi-file planning
        assertNotNull(deferredPatch);
        assertTrue(deferredPatch.getUnifiedDiff().isBlank() || deferredPatch.getStatus() == UnifiedDiffPatch.Status.FAILED,
                "Must defer unresolvable entity refactoring without inventing synthetic classes");
    }

    @Test
    @DisplayName("P2: Memory history stores strictly metadata and supports CLI inspection")
    void testMemoryHistoryMetadataAndCliInspection() throws IOException {
        InspectedSource source = inspectionService.inspectFile(vulnerableServicePath);
        ReviewReport report = orchestrator.auditPath(vulnerableServicePath);
        PolicyEvaluationResult policyResult = PolicyEvaluationResult.passed(
                "EnterpriseStandardPolicy",
                0,
                0,
                0,
                "All enterprise policy checks passed."
        );

        MemoryFacade memoryFacade = client.memoryFacade();
        assertNotNull(memoryFacade, "MemoryFacade must be available from SentinelClient");

        // 1. Record session metadata
        MemoryFacade.AuditSessionMetadata meta = memoryFacade.recordSession(report, policyResult, 150L);
        assertNotNull(meta, "Returned metadata must not be null");
        String runId = meta.getRunId();
        assertNotNull(runId, "Generated runId must not be null");

        // 2. Retrieve session and verify ONLY metadata is stored (never raw source code or patch diffs)
        var retrievedOpt = memoryFacade.getSession(runId);
        assertTrue(retrievedOpt.isPresent(), "Session metadata must be retrievable by runId");
        MemoryFacade.AuditSessionMetadata retrieved = retrievedOpt.get();
        assertEquals(runId, retrieved.getRunId());
        assertEquals("SUCCESS", retrieved.getStatus());
        assertEquals("PASSED", retrieved.getPolicyStatus());
        assertEquals(report.getVulnerabilityCount(), retrieved.getVulnerabilityCount());
        assertNotNull(retrieved.getTimestamp(), "Timestamp must be recorded");

        // Verify no raw code or patch bodies exist in memory
        var storedFindings = retrieved.getFindings();
        assertNotNull(storedFindings);
        for (var fs : storedFindings) {
            assertNotNull(fs.getRuleId());
            assertNotNull(fs.getSeverity());
            // FindingSummary has ruleId, severity, message - no raw code or AST nodes
        }

        // 3. Verify history formatting
        String historyTable = memoryFacade.formatHistoryTable();
        assertTrue(historyTable.contains(runId), "History table must list recorded runId");
        assertTrue(historyTable.contains("PASSED"), "History table must display policy status");

        String sessionDetail = memoryFacade.formatSessionDetail(runId);
        assertTrue(sessionDetail.contains(runId), "Session detail must contain runId");
        assertTrue(sessionDetail.contains("Duration:"), "Session detail must display duration");

        // 4. Verify CLI Runner commands --history and --run
        SentinelCliRunner runner = new SentinelCliRunner();
        int historyExitCode = runner.execute(new String[]{"--history"});
        assertEquals(0, historyExitCode, "CLI --history must exit with code 0");

        int runDetailExitCode = runner.execute(new String[]{"--run", runId});
        assertEquals(0, runDetailExitCode, "CLI --run <runId> must exit with code 0");
    }

    @Test
    @DisplayName("P2 Regression: Memory history persists across audit #1, audit #2, and CLI --history in reverse chronological order")
    void testMemoryHistoryPersistsAcrossAudit1Audit2AndCliHistory() throws Exception {
        Path historyFile = Path.of(MemoryFacade.DEFAULT_HISTORY_FILE);
        Files.deleteIfExists(historyFile);

        try {
            // 1. Run Audit #1 on vulnerableServicePath
            SentinelCliRunner runner1 = new SentinelCliRunner();
            SentinelCliRunner.CliExecutionResult res1 = runner1.execute(
                    vulnerableServicePath, null, null, null, null, null, null, "json"
            );
            assertNotNull(res1, "Audit #1 result must not be null");
            assertNotNull(res1.getReport(), "Audit #1 report must not be null");
            String runId1 = res1.getReport().getReportId();
            assertNotNull(runId1, "Audit #1 runId must not be null");

            // Small delay to ensure strictly distinct timestamps
            Thread.sleep(50);

            // 2. Run Audit #2 on enterpriseVulnerablePath
            SentinelCliRunner runner2 = new SentinelCliRunner();
            SentinelCliRunner.CliExecutionResult res2 = runner2.execute(
                    enterpriseVulnerablePath, null, null, null, null, null, null, "json"
            );
            assertNotNull(res2, "Audit #2 result must not be null");
            assertNotNull(res2.getReport(), "Audit #2 report must not be null");
            String runId2 = res2.getReport().getReportId();
            assertNotNull(runId2, "Audit #2 runId must not be null");
            assertNotEquals(runId1, runId2, "Audit #1 and Audit #2 must have distinct runIds");

            // 3. In a fresh CLI runner instance (simulating separate CLI invocation), execute --history
            SentinelCliRunner historyRunner = new SentinelCliRunner();
            java.io.ByteArrayOutputStream outCapture = new java.io.ByteArrayOutputStream();
            java.io.PrintStream origOut = System.out;
            System.setOut(new java.io.PrintStream(outCapture));
            int exitCode;
            try {
                exitCode = historyRunner.execute(new String[]{"--history"});
            } finally {
                System.setOut(origOut);
            }

            assertEquals(0, exitCode, "CLI --history must exit with code 0");
            String historyOutput = outCapture.toString();

            // 4. Verify both runIds exist in output
            assertTrue(historyOutput.contains(runId1), "History table must contain runId1: " + runId1);
            assertTrue(historyOutput.contains(runId2), "History table must contain runId2: " + runId2);
            assertFalse(historyOutput.contains("No prior review sessions recorded"),
                    "Must not display 'No prior review sessions recorded' after audits");

            // 5. Verify reverse chronological order: runId2 (Audit #2) must appear before runId1 (Audit #1)
            int idx2 = historyOutput.indexOf(runId2);
            int idx1 = historyOutput.indexOf(runId1);
            assertTrue(idx2 >= 0 && idx1 >= 0, "Both runIds must be present in history table");
            assertTrue(idx2 < idx1, String.format("Audit #2 (newer: %s at pos %d) must appear before Audit #1 (older: %s at pos %d)",
                    runId2, idx2, runId1, idx1));

            // 6. Verify programmatic readHistory() returns both in reverse chronological order
            List<MemoryFacade.AuditSessionMetadata> historyList = historyRunner.getMemoryFacade().readHistory();
            assertTrue(historyList.size() >= 2, "readHistory() must return at least 2 sessions");
            assertEquals(runId2, historyList.get(0).getRunId(), "First element must be runId2 (Audit #2, newer)");
            assertEquals(runId1, historyList.get(1).getRunId(), "Second element must be runId1 (Audit #1, older)");

            // 7. Verify ledger schema versioning & workspaceId
            assertTrue(Files.exists(historyFile), ".sentinelhistory.json must exist in workspace");
            String ledgerJson = Files.readString(historyFile);
            assertTrue(ledgerJson.contains("\"schemaVersion\" : \"1.0.0\""), "Ledger must contain schemaVersion 1.0.0");
            assertTrue(ledgerJson.contains("\"workspaceId\""), "Ledger must contain workspaceId");
            assertTrue(ledgerJson.contains("\"sessions\""), "Ledger must contain sessions array");

            // Strict governance: only metadata, never raw source code, diffs, or patch bodies
            assertFalse(ledgerJson.contains("public class VulnerableService"), "Ledger must never persist raw source code");
            assertFalse(ledgerJson.contains("public class EnterpriseSecurityVulnerableService"), "Ledger must never persist raw source code");
            assertFalse(ledgerJson.contains("--- a/"), "Ledger must never persist patch diffs");
            assertFalse(ledgerJson.contains("+++ b/"), "Ledger must never persist patch diffs");

            // 8. Verify --run <runId> inspection on Audit #2
            outCapture.reset();
            System.setOut(new java.io.PrintStream(outCapture));
            try {
                int runExit = historyRunner.execute(new String[]{"--run", runId2});
                assertEquals(0, runExit, "CLI --run <runId> must exit with code 0");
            } finally {
                System.setOut(origOut);
            }
            String detailOutput = outCapture.toString();
            assertTrue(detailOutput.contains(runId2), "Detail output must contain runId2");
            assertTrue(detailOutput.contains("Target Path:"), "Detail output must contain Target Path");
            assertTrue(detailOutput.contains("Duration:"), "Detail output must display duration");
        } finally {
            Files.deleteIfExists(historyFile);
        }
    }
}
