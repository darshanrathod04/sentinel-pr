package com.sentinelpr;

import com.sentinelpr.api.SentinelReviewController;
import com.sentinelpr.api.dto.PolicyEvaluateRequest;
import com.sentinelpr.cli.SentinelCliRunner;
import com.sentinelpr.client.SentinelClient;
import com.sentinelpr.core.governance.audit.AuditTrailEntry;
import com.sentinelpr.core.governance.audit.AuditTrailLogger;
import com.sentinelpr.core.governance.baseline.BaselineEntry;
import com.sentinelpr.core.governance.baseline.BaselineManager;
import com.sentinelpr.core.governance.baseline.BaselineSnapshot;
import com.sentinelpr.core.governance.policy.PolicyEngine;
import com.sentinelpr.core.governance.policy.PolicyEvaluationResult;
import com.sentinelpr.core.governance.policy.SentinelPolicy;
import com.sentinelpr.core.model.ReviewReport;
import com.sentinelpr.core.model.SecurityFinding;
import com.sentinelpr.core.model.SecurityRule;
import com.sentinelpr.core.model.SuppressedFinding;
import com.sentinelpr.core.model.UnifiedDiffPatch;
import com.sentinelpr.core.service.AutomatedPatchService;
import com.sentinelpr.core.service.CodeInspectionService;
import com.sentinelpr.core.service.ReviewSessionMemory;
import com.sentinelpr.core.service.RuleEvaluationService;
import com.sentinelpr.core.service.SentinelAuditOrchestrator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.http.ResponseEntity;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * <b>SentinelPrP3GovernanceVerificationTest</b>
 *
 * <p>Integration test suite validating P3 Enterprise Governance capabilities:</p>
 * <ol>
 *   <li>Baseline Snapshot Engine (BaselineManager, BaselineSnapshot, BaselineEntry)</li>
 *   <li>Enterprise Policy Enforcement Engine (PolicyEngine, SentinelPolicy, PolicyEvaluationResult)</li>
 *   <li>Cryptographic Audit Trail & Compliance Logging (AuditTrailLogger, AuditTrailEntry)</li>
 *   <li>CLI Runner Governance Flags & Exit Codes (0, 1, 2)</li>
 *   <li>REST API Governance Endpoints (/governance/status, /policy/evaluate)</li>
 * </ol>
 */
class SentinelPrP3GovernanceVerificationTest {

    private SentinelClient client;
    private SentinelAuditOrchestrator orchestrator;
    private BaselineManager baselineManager;
    private PolicyEngine policyEngine;
    private AuditTrailLogger auditTrailLogger;
    private SentinelReviewController reviewController;

    private Path fixtureFile;
    private Path samplePolicyFile;
    private Path sampleBaselineFile;

    @BeforeEach
    void setUp() {
        client = SentinelClient.bootstrap("local");
        CodeInspectionService inspectionService = new CodeInspectionService(client);
        RuleEvaluationService evaluationService = new RuleEvaluationService(client);
        AutomatedPatchService patchService = new AutomatedPatchService(client);
        ReviewSessionMemory sessionMemory = new ReviewSessionMemory(client);

        baselineManager = new BaselineManager();
        policyEngine = new PolicyEngine();
        auditTrailLogger = new AuditTrailLogger();

        orchestrator = new SentinelAuditOrchestrator(
                inspectionService,
                evaluationService,
                patchService,
                sessionMemory,
                new com.sentinelpr.core.analysis.SuppressionManager(),
                new com.sentinelpr.core.analysis.DataflowTracker(),
                new com.sentinelpr.core.analysis.diff.IncrementalDiffScanner(),
                baselineManager
        );
        orchestrator.getSessionMemory().clearCache();

        reviewController = new SentinelReviewController(
                orchestrator,
                new com.sentinelpr.core.export.sarif.SarifReportGenerator(),
                new com.sentinelpr.core.export.github.PrReviewCommentBuilder(),
                policyEngine
        );

        fixtureFile = Path.of("src/test/java/com/sentinelpr/fixture/VulnerableService.java");
        samplePolicyFile = Path.of("src/test/resources/SamplePolicy.json");
        sampleBaselineFile = Path.of("src/test/resources/SampleBaseline.json");

        assertTrue(Files.exists(fixtureFile), "Fixture file must exist: " + fixtureFile);
        assertTrue(Files.exists(samplePolicyFile), "SamplePolicy fixture must exist: " + samplePolicyFile);
        assertTrue(Files.exists(sampleBaselineFile), "SampleBaseline fixture must exist: " + sampleBaselineFile);
    }

    @Test
    @DisplayName("P3-1: BaselineManager captures snapshot, serializes/deserializes, and suppresses legacy defects")
    void testBaselineSnapshotCaptureAndSuppression(@TempDir Path tempDir) throws IOException {
        // Step 1: Execute audit to discover defects
        ReviewReport initialReport = orchestrator.auditPath(fixtureFile);
        assertFalse(initialReport.getFindings().isEmpty(), "Initial audit must find vulnerabilities");
        int originalFindingCount = initialReport.getFindings().size();

        // Step 2: Capture baseline snapshot
        BaselineSnapshot snapshot = baselineManager.captureBaseline(initialReport);
        assertNotNull(snapshot);
        assertEquals(originalFindingCount, snapshot.getTotalEntries());
        assertEquals("1.0", snapshot.getVersion());

        // Step 3: Export baseline to disk and load back
        Path baselinePath = tempDir.resolve(".sentinelbaseline.json");
        baselineManager.exportBaseline(snapshot, baselinePath);
        assertTrue(Files.exists(baselinePath));
        assertTrue(Files.size(baselinePath) > 0);

        BaselineSnapshot reloadedSnapshot = baselineManager.loadBaseline(baselinePath);
        assertEquals(snapshot.getTotalEntries(), reloadedSnapshot.getTotalEntries());

        // Step 4: Audit with baseline applied -> all known defects must be suppressed as BASELINE_ACCEPTED
        orchestrator.getSessionMemory().clearCache();
        ReviewReport baselineReport = orchestrator.auditPathWithBaseline(fixtureFile, baselinePath);

        assertNotNull(baselineReport);
        assertEquals(0, baselineReport.getVulnerabilityCount(),
                "All findings present in baseline must be filtered out of active vulnerabilities");
        assertTrue(baselineReport.getSuppressedCount() >= originalFindingCount,
                "Suppressed count must include all baseline-accepted findings");

        for (SuppressedFinding sf : baselineReport.getSuppressedFindings()) {
            assertEquals(BaselineManager.SUPPRESSION_TYPE, sf.getSuppressionType());
            assertTrue(sf.getMatchedReason().contains("Accepted technical debt present in baseline snapshot"));
        }

        // Step 5: Test partial baseline (only 1 rule in baseline)
        BaselineEntry failOpenEntry = BaselineEntry.fromFinding(initialReport.getFindings().stream()
                .filter(f -> f.getRule() == SecurityRule.FAIL_OPEN_SECURITY)
                .findFirst()
                .orElseThrow());
        BaselineSnapshot partialSnapshot = new BaselineSnapshot(fixtureFile.toString(), List.of(failOpenEntry));

        BaselineManager.BaselineFilterResult filterResult = baselineManager.filterWithBaseline(initialReport.getFindings(), partialSnapshot);
        assertEquals(1, filterResult.getSuppressedCount(), "Exactly 1 finding should match partial baseline");
        assertEquals(originalFindingCount - 1, filterResult.getActiveCount(), "Remaining findings must stay active");
    }

    @Test
    @DisplayName("P3-2: PolicyEngine detects breaches for thresholds and blocked security rules")
    void testPolicyEngineBreachDetection() throws IOException {
        SentinelPolicy strictPolicy = policyEngine.loadPolicy(samplePolicyFile);
        assertNotNull(strictPolicy);
        assertEquals("Enterprise-Strict-Security-Policy", strictPolicy.getPolicyName());
        assertEquals(0, strictPolicy.getMaxAllowedCritical());
        assertEquals(0, strictPolicy.getMaxAllowedHigh());
        assertTrue(strictPolicy.getBlockedRules().contains("SEC-001-FAIL-OPEN"));

        ReviewReport report = orchestrator.auditPath(fixtureFile);
        assertFalse(report.getFindings().isEmpty());

        PolicyEvaluationResult result = policyEngine.evaluate(report, strictPolicy);

        assertNotNull(result);
        assertTrue(result.isBreached(), "Evaluation must indicate policy BREACHED");
        assertEquals(PolicyEvaluationResult.Status.BREACHED, result.getStatus());
        assertEquals(1, result.getExitCode(), "Breached policy must map to exit code 1");
        assertFalse(result.getViolations().isEmpty(), "Violations list must not be empty");

        // Verify specific breach reasons
        boolean hasBlockedRuleBreach = result.getViolations().stream()
                .anyMatch(v -> v.contains("violates strictly blocked rule [SEC-001-FAIL-OPEN]"));
        boolean hasCriticalCountBreach = result.getViolations().stream()
                .anyMatch(v -> v.contains("CRITICAL finding(s), maximum allowed"));

        assertTrue(hasBlockedRuleBreach, "Must report blocked rule violation for SEC-001-FAIL-OPEN");
        assertTrue(hasCriticalCountBreach, "Must report critical threshold violation");
    }

    @Test
    @DisplayName("P3-3: PolicyEngine passes on clean audit or permissive thresholds")
    void testPolicyEnginePassingScenario() throws IOException {
        // Scenario A: Permissive policy with high allowances
        SentinelPolicy permissivePolicy = SentinelPolicy.createPermissivePolicy();
        ReviewReport reportWithFindings = orchestrator.auditPath(fixtureFile);

        PolicyEvaluationResult permissiveResult = policyEngine.evaluate(reportWithFindings, permissivePolicy);
        assertTrue(permissiveResult.isPassed(), "Permissive policy should pass");
        assertEquals(PolicyEvaluationResult.Status.PASSED, permissiveResult.getStatus());
        assertEquals(0, permissiveResult.getExitCode());
        assertTrue(permissiveResult.getViolations().isEmpty());

        // Scenario B: Strict policy against a clean report (0 defects)
        SentinelPolicy strictPolicy = SentinelPolicy.createDefaultStrictPolicy();
        ReviewReport cleanReport = new ReviewReport(
                "CLEAN-001",
                null,
                "src/main/java/CleanService.java",
                1,
                0,
                "SUCCESS",
                false,
                "No defects found",
                List.of(),
                List.of(),
                List.of()
        );

        PolicyEvaluationResult cleanResult = policyEngine.evaluate(cleanReport, strictPolicy);
        assertTrue(cleanResult.isPassed(), "Strict policy must pass on report with 0 findings");
        assertEquals(0, cleanResult.getExitCode());
        assertEquals(0, cleanResult.getCriticalCount());
        assertEquals(0, cleanResult.getHighCount());
    }

    @Test
    @DisplayName("P3-4: AuditTrailLogger produces signed cryptographic SOC2/ISO27001 entries and verifies integrity")
    void testAuditTrailCryptographicLoggingAndVerification(@TempDir Path tempDir) throws IOException {
        ReviewReport report = orchestrator.auditPath(fixtureFile);
        SentinelPolicy policy = policyEngine.loadPolicy(samplePolicyFile);
        PolicyEvaluationResult policyResult = policyEngine.evaluate(report, policy);

        // Step 1: Create signed audit trail entry
        AuditTrailEntry entry = auditTrailLogger.createAuditEntry(
                report,
                policyResult,
                "commit-sha-9876543210abcdef",
                "release/2026.1",
                "auditor-jane-doe"
        );

        assertNotNull(entry);
        assertEquals(report.getReportId(), entry.getRunId());
        assertEquals("auditor-jane-doe", entry.getOperator());
        assertEquals("commit-sha-9876543210abcdef", entry.getCommitId());
        assertEquals("release/2026.1", entry.getBranch());
        assertEquals("BREACHED", entry.getPolicyStatus());
        assertEquals(report.getVulnerabilityCount(), entry.getTotalFindings());

        // Step 2: Verify cryptographic hashes and signatures
        assertNotNull(entry.getInputFingerprint());
        assertEquals(64, entry.getInputFingerprint().length(), "SHA-256 fingerprint must be 64 hex characters");

        assertNotNull(entry.getReportSignature());
        assertEquals(64, entry.getReportSignature().length(), "SHA-256 report signature must be 64 hex characters");

        assertTrue(auditTrailLogger.verifyAuditSignature(entry),
                "Audit trail entry signature must be cryptographically valid");

        // Step 3: Append to NDJSON ledger file
        Path ledgerFile = tempDir.resolve("sentinel-audit.log");
        auditTrailLogger.appendAuditLog(entry, ledgerFile);
        assertTrue(Files.exists(ledgerFile));
        assertTrue(Files.size(ledgerFile) > 0);

        List<String> lines = Files.readAllLines(ledgerFile);
        assertEquals(1, lines.size(), "Ledger should have exactly 1 NDJSON line");

        AuditTrailEntry readBackEntry = auditTrailLogger.deserialize(lines.get(0));
        assertEquals(entry.getRunId(), readBackEntry.getRunId());
        assertEquals(entry.getReportSignature(), readBackEntry.getReportSignature());
        assertTrue(auditTrailLogger.verifyAuditSignature(readBackEntry),
                "Deserialized entry signature must verify successfully");

        // Step 4: Anti-tamper verification
        AuditTrailEntry tamperedEntry = new AuditTrailEntry(
                entry.getRunId(),
                entry.getTimestamp(),
                entry.getTargetPath(),
                entry.getCommitId(),
                entry.getBranch(),
                entry.getOperator(),
                entry.getInputFingerprint(),
                entry.getReportSignature(),
                entry.getMemoryKernelFingerprint(),
                entry.getRulesActive(),
                entry.getModelProvider(),
                entry.getPolicyStatus(),
                9999, // Tampered finding count
                entry.getTotalPatches()
        );
        assertFalse(auditTrailLogger.verifyAuditSignature(tamperedEntry),
                "Tampered entry must fail cryptographic verification");
    }

    @Test
    @DisplayName("P3-5: SentinelCliRunner executes governance flags and returns compliant exit codes (0, 1, 2)")
    void testCliRunnerGovernanceFlagsAndExitCodes(@TempDir Path tempDir) throws IOException {
        SentinelCliRunner runner = new SentinelCliRunner(
                orchestrator,
                new com.sentinelpr.core.export.sarif.SarifReportGenerator(),
                new com.sentinelpr.core.export.github.PrReviewCommentBuilder(),
                baselineManager,
                policyEngine,
                auditTrailLogger
        );

        Path baselineOutput = tempDir.resolve(".sentinelbaseline.json");
        Path auditLogOutput = tempDir.resolve("audit-ledger.log");

        // Case 1: Capture baseline via CLI -> exit code 0
        orchestrator.getSessionMemory().clearCache();
        int baselineExitCode = runner.execute(new String[]{
                fixtureFile.toString(),
                "--create-baseline", baselineOutput.toString(),
                "--audit-log", auditLogOutput.toString()
        });
        assertEquals(0, baselineExitCode, "Creating baseline without strict policy should return 0");
        assertTrue(Files.exists(baselineOutput), "Baseline file must be generated");
        assertTrue(Files.exists(auditLogOutput), "Audit log must be created");

        // Case 2: Policy breach -> exit code 1
        orchestrator.getSessionMemory().clearCache();
        int breachExitCode = runner.execute(new String[]{
                fixtureFile.toString(),
                "--policy", samplePolicyFile.toString()
        });
        assertEquals(1, breachExitCode, "Vulnerable code against strict policy must exit with code 1");

        // Case 3: Applying baseline suppresses defects -> policy passes with exit code 0 (when no blocked rules)
        Path permissivePolicyFile = tempDir.resolve("permissive-threshold-policy.json");
        Files.writeString(permissivePolicyFile, """
            {
              "policyName": "Threshold-Only-Policy",
              "version": "1.0",
              "maxAllowedCritical": 0,
              "maxAllowedHigh": 0,
              "maxAllowedMedium": 0,
              "failOnUnverifiedPatch": false,
              "blockedRules": []
            }
            """);

        orchestrator.getSessionMemory().clearCache();
        int baselineSuppressedExitCode = runner.execute(new String[]{
                fixtureFile.toString(),
                "--baseline", baselineOutput.toString(),
                "--policy", permissivePolicyFile.toString()
        });
        assertEquals(0, baselineSuppressedExitCode,
                "When all vulnerabilities are baseline-accepted and no blocked rules match, policy evaluation should PASS with exit code 0");

        // Case 3b: Policy Supremacy via CLI: Even with baseline, blocked rules must trigger exit code 1
        orchestrator.getSessionMemory().clearCache();
        int blockedBaselineExitCode = runner.execute(new String[]{
                fixtureFile.toString(),
                "--baseline", baselineOutput.toString(),
                "--policy", samplePolicyFile.toString()
        });
        assertEquals(1, blockedBaselineExitCode,
                "Policy supremacy: blocked rule cannot be suppressed by baseline, so exit code must be 1");

        // Case 4: Target not found or invalid args -> exit code 3
        int missingFileExitCode = runner.execute(new String[]{
                "nonexistent/path/Vulnerable.java"
        });
        assertEquals(3, missingFileExitCode, "Nonexistent target file must return exit code 3");

        int emptyArgsExitCode = runner.execute(new String[]{});
        assertEquals(3, emptyArgsExitCode, "Empty arguments must return exit code 3");
    }

    @Test
    @DisplayName("P3-6: SentinelReviewController handles /governance/status and /policy/evaluate")
    void testRestControllerGovernanceEndpoints() {
        // 1. GET /governance/status
        ResponseEntity<Map<String, Object>> statusResp = reviewController.governanceStatus();
        assertEquals(200, statusResp.getStatusCode().value());
        assertNotNull(statusResp.getBody());

        Map<String, Object> body = statusResp.getBody();
        assertEquals("ACTIVE", body.get("status"));
        assertEquals(10, body.get("rulesCatalog"));
        assertEquals(SentinelPolicy.DEFAULT_POLICY_NAME, body.get("defaultPolicy"));
        assertTrue(body.get("baselineEngine").toString().contains("SentinelBaselineSnapshot"));
        assertNotNull(body.get("complianceStandards"));

        // 2. POST /policy/evaluate with valid target path
        orchestrator.getSessionMemory().clearCache();
        PolicyEvaluateRequest evalRequest = new PolicyEvaluateRequest();
        evalRequest.setTargetPath(fixtureFile.toString());
        evalRequest.setPolicy(SentinelPolicy.createDefaultStrictPolicy());

        ResponseEntity<?> evalResp = reviewController.evaluatePolicy(evalRequest);
        assertEquals(200, evalResp.getStatusCode().value());
        assertTrue(evalResp.getBody() instanceof PolicyEvaluationResult);

        PolicyEvaluationResult result = (PolicyEvaluationResult) evalResp.getBody();
        assertTrue(result.isBreached(), "Strict policy should be breached by VulnerableService");
        assertTrue(result.getCriticalCount() > 0);

        // 3. POST /policy/evaluate with invalid request (empty body)
        PolicyEvaluateRequest invalidRequest = new PolicyEvaluateRequest();
        ResponseEntity<?> badResp = reviewController.evaluatePolicy(invalidRequest);
        assertEquals(400, badResp.getStatusCode().value());
    }

    @Test
    @DisplayName("P3-7: Blocked rule cannot be suppressed by baseline debt (Policy Supremacy)")
    void testBlockedRuleCannotBeSuppressedByBaseline(@TempDir Path tempDir) throws IOException {
        // Step 1: Capture baseline containing SEC-001-FAIL-OPEN
        orchestrator.getSessionMemory().clearCache();
        ReviewReport initialReport = orchestrator.auditPath(fixtureFile);
        Path baselinePath = tempDir.resolve("baseline.json");
        baselineManager.exportBaseline(initialReport, baselinePath);

        // Step 2: Create a policy strictly blocking SEC-001-FAIL-OPEN
        SentinelPolicy blockedPolicy = new SentinelPolicy(
                "Blocked-Rule-Policy",
                "1.0",
                10,
                10,
                10,
                -1,
                false,
                List.of("SEC-001-FAIL-OPEN"),
                List.of()
        );

        // Step 3: Run baseline audit with policy supremacy enabled
        orchestrator.getSessionMemory().clearCache();
        ReviewReport report = orchestrator.auditPathWithBaseline(fixtureFile, baselinePath, blockedPolicy);

        // SEC-001 finding must remain active and NOT be suppressed by baseline
        boolean sec001Active = report.getFindings().stream()
                .anyMatch(f -> "SEC-001-FAIL-OPEN".equals(f.getRule().getRuleId()));
        assertTrue(sec001Active, "SEC-001-FAIL-OPEN must not be suppressed by baseline because it is blocked by policy");

        // Step 4: Evaluate with PolicyEngine
        PolicyEvaluationResult result = policyEngine.evaluate(report, blockedPolicy);
        assertTrue(result.isBreached(), "Policy must be BREACHED");
        assertEquals(PolicyEvaluationResult.Status.BREACHED, result.getStatus());
        assertEquals(1, result.getExitCode());
        assertTrue(result.getBlockedCount() > 0, "Blocked count must be > 0");
        assertTrue(result.getViolations().stream().anyMatch(v -> v.contains("BLOCKED_BY_POLICY")),
                "Violation must contain BLOCKED_BY_POLICY marker");
    }

    @Test
    @DisplayName("P3-8: UnifiedDiffPatch enforces strict verification state machine invariants")
    void testPatchStatusConsistency() {
        // Invariant: status != SUCCESS implies verified = false
        UnifiedDiffPatch failedPatch = new UnifiedDiffPatch(
                "f1", "SEC-001", "Service.java", "diff", "patched source",
                UnifiedDiffPatch.Status.FAILED, true, true, "failed message"
        );
        assertFalse(failedPatch.isVerified(), "FAILED patch must never report verified = true");
        assertFalse(failedPatch.isRegressionVerified(), "FAILED patch must never report regressionVerified = true");
        assertFalse(failedPatch.isAstValid(), "FAILED patch must never report astValid = true");

        // Invariant: DEFERRED_TO_MULTI_FILE_PLAN implies verified = false
        UnifiedDiffPatch deferredPatch = new UnifiedDiffPatch(
                "f2", "ARCH-002", "Controller.java", "", "source",
                UnifiedDiffPatch.Status.DEFERRED_TO_MULTI_FILE_PLAN, true, true, "deferred message"
        );
        assertFalse(deferredPatch.isVerified(), "DEFERRED patch must never report verified = true");
        assertFalse(deferredPatch.isRegressionVerified(), "DEFERRED patch must never report regressionVerified = true");
        assertFalse(deferredPatch.isAstValid(), "DEFERRED patch must never report astValid = true");

        // Invariant: Blank diff implies verified = false
        UnifiedDiffPatch emptyDiffPatch = new UnifiedDiffPatch(
                "f3", "SEC-002", "Service.java", "   ", "source",
                UnifiedDiffPatch.Status.SUCCESS, true, true, "empty diff"
        );
        assertFalse(emptyDiffPatch.isVerified(), "Blank diff patch must never report verified = true");

        // Valid verified patch
        UnifiedDiffPatch validPatch = new UnifiedDiffPatch(
                "f4", "SEC-003", "Service.java", "@@ -1 +1 @@", "patched source",
                UnifiedDiffPatch.Status.SUCCESS, true, true, "success message"
        );
        assertTrue(validPatch.isVerified(), "Valid successful patch should report verified = true");
        assertTrue(validPatch.isRegressionVerified());
        assertTrue(validPatch.isAstValid());
    }

    @Test
    @DisplayName("P3-9: AuditTrailLogger produces transparent counts and execution timings schema")
    void testAuditTrailTransparentCounts() throws IOException {
        ReviewReport report = orchestrator.auditPath(fixtureFile);
        SentinelPolicy policy = SentinelPolicy.createDefaultStrictPolicy();
        PolicyEvaluationResult policyResult = policyEngine.evaluate(report, policy);

        AuditTrailEntry entry = auditTrailLogger.createAuditEntry(
                report, policyResult, "commit-12345", "main", "security-auditor"
        );

        assertNotNull(entry);
        assertEquals(report.getVulnerabilityCount(), entry.getActiveFindings());
        assertEquals(report.getSuppressedCount(), entry.getSuppressedFindings());
        assertEquals(policyResult.getBlockedCount(), entry.getBlockedFindings());
        assertEquals("v1.0.0", entry.getRuleSetVersion());
        assertEquals("v1.0", entry.getPolicyVersion());

        assertNotNull(entry.getExecutionTimings());
        assertTrue(entry.getExecutionTimings().getTotalMs() >= 0);
        assertTrue(auditTrailLogger.verifyAuditSignature(entry), "Cryptographic signature must match transparent payload");
    }

    @Test
    @DisplayName("P3-10: Enterprise governance states and stable exit codes (0, 1, 2, 4)")
    void testGovernanceStatesAndExitCodes() {
        // 1. PASSED -> Exit code 0
        PolicyEvaluationResult passed = PolicyEvaluationResult.passed("P1", 0, 0, 0, "Passed");
        assertEquals(PolicyEvaluationResult.Status.PASSED, passed.getStatus());
        assertTrue(passed.isPassed());
        assertEquals(0, passed.getExitCode());

        // 2. PASSED_WITH_BASELINE -> Exit code 0
        PolicyEvaluationResult passedWithBase = PolicyEvaluationResult.passedWithBaseline("P2", 0, 0, 0, 5, "Passed with baseline");
        assertEquals(PolicyEvaluationResult.Status.PASSED_WITH_BASELINE, passedWithBase.getStatus());
        assertTrue(passedWithBase.isPassed());
        assertTrue(passedWithBase.isPassedWithBaseline());
        assertEquals(0, passedWithBase.getExitCode());

        // 3. BREACHED (defect thresholds) -> Exit code 1
        PolicyEvaluationResult breached = PolicyEvaluationResult.breached("P3", List.of("violation"), 1, 0, 0, 0, 0, "Breached");
        assertEquals(PolicyEvaluationResult.Status.BREACHED, breached.getStatus());
        assertTrue(breached.isBreached());
        assertEquals(1, breached.getExitCode());

        // 4. BREACHED (unverified patch failure) -> Exit code 4
        PolicyEvaluationResult patchBreached = PolicyEvaluationResult.breached("P4", List.of("patch failure"), 0, 0, 0, 1, 0, "Unverified patch");
        assertEquals(PolicyEvaluationResult.Status.BREACHED, patchBreached.getStatus());
        assertTrue(patchBreached.isBreached());
        assertEquals(4, patchBreached.getExitCode());

        // 5. FAILED (internal engine error) -> Exit code 2
        PolicyEvaluationResult failed = PolicyEvaluationResult.failed("P5", "Engine failure");
        assertEquals(PolicyEvaluationResult.Status.FAILED, failed.getStatus());
        assertTrue(failed.isFailed());
        assertEquals(2, failed.getExitCode());
    }
}
