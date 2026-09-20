package com.sentinelpr;

import com.sentinelpr.client.SentinelClient;
import com.sentinelpr.core.analysis.DataflowTracker;
import com.sentinelpr.core.analysis.taint.TaintFlow;
import com.sentinelpr.core.model.InspectedSource;
import com.sentinelpr.core.model.ReviewReport;
import com.sentinelpr.core.model.SecurityFinding;
import com.sentinelpr.core.model.SecurityRule;
import com.sentinelpr.core.model.SuppressedFinding;
import com.sentinelpr.core.model.UnifiedDiffPatch;
import com.sentinelpr.core.service.AutomatedPatchService;
import com.sentinelpr.core.service.CodeInspectionService;
import com.sentinelpr.core.service.PatchComposer;
import com.sentinelpr.core.service.PatchVerifier;
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
 * <b>SentinelPrP0VerificationTest</b>
 *
 * <p>Integration test suite validating P0 enterprise capabilities:</p>
 * <ol>
 *   <li>Intra-procedural Taint & Dataflow Engine (DataflowTracker)</li>
 *   <li>False Positive Suppression Engine (SuppressionManager)</li>
 *   <li>Atomic Patch Composition (PatchComposer)</li>
 *   <li>Post-Patch Regression Verification (PatchVerifier)</li>
 * </ol>
 */
class SentinelPrP0VerificationTest {

    private SentinelClient client;
    private SentinelAuditOrchestrator orchestrator;
    private CodeInspectionService inspectionService;
    private DataflowTracker dataflowTracker;
    private Path fixturePath;

    @BeforeEach
    void setUp() {
        client = SentinelClient.bootstrap("local");
        inspectionService = new CodeInspectionService(client);
        dataflowTracker = new DataflowTracker();

        orchestrator = new SentinelAuditOrchestrator(
                inspectionService,
                new RuleEvaluationService(client),
                new AutomatedPatchService(client),
                new ReviewSessionMemory(client)
        );
        orchestrator.getSessionMemory().clearCache();

        fixturePath = Path.of("src/test/java/com/sentinelpr/fixture/TaintedVulnerableService.java");
        if (!Files.exists(fixturePath)) {
            fixturePath = Path.of("apps/sentinel-pr/src/test/java/com/sentinelpr/fixture/TaintedVulnerableService.java");
        }
        assertTrue(Files.exists(fixturePath), "Fixture must exist at: " + fixturePath.toAbsolutePath());
    }

    @Test
    @DisplayName("Requirement 1: DataflowTracker traces untrusted parameter to sensitive sink")
    void testTaintDataflowTracking() throws IOException {
        InspectedSource source = inspectionService.inspectFile(fixturePath);
        List<TaintFlow> flows = dataflowTracker.analyze(source);

        assertNotNull(flows, "Taint flows list must not be null");
        assertFalse(flows.isEmpty(), "DataflowTracker must detect at least one taint flow in fixture");

        // Assert un-sanitized flow from untrustedInput to Runtime.exec
        boolean foundUnsanitized = flows.stream().anyMatch(f ->
                "untrustedInput".equals(f.getSource().getName())
                        && f.getSink().getTargetMethod().contains("exec")
                        && !f.isSanitized()
                        && f.getTraceSteps().contains("preparedCommand")
        );
        assertTrue(foundUnsanitized, "Taint tracker must trace 'untrustedInput' -> 'preparedCommand' -> Runtime.exec without sanitization");

        // Assert sanitized flow exists where validateCommand guard was applied
        boolean foundSanitized = flows.stream().anyMatch(f ->
                "untrustedInput".equals(f.getSource().getName())
                        && f.getSink().getTargetMethod().contains("exec")
                        && f.isSanitized()
        );
        assertTrue(foundSanitized, "Taint tracker must detect sanitization guard on executeSanitizedCommand");

        System.out.println("[P0 TEST PASSED] DataflowTracker Flows Traced:");
        for (TaintFlow flow : flows) {
            System.out.println("  " + flow.formatTrace());
        }
    }

    @Test
    @DisplayName("Requirement 2: SuppressionManager catches @SuppressWarnings and inline comments, storing in suppressedFindings")
    void testFalsePositiveSuppression() throws IOException {
        ReviewReport report = orchestrator.auditPath(fixturePath);

        assertNotNull(report, "ReviewReport must not be null");
        assertEquals("SUCCESS", report.getStatus());

        List<SuppressedFinding> suppressed = report.getSuppressedFindings();
        assertNotNull(suppressed, "Suppressed findings list must not be null");
        assertTrue(suppressed.size() >= 2, "Must suppress at least 2 findings (annotation + inline comment), found: " + suppressed.size());

        // 1. Verify Annotation Suppression: @SuppressWarnings("sentinel:SEC-001")
        boolean annotationSuppressed = suppressed.stream().anyMatch(sf ->
                sf.getFinding().getRule() == SecurityRule.FAIL_OPEN_SECURITY
                        && "ANNOTATION".equals(sf.getSuppressionType())
                        && sf.getMatchedReason().contains("sentinel:SEC-001")
        );
        assertTrue(annotationSuppressed, "Must record suppressed finding for @SuppressWarnings(\"sentinel:SEC-001\")");

        // 2. Verify Inline Comment Suppression: // sentinel-ignore SEC-002
        boolean commentSuppressed = suppressed.stream().anyMatch(sf ->
                sf.getFinding().getRule() == SecurityRule.UNCLOSED_IO_STREAM
                        && "INLINE_COMMENT".equals(sf.getSuppressionType())
                        && sf.getMatchedReason().contains("sentinel-ignore SEC-002")
        );
        assertTrue(commentSuppressed, "Must record suppressed finding for '// sentinel-ignore SEC-002'");

        // 3. Verify that active findings contain only the UN-SUPPRESSED defects
        List<SecurityFinding> active = report.getFindings();
        boolean unsuppressedFailOpen = active.stream()
                .anyMatch(f -> f.getRule() == SecurityRule.FAIL_OPEN_SECURITY && "checkSuperAdmin".equals(f.getMethodName()));
        assertTrue(unsuppressedFailOpen, "Unsuppressed fail-open method checkSuperAdmin must remain in active findings");

        boolean unsuppressedStream = active.stream()
                .anyMatch(f -> f.getRule() == SecurityRule.UNCLOSED_IO_STREAM && "readTelemetryLog".equals(f.getMethodName()));
        assertTrue(unsuppressedStream, "Unsuppressed stream method readTelemetryLog must remain in active findings");

        System.out.println("[P0 TEST PASSED] Suppressed Findings Recorded in ReviewReport:");
        for (SuppressedFinding sf : suppressed) {
            System.out.printf("  [%s] %s -> Reason: %s%n",
                    sf.getSuppressionType(), sf.getFinding().getDescription(), sf.getMatchedReason());
        }
    }

    @Test
    @DisplayName("Requirements 3 & 4: PatchComposer produces ONE unified diff with all fixes, verified by PatchVerifier")
    void testAtomicPatchCompositionAndRegressionVerification() throws IOException {
        ReviewReport report = orchestrator.auditPath(fixturePath);

        List<UnifiedDiffPatch> patches = report.getPatches();
        assertNotNull(patches, "Patches list must not be null");
        assertEquals(1, patches.size(), "PatchComposer must produce exactly ONE composed unified diff for the multi-vulnerability file");

        UnifiedDiffPatch patch = patches.get(0);

        // Assert single unified diff characteristics
        assertNotNull(patch.getUnifiedDiff(), "Composed unified diff must not be null");
        assertFalse(patch.getUnifiedDiff().isBlank(), "Composed unified diff must not be blank");
        assertTrue(patch.getUnifiedDiff().contains("--- a/"), "Must contain diff header '--- a/'");
        assertTrue(patch.getUnifiedDiff().contains("+++ b/"), "Must contain diff header '+++ b/'");

        // Assert all fixes are composed into the single diff:
        // Fix 1: AtomicInteger import & mutation
        assertTrue(patch.getUnifiedDiff().contains("AtomicInteger"), "Composed diff must include AtomicInteger fix");
        assertTrue(patch.getUnifiedDiff().contains("incrementAndGet()"), "Composed diff must include incrementAndGet() fix");

        // Fix 2: try-with-resources conversion for unclosed stream
        assertTrue(patch.getUnifiedDiff().contains("try (FileInputStream fis = new FileInputStream(logFile))"),
                "Composed diff must include try-with-resources for readTelemetryLog");

        // Fix 3: fail-closed security fix
        assertTrue(patch.getUnifiedDiff().contains("return false; // SentinelPR: fail-closed security fix"),
                "Composed diff must include fail-closed security fix for checkSuperAdmin");

        // Fix 4: ProcessBuilder conversion for un-isolated subprocess
        assertTrue(patch.getUnifiedDiff().contains("new ProcessBuilder("),
                "Composed diff must include ProcessBuilder fix for executeUserCommand");

        // Assert Verification & Regression Flags
        assertTrue(patch.isVerified(), "Composed patch must be AST syntax verified: " + patch.getVerificationMessage());
        assertTrue(patch.isRegressionVerified(), "Composed patch must be marked regressionVerified: true. Details: " + patch.getVerificationMessage());
        assertEquals(UnifiedDiffPatch.Status.SUCCESS, patch.getStatus(), "Composed patch status must be SUCCESS");

        System.out.println("[P0 TEST PASSED] Composed Unified Diff Patch:");
        System.out.println(patch.getUnifiedDiff());
        System.out.println("Verification Message: " + patch.getVerificationMessage());
    }

    @Test
    @DisplayName("Requirement 2b: SuppressionManager suppresses findings via .sentinelignore repository file")
    void testSentinelIgnoreFileSuppression() throws IOException {
        Path tempIgnore = fixturePath.getParent().resolve(".sentinelignore");
        try {
            Files.writeString(tempIgnore, "# Temporary Sentinel Ignore\nSEC-004 Command execution accepted in fixture\n");

            // Reset session memory cache
            orchestrator.getSessionMemory().clearCache();

            ReviewReport report = orchestrator.auditPath(fixturePath);
            assertNotNull(report);

            boolean hasIgnoreFileSuppression = report.getSuppressedFindings().stream()
                    .anyMatch(sf -> sf.getFinding().getRule() == SecurityRule.UNISOLATED_SUBPROCESS
                            && "IGNORE_FILE".equals(sf.getSuppressionType()));
            assertTrue(hasIgnoreFileSuppression, "Must suppress SEC-004 via .sentinelignore file");

            System.out.println("[P0 TEST PASSED] .sentinelignore suppression confirmed.");

        } finally {
            Files.deleteIfExists(tempIgnore);
        }
    }
}
