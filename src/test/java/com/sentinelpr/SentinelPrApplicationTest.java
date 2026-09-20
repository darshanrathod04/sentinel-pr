package com.sentinelpr;

import com.sentinelpr.client.SentinelClient;
import com.sentinelpr.core.model.ReviewReport;
import com.sentinelpr.core.model.SecurityFinding;
import com.sentinelpr.core.model.SecurityRule;
import com.sentinelpr.core.model.UnifiedDiffPatch;
import com.sentinelpr.core.service.AutomatedPatchService;
import com.sentinelpr.core.service.CodeInspectionService;
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
 * <b>SentinelPrApplicationTest</b>
 *
 * <p>Integration and smoke tests for SentinelPR built on Shree AI OS.</p>
 */
class SentinelPrApplicationTest {

    private SentinelAuditOrchestrator orchestrator;
    private SentinelClient client;

    @BeforeEach
    void setUp() {
        // Bootstrap client singleton
        client = SentinelClient.bootstrap("local");
        orchestrator = new SentinelAuditOrchestrator(
                new CodeInspectionService(client),
                new RuleEvaluationService(client),
                new AutomatedPatchService(client),
                new ReviewSessionMemory(client)
        );
        orchestrator.getSessionMemory().clearCache();
    }

    @Test
    @DisplayName("SentinelPR detects intentional vulnerabilities, generates valid unified diff patches, and finishes SUCCESS")
    void testDetectVulnerabilitiesAndSynthesizePatches() throws IOException {
        Path fixturePath = Path.of("src/test/java/com/sentinelpr/fixture/VulnerableService.java");
        if (!Files.exists(fixturePath)) {
            // Check alternate path in case working dir varies
            Path alt = Path.of("apps/sentinel-pr/src/test/java/com/sentinelpr/fixture/VulnerableService.java");
            if (Files.exists(alt)) {
                fixturePath = alt;
            }
        }
        assertTrue(Files.exists(fixturePath), "VulnerableService fixture must exist at: " + fixturePath.toAbsolutePath());

        // 1. Execute Audit
        ReviewReport report = orchestrator.auditPath(fixturePath);

        // 2. Assert overall execution status
        assertNotNull(report, "ReviewReport must not be null");
        assertEquals("SUCCESS", report.getStatus(), "Execution must finish with status SUCCESS");
        assertEquals(1, report.getScannedFileCount(), "Must scan 1 source file");

        // 3. Assert detection of vulnerabilities
        List<SecurityFinding> findings = report.getFindings();
        assertNotNull(findings, "Findings list must not be null");
        assertTrue(findings.size() >= 2, "SentinelPR must detect at least 2 vulnerabilities, detected: " + findings.size());

        boolean detectedFailOpen = findings.stream()
                .anyMatch(f -> f.getRule() == SecurityRule.FAIL_OPEN_SECURITY);
        assertTrue(detectedFailOpen, "SentinelPR must detect the fail-open security catch block (SEC-001-FAIL-OPEN)");

        boolean detectedUnclosedStream = findings.stream()
                .anyMatch(f -> f.getRule() == SecurityRule.UNCLOSED_IO_STREAM);
        assertTrue(detectedUnclosedStream, "SentinelPR must detect the unclosed FileInputStream (SEC-002-UNCLOSED-STREAM)");

        boolean detectedVolatileCompound = findings.stream()
                .anyMatch(f -> f.getRule() == SecurityRule.VOLATILE_COMPOUND_OP);
        assertTrue(detectedVolatileCompound, "SentinelPR must detect the volatile compound mutation (SEC-003-VOLATILE-COMPOUND)");

        // 4. Assert non-empty, syntactically valid patches
        List<UnifiedDiffPatch> patches = report.getPatches();
        assertNotNull(patches, "Patches list must not be null");
        assertFalse(patches.isEmpty(), "SentinelPR must generate non-empty patches");

        for (UnifiedDiffPatch patch : patches) {
            assertNotNull(patch.getUnifiedDiff(), "Patch unified diff must not be null");
            assertFalse(patch.getUnifiedDiff().isBlank(), "Patch unified diff string must not be empty or blank");
            assertTrue(patch.getUnifiedDiff().contains("--- a/"), "Unified diff must contain standard header '--- a/'");
            assertTrue(patch.getUnifiedDiff().contains("+++ b/"), "Unified diff must contain standard header '+++ b/'");
            assertTrue(patch.getUnifiedDiff().contains("@@"), "Unified diff must contain hunk range '@@'");
            assertTrue(patch.isVerified(), "Synthesized patch must be syntactically verified (AST valid Java 21)");
            assertEquals(UnifiedDiffPatch.Status.SUCCESS, patch.getStatus(), "Patch application status must be SUCCESS");
        }

        // Print inspection report summary to console
        System.out.println("[TEST PASSED] SentinelPR Report Summary: " + report.getSummary());
        for (UnifiedDiffPatch p : patches) {
            System.out.println("[TEST PATCH GENERATED for " + p.getRuleId() + "]:\n" + p.getUnifiedDiff());
        }
    }

    @Test
    @DisplayName("ReviewSessionMemory avoids duplicate rule evaluation on unchanged files")
    void testSessionMemoryDeduplication() throws IOException {
        Path fixturePath = Path.of("src/test/java/com/sentinelpr/fixture/VulnerableService.java");
        if (!Files.exists(fixturePath)) {
            fixturePath = Path.of("apps/sentinel-pr/src/test/java/com/sentinelpr/fixture/VulnerableService.java");
        }

        // Run 1: Cold run
        ReviewReport report1 = orchestrator.auditPath(fixturePath);
        assertFalse(report1.isCachedAudit(), "First audit run must be cold (not cached)");

        // Run 2: Hot run on identical file
        ReviewReport report2 = orchestrator.auditPath(fixturePath);
        assertTrue(report2.isCachedAudit(), "Second audit run must hit session memory and avoid duplicate rule evaluations");
        assertEquals(report1.getVulnerabilityCount(), report2.getVulnerabilityCount());
    }

    @Test
    @DisplayName("SentinelClient exposes verified 10-SDK surface methods")
    void testClientSdkSurface() {
        assertNotNull(client.project(), "client.project() must be accessible");
        assertNotNull(client.reasoning(), "client.reasoning() must be accessible");
        assertNotNull(client.developer(), "client.developer() must be accessible");
        assertNotNull(client.memory(), "client.memory() must be accessible");
        assertNotNull(client.identity(), "client.identity() must be accessible");
        assertNotNull(client.knowledge(), "client.knowledge() must be accessible");
        assertNotNull(client.planning(), "client.planning() must be accessible");
        assertNotNull(client.execution(), "client.execution() must be accessible");
        assertNotNull(client.reflection(), "client.reflection() must be accessible");
        assertNotNull(client.settings(), "client.settings() must be accessible");
        assertNotNull(client.diagnostics(), "client.diagnostics() must be accessible");
        assertNotNull(client.events(), "client.events() must be accessible");
    }
}
