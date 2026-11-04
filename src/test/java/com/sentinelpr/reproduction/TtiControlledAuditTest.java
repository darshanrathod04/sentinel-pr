package com.sentinelpr.reproduction;

import com.sentinelpr.cli.SentinelCliRunner;
import com.sentinelpr.core.model.ReviewReport;
import com.sentinelpr.core.model.SecurityFinding;
import com.sentinelpr.core.model.UnifiedDiffPatch;
import com.sentinelpr.core.remediation.PatchValidationStatus;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

/**
 * <b>TtiControlledAuditTest</b>
 *
 * <p>Phase 4B.2 Controlled Security Review of the internal TTI Repository:</p>
 * <ul>
 *   <li>Evaluates the full first-party codebase of {@code D:/TTI}.</li>
 *   <li>Verifies non-Java manual remediation enforcement (no synthetic patches for Python/TS).</li>
 *   <li>Extracts rule distribution, findings, and operational metrics without leaking external data.</li>
 * </ul>
 */
@DisplayName("Phase 4B.2: Controlled Security Review of TTI Repository")
public class TtiControlledAuditTest {

    @Test
    @DisplayName("Controlled Audit of TTI Repository using SentinelPR")
    void testControlledTtiAudit() {
        Path ttiPath = Path.of("D:/TTI");
        if (!Files.exists(ttiPath)) {
            System.out.println("[Notice] D:/TTI does not exist on this environment; skipping live audit.");
            return;
        }

        SentinelCliRunner runner = new SentinelCliRunner();
        ReviewReport report = runner.run(ttiPath);

        assertNotNull(report, "ReviewReport must not be null");
        System.out.println("=== TTI CONTROLLED AUDIT RESULTS ===");
        System.out.println("Status: " + report.getStatus());
        System.out.println("Files Scanned: " + report.getScannedFileCount());
        System.out.println("Vulnerabilities Detected: " + report.getVulnerabilityCount());

        List<SecurityFinding> findings = report.getFindings();
        Map<String, Long> findingsByRule = findings.stream()
                .collect(Collectors.groupingBy(f -> f.getRule().getRuleId(), Collectors.counting()));

        System.out.println("\nFindings by Rule:");
        findingsByRule.forEach((rule, count) -> System.out.println("  " + rule + ": " + count));

        // Invariant 1: All non-Java patches must be marked MANUAL_REMEDIATION_REQUIRED
        for (UnifiedDiffPatch patch : report.getPatches()) {
            assertEquals(UnifiedDiffPatch.Status.MANUAL_REMEDIATION_REQUIRED, patch.getStatus(),
                    "All non-Java findings in TTI must require manual remediation");
            assertEquals(PatchValidationStatus.MANUAL_REMEDIATION_REQUIRED, patch.getValidationStatus());
            assertFalse(patch.isVerified(), "Non-Java patches must not be claimed as verified");
            assertEquals("", patch.getUnifiedDiff(), "Non-Java patch must have empty unified diff");
        }

        // Invariant 2: Scanned count must reflect first-party code (> 100 files)
        assertTrue(report.getScannedFileCount() > 100,
                "Must scan all first-party Python, JS, and TS files in TTI");
    }
}
