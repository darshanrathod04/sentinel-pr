package com.sentinelpr.benchmark;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sentinelpr.benchmark.model.BenchmarkCase;
import com.sentinelpr.core.model.SecurityRule;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

public class AdversarialSuiteIntegrityTest {

    private static final Path CATALOG_PATH = Path.of("benchmark/ground-truth/ground-truth-catalog.json");
    private static List<BenchmarkCase> allCases;

    @BeforeAll
    static void loadCatalog() throws Exception {
        assertTrue(Files.exists(CATALOG_PATH), "Ground truth catalog must exist at " + CATALOG_PATH);
        ObjectMapper mapper = new ObjectMapper();
        allCases = mapper.readValue(CATALOG_PATH.toFile(), new TypeReference<List<BenchmarkCase>>() {});
        assertNotNull(allCases, "Catalog cases must not be null");
    }

    @Test
    @DisplayName("Catalog contains exactly 108 total cases: 26 canonical, 50 adversarial, 30 realistic, and 2 cross-file")
    void testCatalogSuiteCounts() {
        assertEquals(108, allCases.size(), "Combined catalog must contain exactly 108 cases");

        long canonicalCount = allCases.stream().filter(BenchmarkCase::isCanonical).count();
        long adversarialCount = allCases.stream().filter(BenchmarkCase::isAdversarial).count();
        long realisticCount = allCases.stream().filter(BenchmarkCase::isRealistic).count();
        long crossFileCount = allCases.stream().filter(BenchmarkCase::isCrossFile).count();

        assertEquals(26, canonicalCount, "Must have exactly 26 canonical cases");
        assertEquals(50, adversarialCount, "Must have exactly 50 adversarial cases");
        assertEquals(30, realisticCount, "Must have exactly 30 realistic cases");
        assertEquals(2, crossFileCount, "Must have exactly 2 cross-file cases");

        long canonicalVuln = allCases.stream().filter(c -> c.isCanonical() && "VULNERABLE".equalsIgnoreCase(c.getCaseType())).count();
        long canonicalSafe = allCases.stream().filter(c -> c.isCanonical() && "SAFE".equalsIgnoreCase(c.getCaseType())).count();
        assertEquals(13, canonicalVuln, "Canonical baseline must have 13 vulnerable fixtures");
        assertEquals(13, canonicalSafe, "Canonical baseline must have 13 safe fixtures");
    }

    @Test
    @DisplayName("No duplicate case IDs exist across the combined suite")
    void testNoDuplicateCaseIds() {
        Set<String> seenIds = new HashSet<>();
        List<String> duplicates = new ArrayList<>();

        for (BenchmarkCase bCase : allCases) {
            String cid = bCase.getCaseId();
            assertNotNull(cid, "Case ID must not be null");
            assertFalse(cid.isBlank(), "Case ID must not be blank");
            if (!seenIds.add(cid)) {
                duplicates.add(cid);
            }
        }

        assertTrue(duplicates.isEmpty(), "Duplicate case IDs detected: " + duplicates);
    }

    @Test
    @DisplayName("All fixture paths and primary fixture paths exist on disk")
    void testAllFixturePathsExistOnDisk() {
        List<String> missing = new ArrayList<>();

        for (BenchmarkCase bCase : allCases) {
            String primary = bCase.getPrimaryFixturePath();
            assertNotNull(primary, "Primary fixture path must not be null for " + bCase.getCaseId());
            if (!Files.exists(Path.of(primary))) {
                missing.add(bCase.getCaseId() + " -> " + primary);
            }

            for (String p : bCase.getFixturePaths()) {
                if (!Files.exists(Path.of(p))) {
                    missing.add(bCase.getCaseId() + " -> " + p);
                }
            }
        }

        assertTrue(missing.isEmpty(), "Missing fixture files on disk: " + missing);
    }

    @Test
    @DisplayName("Every case maps to a recognized SecurityRule enum")
    void testAllCasesMapToValidSecurityRules() {
        Set<String> validRuleIds = Arrays.stream(SecurityRule.values())
                .map(SecurityRule::getRuleId)
                .collect(Collectors.toSet());

        List<String> invalid = new ArrayList<>();
        for (BenchmarkCase bCase : allCases) {
            String ruleId = bCase.getRuleId();
            if (!validRuleIds.contains(ruleId)) {
                invalid.add(bCase.getCaseId() + " has unrecognized ruleId: " + ruleId);
            }
        }

        assertTrue(invalid.isEmpty(), "Cases with invalid ruleId found: " + invalid);
    }

    @Test
    @DisplayName("Adversarial distribution satisfies requirements (50 total cases)")
    void testAdversarialDistribution() {
        Map<String, Long> advPerRule = allCases.stream()
                .filter(BenchmarkCase::isAdversarial)
                .collect(Collectors.groupingBy(BenchmarkCase::getRuleId, Collectors.counting()));

        assertEquals(10L, advPerRule.getOrDefault("SEC-005-SQL-INJECTION", 0L), "SEC-005 must have 10 adversarial cases");
        assertEquals(8L, advPerRule.getOrDefault("SEC-008-HARDCODED-SECRET", 0L), "SEC-008 must have 8 adversarial cases");
        assertEquals(6L, advPerRule.getOrDefault("SEC-006-PATH-TRAVERSAL", 0L), "SEC-006 must have 6 adversarial cases");
        assertEquals(5L, advPerRule.getOrDefault("SEC-002-UNCLOSED-STREAM", 0L), "SEC-002 must have 5 adversarial cases");
        assertEquals(4L, advPerRule.getOrDefault("SEC-001-FAIL-OPEN", 0L), "SEC-001 must have 4 adversarial cases");
        assertEquals(3L, advPerRule.getOrDefault("SEC-003-VOLATILE-COMPOUND", 0L), "SEC-003 must have 3 adversarial cases");
        assertEquals(3L, advPerRule.getOrDefault("SEC-004-UNISOLATED-SUBPROCESS", 0L), "SEC-004 must have 3 adversarial cases");
        assertEquals(3L, advPerRule.getOrDefault("SEC-007-INSECURE-DESERIALIZATION", 0L), "SEC-007 must have 3 adversarial cases");
        assertEquals(2L, advPerRule.getOrDefault("SEC-009-SPRING-SECURITY-CSRF-DISABLED", 0L), "SEC-009 must have 2 adversarial cases");
        assertEquals(2L, advPerRule.getOrDefault("SEC-010-SPRING-PERMISSIVE-CORS", 0L), "SEC-010 must have 2 adversarial cases");
        assertEquals(2L, advPerRule.getOrDefault("ARCH-002-LEAKY-ABSTRACTION", 0L), "ARCH-002 must have 2 adversarial cases");
        assertEquals(2L, advPerRule.getOrDefault("ARCH-003-NON-DETERMINISTIC-CALLS", 0L), "ARCH-003 must have 2 adversarial cases");
    }
}
