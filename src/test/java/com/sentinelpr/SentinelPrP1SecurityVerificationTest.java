package com.sentinelpr;

import com.sentinelpr.client.SentinelClient;
import com.sentinelpr.core.analysis.FrameworkContextAnalyzer;
import com.sentinelpr.core.analysis.SecretScanningEngine;
import com.sentinelpr.core.model.InspectedSource;
import com.sentinelpr.core.model.ReviewReport;
import com.sentinelpr.core.model.SecurityFinding;
import com.sentinelpr.core.model.SecurityRule;
import com.sentinelpr.core.model.Severity;
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
 * <b>SentinelPrP1SecurityVerificationTest</b>
 *
 * <p>Integration test suite validating P1 enterprise security suite:</p>
 * <ol>
 *   <li>OWASP Top 10 Vulnerabilities: SQL Injection, Path Traversal, Insecure Deserialization</li>
 *   <li>Secret & Credential Scanner: Shannon entropy and pattern matching</li>
 *   <li>Spring Boot Framework Awareness: CSRF disabled and permissive CORS</li>
 *   <li>Unified Diff Remediation: Parameterization, Bounds Check, System.getenv, Restricted CORS</li>
 *   <li>False Positive Suppression on P1 rules</li>
 * </ol>
 */
class SentinelPrP1SecurityVerificationTest {

    private SentinelClient client;
    private SentinelAuditOrchestrator orchestrator;
    private CodeInspectionService inspectionService;
    private RuleEvaluationService evaluationService;
    private Path fixturePath;

    @BeforeEach
    void setUp() {
        client = SentinelClient.bootstrap("local");
        inspectionService = new CodeInspectionService(client);
        evaluationService = new RuleEvaluationService(client);

        orchestrator = new SentinelAuditOrchestrator(
                inspectionService,
                evaluationService,
                new AutomatedPatchService(client),
                new ReviewSessionMemory(client)
        );
        orchestrator.getSessionMemory().clearCache();

        fixturePath = Path.of("src/test/java/com/sentinelpr/fixture/EnterpriseSecurityVulnerableService.java");
        if (!Files.exists(fixturePath)) {
            fixturePath = Path.of("apps/sentinel-pr/src/test/java/com/sentinelpr/fixture/EnterpriseSecurityVulnerableService.java");
        }
        assertTrue(Files.exists(fixturePath), "Fixture must exist at: " + fixturePath.toAbsolutePath());
    }

    @Test
    @DisplayName("P1-1: OWASP & Framework rules detect SQL Injection, Path Traversal, Deserialization, Secrets, CORS")
    void testAllP1SecurityRulesDetected() throws IOException {
        InspectedSource source = inspectionService.inspectFile(fixturePath);
        List<SecurityFinding> findings = evaluationService.evaluate(source);

        assertNotNull(findings);
        assertFalse(findings.isEmpty(), "Findings should not be empty on vulnerable fixture");

        // 1. Verify SEC-005-SQL-INJECTION detected
        boolean hasSqlInjection = findings.stream().anyMatch(f ->
                f.getRule() == SecurityRule.SQL_INJECTION
                        && f.getSeverity() == Severity.CRITICAL
                        && "queryUserData".equals(f.getMethodName())
                        && f.getStartLine() > 0
        );
        assertTrue(hasSqlInjection, "Should detect SEC-005 SQL Injection in queryUserData");

        // 2. Verify SEC-006-PATH-TRAVERSAL detected
        boolean hasPathTraversal = findings.stream().anyMatch(f ->
                f.getRule() == SecurityRule.PATH_TRAVERSAL
                        && f.getSeverity() == Severity.CRITICAL
                        && "loadUserReport".equals(f.getMethodName())
                        && f.getStartLine() > 0
        );
        assertTrue(hasPathTraversal, "Should detect SEC-006 Path Traversal in loadUserReport");

        // 3. Verify SEC-007-INSECURE-DESERIALIZATION detected
        boolean hasInsecureDeserialization = findings.stream().anyMatch(f ->
                f.getRule() == SecurityRule.INSECURE_DESERIALIZATION
                        && f.getSeverity() == Severity.CRITICAL
                        && "deserializeUntrusted".equals(f.getMethodName())
                        && f.getStartLine() > 0
        );
        assertTrue(hasInsecureDeserialization, "Should detect SEC-007 Insecure Deserialization in deserializeUntrusted");

        // 4. Verify SEC-008-HARDCODED-SECRET detected for AWS Key
        boolean hasHardcodedSecret = findings.stream().anyMatch(f ->
                f.getRule() == SecurityRule.HARDCODED_SECRET
                        && f.getSeverity() == Severity.HIGH
                        && f.getVulnerableSnippet().contains("AKIA")
        );
        assertTrue(hasHardcodedSecret, "Should detect SEC-008 Hardcoded Secret for AWS Access Key");

        // 5. Verify SEC-010-SPRING-PERMISSIVE-CORS detected
        boolean hasPermissiveCors = findings.stream().anyMatch(f ->
                f.getRule() == SecurityRule.SPRING_PERMISSIVE_CORS
                        && f.getSeverity() == Severity.MEDIUM
                        && f.getVulnerableSnippet().contains("*")
        );
        assertTrue(hasPermissiveCors, "Should detect SEC-010 Permissive CORS on class annotation");

        // 6. Verify safe baseline (loadSecuredDocument) does NOT produce Path Traversal
        boolean falsePositiveOnSafeMethod = findings.stream().anyMatch(f ->
                f.getRule() == SecurityRule.PATH_TRAVERSAL
                        && "loadSecuredDocument".equals(f.getMethodName())
        );
        assertFalse(falsePositiveOnSafeMethod, "Safe method with .normalize() and .startsWith() must not produce false positive");
    }

    @Test
    @DisplayName("P1-2: SecretScanningEngine entropy scoring, pattern matching, and whitelisting")
    void testSecretScanningEntropyAndPatterns() {
        SecretScanningEngine scanner = new SecretScanningEngine();

        // High entropy random token
        String highEntropyToken = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        double entropy = SecretScanningEngine.calculateShannonEntropy(highEntropyToken);
        assertTrue(entropy > SecretScanningEngine.ENTROPY_THRESHOLD, "High entropy string should score > 3.2 (was: " + entropy + ")");

        // Low entropy repeated token
        String lowEntropyToken = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        double lowEntropy = SecretScanningEngine.calculateShannonEntropy(lowEntropyToken);
        assertEquals(0.0, lowEntropy, 0.001, "Monotonous string should have 0 entropy");

        // Redaction verification
        String redacted = SecretScanningEngine.redactSecret("AKIAIOSFODNN7EXAMPLE");
        assertEquals("AKIA...MPLE", redacted);

        // Scan code with dummy password vs high-entropy secret
        String dummyCode = """
            package com.example;
            public class DummyService {
                private String password = "password123";
                private String testSecret = "dummy";
                private String adminPass = "admin";
            }
            """;
        InspectedSource dummySource = inspectionService.inspectSourceCode(dummyCode, "DummyService.java");
        List<SecurityFinding> dummyFindings = scanner.scan(dummySource);
        assertTrue(dummyFindings.isEmpty(), "Whitelisted placeholder passwords must not be flagged");
    }

    @Test
    @DisplayName("P1-3: FrameworkContextAnalyzer detects CSRF disabled and verifies stateless exemption")
    void testSpringFrameworkAwareness() {
        FrameworkContextAnalyzer analyzer = new FrameworkContextAnalyzer();

        // 1. Vulnerable: CSRF disabled without stateless session
        String vulnerableCsrfCode = """
            package com.example;
            import org.springframework.context.annotation.Bean;
            import org.springframework.security.config.annotation.web.builders.HttpSecurity;
            import org.springframework.security.web.SecurityFilterChain;
            public class SecurityConfig {
                @Bean
                public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
                    http.csrf().disable();
                    return http.build();
                }
            }
            """;
        InspectedSource vulnSource = inspectionService.inspectSourceCode(vulnerableCsrfCode, "SecurityConfig.java");
        List<SecurityFinding> vulnFindings = analyzer.evaluateCsrfDisabled(vulnSource);
        assertEquals(1, vulnFindings.size(), "Should flag CSRF disabled on stateful config");
        assertEquals(SecurityRule.SPRING_SECURITY_CSRF_DISABLED, vulnFindings.get(0).getRule());
        assertEquals(Severity.HIGH, vulnFindings.get(0).getSeverity());

        // 2. Safe: CSRF disabled WITH stateless session creation policy
        String statelessCsrfCode = """
            package com.example;
            import org.springframework.context.annotation.Bean;
            import org.springframework.security.config.annotation.web.builders.HttpSecurity;
            import org.springframework.security.config.http.SessionCreationPolicy;
            import org.springframework.security.web.SecurityFilterChain;
            public class StatelessSecurityConfig {
                @Bean
                public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
                    http.csrf().disable()
                        .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
                    return http.build();
                }
            }
            """;
        InspectedSource statelessSource = inspectionService.inspectSourceCode(statelessCsrfCode, "StatelessSecurityConfig.java");
        List<SecurityFinding> safeFindings = analyzer.evaluateCsrfDisabled(statelessSource);
        assertTrue(safeFindings.isEmpty(), "Stateless session configuration must exempt CSRF disablement");
    }

    @Test
    @DisplayName("P1-4: Unified Diff remediations generate valid Java 21 LTS syntax")
    void testP1UnifiedDiffRemediationsAndAstValidity() throws IOException {
        InspectedSource source = inspectionService.inspectFile(fixturePath);
        List<SecurityFinding> findings = evaluationService.evaluate(source);

        // Test Patch on SEC-005 SQL Injection
        SecurityFinding sqlFinding = findings.stream()
                .filter(f -> f.getRule() == SecurityRule.SQL_INJECTION && "queryUserData".equals(f.getMethodName()))
                .findFirst()
                .orElseThrow();

        UnifiedDiffPatch sqlPatch = client.developer().generatePatch(source, sqlFinding);
        assertNotNull(sqlPatch);
        assertTrue(sqlPatch.isAstValid(), "SQL Injection patch must be syntactically valid Java 21 LTS");
        assertTrue(sqlPatch.getUnifiedDiff().contains("+"), "SQL Patch must contain additions");

        // Test Patch on SEC-006 Path Traversal
        SecurityFinding pathFinding = findings.stream()
                .filter(f -> f.getRule() == SecurityRule.PATH_TRAVERSAL && "loadUserReport".equals(f.getMethodName()))
                .findFirst()
                .orElseThrow();

        UnifiedDiffPatch pathPatch = client.developer().generatePatch(source, pathFinding);
        assertNotNull(pathPatch);
        assertTrue(pathPatch.isAstValid(), "Path Traversal patch must be syntactically valid Java 21 LTS");
        assertTrue(pathPatch.getUnifiedDiff().contains("getCanonicalFile") || pathPatch.getUnifiedDiff().contains("normalize"),
                "Path Traversal patch should introduce canonical or normalized path guards");

        // Test Patch on SEC-008 Hardcoded Secret
        SecurityFinding secretFinding = findings.stream()
                .filter(f -> f.getRule() == SecurityRule.HARDCODED_SECRET)
                .findFirst()
                .orElseThrow();

        UnifiedDiffPatch secretPatch = client.developer().generatePatch(source, secretFinding);
        assertNotNull(secretPatch);
        assertTrue(secretPatch.isAstValid(), "Secret patch must be syntactically valid Java 21 LTS");
        assertTrue(secretPatch.getUnifiedDiff().contains("System.getenv"), "Secret patch must externalize credentials to System.getenv");

        // Test Patch on SEC-010 Permissive CORS
        SecurityFinding corsFinding = findings.stream()
                .filter(f -> f.getRule() == SecurityRule.SPRING_PERMISSIVE_CORS)
                .findFirst()
                .orElseThrow();

        UnifiedDiffPatch corsPatch = client.developer().generatePatch(source, corsFinding);
        assertNotNull(corsPatch);
        assertTrue(corsPatch.isAstValid(), "CORS patch must be syntactically valid Java 21 LTS");
        assertTrue(corsPatch.getUnifiedDiff().contains("https://trusted.domain.com"), "CORS patch must restrict origins to trusted domain");
    }

    @Test
    @DisplayName("P1-5: False Positive Suppression engine functions properly on P1 rules")
    void testSuppressionEngineWorksOnP1Rules() throws IOException {
        ReviewReport report = orchestrator.auditPath(fixturePath);

        assertNotNull(report);
        assertNotNull(report.getSuppressedFindings());

        // 1. Verify queryUserDataSuppressed is suppressed via @SuppressWarnings("sentinel:SEC-005")
        boolean sqlSuppressed = report.getSuppressedFindings().stream().anyMatch(sf ->
                sf.getFinding().getRule() == SecurityRule.SQL_INJECTION
                        && "queryUserDataSuppressed".equals(sf.getFinding().getMethodName())
                        && sf.getSuppressionType().equals("ANNOTATION")
        );
        assertTrue(sqlSuppressed, "SQL Injection finding on queryUserDataSuppressed must be suppressed via annotation");

        // 2. Verify loadSystemAsset is suppressed via inline comment // sentinel-ignore SEC-006
        boolean pathSuppressed = report.getSuppressedFindings().stream().anyMatch(sf ->
                sf.getFinding().getRule() == SecurityRule.PATH_TRAVERSAL
                        && "loadSystemAsset".equals(sf.getFinding().getMethodName())
                        && sf.getSuppressionType().equals("INLINE_COMMENT")
        );
        assertTrue(pathSuppressed, "Path Traversal finding on loadSystemAsset must be suppressed via inline comment");

        // 3. Unsuppressed active findings must remain in report.getFindings()
        boolean activeSqlRemains = report.getFindings().stream().anyMatch(f ->
                f.getRule() == SecurityRule.SQL_INJECTION && "queryUserData".equals(f.getMethodName())
        );
        assertTrue(activeSqlRemains, "Active unsuppressed SQL Injection finding must remain active");
    }
}
