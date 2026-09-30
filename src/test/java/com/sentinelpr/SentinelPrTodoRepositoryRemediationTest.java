package com.sentinelpr;

import com.sentinelpr.client.SentinelClient;
import com.sentinelpr.core.model.InspectedSource;
import com.sentinelpr.core.model.ReviewReport;
import com.sentinelpr.core.model.SecurityFinding;
import com.sentinelpr.core.model.SecurityRule;
import com.sentinelpr.core.model.UnifiedDiffPatch;
import com.sentinelpr.core.remediation.PatchQualityMetrics;
import com.sentinelpr.core.remediation.PatchValidationStatus;
import com.sentinelpr.core.service.AutomatedPatchService;
import com.sentinelpr.core.service.CodeInspectionService;
import com.sentinelpr.core.service.PatchVerifier;
import com.sentinelpr.core.service.ReviewSessionMemory;
import com.sentinelpr.core.service.RuleEvaluationService;
import com.sentinelpr.core.service.SentinelAuditOrchestrator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * <b>SentinelPrTodoRepositoryRemediationTest</b>
 *
 * <p>Regression test suite specifically verifying the TodoRepository scenario and
 * patch intelligence hardening requirements for SentinelPR v1.1.4:</p>
 * <ol>
 *   <li>Requirement A: SEC-005 SQL injection remediation produces PreparedStatement, '?', setString, executeQuery.</li>
 *   <li>Requirement B: SEC-008 Hardcoded DB credentials produce DB_URL, DB_USER, DB_PASSWORD, NOT APP_SECRET.</li>
 *   <li>Requirement C: Combined findings in TodoRepository produce a coherent, composable remediation.</li>
 *   <li>Requirement D: Invalid generated patches are rejected and fall back safely.</li>
 *   <li>Requirement E: Strict regression protection ensuring JDBC credentials are NEVER replaced with APP_SECRET.</li>
 *   <li>Quality metrics telemetry validation.</li>
 * </ol>
 */
class SentinelPrTodoRepositoryRemediationTest {

    private SentinelClient client;
    private CodeInspectionService inspectionService;
    private RuleEvaluationService evaluationService;
    private AutomatedPatchService patchService;
    private SentinelAuditOrchestrator orchestrator;

    private static final String TODO_REPOSITORY_SOURCE = """
            package com.example.repository;

            import java.sql.Connection;
            import java.sql.DriverManager;
            import java.sql.ResultSet;
            import java.sql.SQLException;
            import java.sql.Statement;

            public class TodoRepository {

                public ResultSet getTodos(String titleFilter) throws SQLException {
                    Connection conn = DriverManager.getConnection(
                        "jdbc:mysql://localhost:3306/tododb",
                        "root",
                        ""
                    );

                    Statement stmt = conn.createStatement();

                    String rawSql =
                        "SELECT * FROM todos WHERE title = '" + titleFilter + "'";

                    ResultSet rs = stmt.executeQuery(rawSql);
                    return rs;
                }
            }
            """;

    @BeforeEach
    void setUp() {
        client = SentinelClient.bootstrap("local");
        inspectionService = new CodeInspectionService(client);
        evaluationService = new RuleEvaluationService(client);
        patchService = new AutomatedPatchService(client);
        ReviewSessionMemory sessionMemory = new ReviewSessionMemory(client);

        orchestrator = new SentinelAuditOrchestrator(
                inspectionService,
                evaluationService,
                patchService,
                sessionMemory
        );
        orchestrator.getSessionMemory().clearCache();
    }

    @Test
    @DisplayName("Task 8-A: SEC-005 SQL Injection generates PreparedStatement, ?, setString, and executeQuery without raw concatenation")
    void testSqlInjectionRemediation() {
        String sqlOnlyCode = """
                package com.example;

                import java.sql.Connection;
                import java.sql.ResultSet;
                import java.sql.SQLException;
                import java.sql.Statement;

                public class TodoSearchService {
                    public ResultSet search(Connection conn, String titleFilter) throws SQLException {
                        Statement stmt = conn.createStatement();
                        String rawSql = "SELECT * FROM todos WHERE title = '" + titleFilter + "'";
                        ResultSet rs = stmt.executeQuery(rawSql);
                        return rs;
                    }
                }
                """;

        InspectedSource source = inspectionService.inspectSourceCode(sqlOnlyCode, "TodoSearchService.java");
        List<SecurityFinding> findings = evaluationService.evaluate(source);

        SecurityFinding sqlFinding = findings.stream()
                .filter(f -> f.getRule() == SecurityRule.SQL_INJECTION)
                .findFirst()
                .orElseThrow(() -> new AssertionError("Expected SEC-005 SQL Injection finding"));

        UnifiedDiffPatch patch = patchService.generatePatch(source, sqlFinding);

        assertNotNull(patch, "Patch must not be null");
        assertTrue(patch.isAstValid(), "SQL Injection patch must be syntactically valid Java 21");
        assertEquals(PatchValidationStatus.VALID_PATCH, patch.getValidationStatus());

        String patchedSource = patch.getPatchedSource();
        String diff = patch.getUnifiedDiff();

        // Required properties from prompt:
        assertTrue(patchedSource.contains("PreparedStatement"), "Must introduce PreparedStatement");
        assertTrue(patchedSource.contains("?"), "Must introduce '?' placeholder");
        assertTrue(patchedSource.contains("setString"), "Must introduce parameter binding (setString)");
        assertTrue(patchedSource.contains("executeQuery()"), "Must call zero-argument executeQuery() on PreparedStatement");

        // Negative check: MUST NOT contain raw user-input string concatenation into SQL
        assertFalse(patchedSource.contains("WHERE title = '\" + titleFilter"),
                "Must NOT contain raw string concatenation of titleFilter into SQL");
        assertFalse(diff.contains("+ String rawSql = \"SELECT * FROM todos WHERE title = '\""),
                "Diff must not retain vulnerable raw SQL concatenation");

        // Quality metrics check
        PatchQualityMetrics metrics = patch.getQualityMetrics();
        assertNotNull(metrics);
        assertTrue(metrics.isPatchGenerated());
        assertTrue(metrics.isPatchValidated());
        assertFalse(metrics.isPatchRejected());
        assertTrue(metrics.getStrategyUsed().contains("SqlInjection"));
    }

    @Test
    @DisplayName("Task 8-B: SEC-008 Hardcoded DB credentials generate DB_URL, DB_USER, DB_PASSWORD, NOT APP_SECRET")
    void testHardcodedDbCredentialsRemediation() {
        String dbCredsCode = """
                package com.example;

                import java.sql.Connection;
                import java.sql.DriverManager;
                import java.sql.SQLException;

                public class DbConnectionFactory {
                    public Connection createConnection() throws SQLException {
                        return DriverManager.getConnection(
                            "jdbc:mysql://localhost:3306/tododb",
                            "root",
                            ""
                        );
                    }
                }
                """;

        InspectedSource source = inspectionService.inspectSourceCode(dbCredsCode, "DbConnectionFactory.java");
        List<SecurityFinding> findings = evaluationService.evaluate(source);

        SecurityFinding secretFinding = findings.stream()
                .filter(f -> f.getRule() == SecurityRule.HARDCODED_SECRET)
                .findFirst()
                .orElseThrow(() -> new AssertionError("Expected SEC-008 finding on hardcoded DB credentials"));

        UnifiedDiffPatch patch = patchService.generatePatch(source, secretFinding);

        assertNotNull(patch, "Patch must not be null");
        assertTrue(patch.isAstValid(), "DB credentials patch must be syntactically valid Java 21");
        assertEquals(PatchValidationStatus.VALID_PATCH, patch.getValidationStatus());

        String patchedSource = patch.getPatchedSource();

        // Expected: DB_URL, DB_USER, DB_PASSWORD
        assertTrue(patchedSource.contains("System.getenv(\"DB_URL\")"), "Must externalize DB URL to DB_URL");
        assertTrue(patchedSource.contains("System.getenv(\"DB_USER\")"), "Must externalize DB user to DB_USER");
        assertTrue(patchedSource.contains("System.getenv(\"DB_PASSWORD\")"), "Must externalize DB password to DB_PASSWORD");

        // STRICT REQUIREMENT: MUST NOT use APP_SECRET for database credentials
        assertFalse(patchedSource.contains("APP_SECRET"), "Database credentials must NEVER be replaced with APP_SECRET");
        assertFalse(patch.getUnifiedDiff().contains("APP_SECRET"), "Unified diff must NEVER contain APP_SECRET for DB connection");
    }

    @Test
    @DisplayName("Task 8-C: Combined findings in TodoRepository produce a coherent, composable remediation")
    void testCombinedFindingsRemediation() {
        ReviewReport report = orchestrator.auditSourceCode(TODO_REPOSITORY_SOURCE, "TodoRepository.java");

        assertNotNull(report, "ReviewReport must not be null");
        List<SecurityFinding> findings = report.getFindings();

        // 1. Verify both SEC-005 and SEC-008 are discovered
        boolean hasSql = findings.stream().anyMatch(f -> f.getRule() == SecurityRule.SQL_INJECTION);
        boolean hasSecret = findings.stream().anyMatch(f -> f.getRule() == SecurityRule.HARDCODED_SECRET);

        assertTrue(hasSql, "Must discover SEC-005 SQL Injection in TodoRepository");
        assertTrue(hasSecret, "Must discover SEC-008 Hardcoded Credentials in TodoRepository");

        // 2. Exactly ONE composable unified diff patch generated for the file
        List<UnifiedDiffPatch> patches = report.getPatches();
        assertNotNull(patches);
        assertEquals(1, patches.size(), "PatchComposer must produce exactly ONE composed unified diff for the multi-vulnerability file");

        UnifiedDiffPatch composedPatch = patches.get(0);
        assertTrue(composedPatch.isAstValid(), "Composed patch must be syntactically valid Java 21");
        assertEquals(PatchValidationStatus.VALID_PATCH, composedPatch.getValidationStatus());
        assertEquals(UnifiedDiffPatch.Status.SUCCESS, composedPatch.getStatus());

        String patchedSource = composedPatch.getPatchedSource();

        // Verify SEC-008 fix is present in composed source
        assertTrue(patchedSource.contains("DB_URL"), "Composed patch must include DB_URL");
        assertTrue(patchedSource.contains("DB_USER"), "Composed patch must include DB_USER");
        assertTrue(patchedSource.contains("DB_PASSWORD"), "Composed patch must include DB_PASSWORD");
        assertFalse(patchedSource.contains("APP_SECRET"), "Composed patch must NOT contain APP_SECRET");

        // Verify SEC-005 fix is present in composed source
        assertTrue(patchedSource.contains("PreparedStatement"), "Composed patch must include PreparedStatement");
        assertTrue(patchedSource.contains("?"), "Composed patch must include '?' placeholder");
        assertTrue(patchedSource.contains("setString"), "Composed patch must include parameter binding");
        assertTrue(patchedSource.contains("executeQuery()"), "Composed patch must include zero-argument executeQuery()");
        assertFalse(patchedSource.contains("WHERE title = '\" + titleFilter"), "Composed patch must NOT contain raw SQL concatenation");

        // 3. Post-patch regression verification: 0 critical vulnerabilities remain
        assertTrue(composedPatch.isRegressionVerified(),
                "Composed patch must pass post-patch regression verification: " + composedPatch.getVerificationMessage());
    }

    @Test
    @DisplayName("Task 8-D: Invalid generated patch is rejected and deterministic fallback is safely handled")
    void testInvalidGeneratedPatchRejection() {
        PatchVerifier verifier = new PatchVerifier(inspectionService, evaluationService);

        // Simulate malformed source code (e.g. syntax error with unbalanced brackets and missing semicolon)
        String malformedSource = """
                package com.example;
                public class MalformedClass {
                    public void brokenMethod( {
                        String x = "unclosed string
                    }
                """;

        var result = verifier.verify(malformedSource, "MalformedClass.java");
        assertFalse(result.isSyntaxValid(), "Malformed source must fail AST syntax validation");
        assertEquals(PatchValidationStatus.INVALID_PATCH, result.getValidationStatus());
        assertFalse(result.isRegressionVerified(), "Malformed source must not pass regression verification");
    }

    @Test
    @DisplayName("Task 8-E: Regression protection - arbitrary JDBC credentials are NEVER replaced with APP_SECRET")
    void testRegressionProtectionJdbcNeverReplacedWithAppSecret() {
        String[] jdbcVariations = {
                // MySQL
                """
                package com.example;
                import java.sql.DriverManager;
                public class Repo1 {
                    public void connect() throws Exception {
                        DriverManager.getConnection("jdbc:mysql://localhost:3306/db", "root", "secret1");
                    }
                }
                """,
                // PostgreSQL
                """
                package com.example;
                import java.sql.DriverManager;
                public class Repo2 {
                    public void connect() throws Exception {
                        DriverManager.getConnection("jdbc:postgresql://localhost:5432/proddb", "postgres_user", "postgres_pass");
                    }
                }
                """,
                // Oracle
                """
                package com.example;
                import java.sql.DriverManager;
                public class Repo3 {
                    public void connect() throws Exception {
                        DriverManager.getConnection("jdbc:oracle:thin:@localhost:1521:xe", "oracle_admin", "oracle_pwd");
                    }
                }
                """
        };

        for (int i = 0; i < jdbcVariations.length; i++) {
            String code = jdbcVariations[i];
            InspectedSource source = inspectionService.inspectSourceCode(code, "Repo" + (i + 1) + ".java");
            List<SecurityFinding> findings = evaluationService.evaluate(source);

            assertFalse(findings.isEmpty(), "Variation " + (i + 1) + " must detect finding");
            for (SecurityFinding finding : findings) {
                if (finding.getRule() == SecurityRule.HARDCODED_SECRET) {
                    UnifiedDiffPatch patch = patchService.generatePatch(source, finding);
                    assertNotNull(patch);

                    // Assert: NEVER replace arbitrary JDBC credentials with APP_SECRET
                    assertFalse(patch.getPatchedSource().contains("APP_SECRET"),
                            "Variation " + (i + 1) + " must NEVER produce APP_SECRET for JDBC credentials");
                    assertTrue(patch.getPatchedSource().contains("DB_URL") || patch.getPatchedSource().contains("DB_USER") || patch.getPatchedSource().contains("DB_PASSWORD"),
                            "Variation " + (i + 1) + " must produce DB_URL/DB_USER/DB_PASSWORD");
                }
            }
        }
    }

    @Test
    @DisplayName("Task 9: Patch quality metrics are exposed internally")
    void testPatchQualityMetricsExposed() {
        ReviewReport report = orchestrator.auditSourceCode(TODO_REPOSITORY_SOURCE, "TodoRepository.java");
        assertNotNull(report);
        assertFalse(report.getPatches().isEmpty());

        UnifiedDiffPatch patch = report.getPatches().get(0);
        PatchQualityMetrics metrics = patch.getQualityMetrics();

        assertNotNull(metrics, "PatchQualityMetrics must not be null");
        assertTrue(metrics.isPatchGenerated(), "Metrics must indicate patch was generated");
        assertTrue(metrics.isPatchValidated(), "Metrics must indicate patch was validated");
        assertFalse(metrics.isPatchRejected(), "Metrics must indicate patch was not rejected");
        assertNotNull(metrics.getStrategyUsed(), "Strategy used must be reported");
        assertFalse(metrics.getAppliedStrategies().isEmpty(), "Applied strategies must be tracked");
        assertEquals(PatchValidationStatus.VALID_PATCH, patch.getValidationStatus());
    }

    @Test
    @DisplayName("H-1 Regression: Intervening statements between Statement and SQL declaration survive untouched")
    void testH1InterveningCodePreservation() {
        String codeWithInterveningStatements = """
                package com.example.repository;

                import java.sql.Connection;
                import java.sql.ResultSet;
                import java.sql.SQLException;
                import java.sql.Statement;

                public class InterveningCodeRepository {

                    public ResultSet searchTodos(Connection conn, String titleFilter) throws SQLException {
                        Statement stmt = conn.createStatement();

                        validateTitle(titleFilter);
                        System.out.println("audit");

                        String rawSql = "SELECT * FROM todos WHERE title = '" + titleFilter + "'";

                        ResultSet rs = stmt.executeQuery(rawSql);
                        return rs;
                    }

                    private void validateTitle(String title) {
                        if (title == null) {
                            throw new IllegalArgumentException("title required");
                        }
                    }
                }
                """;

        InspectedSource source = inspectionService.inspectSourceCode(codeWithInterveningStatements, "InterveningCodeRepository.java");
        List<SecurityFinding> findings = evaluationService.evaluate(source);

        SecurityFinding sqlFinding = findings.stream()
                .filter(f -> f.getRule() == SecurityRule.SQL_INJECTION)
                .findFirst()
                .orElseThrow(() -> new AssertionError("Expected SEC-005 finding"));

        UnifiedDiffPatch patch = patchService.generatePatch(source, sqlFinding);
        assertNotNull(patch);
        assertTrue(patch.isAstValid(), "Patch must be syntactically valid Java 21");

        String patchedSource = patch.getPatchedSource();

        // STRICT H-1 CHECKS: All intervening statements MUST be preserved
        assertTrue(patchedSource.contains("validateTitle(titleFilter);"),
                "Intervening statement 'validateTitle(titleFilter);' MUST survive patch");
        assertTrue(patchedSource.contains("System.out.println(\"audit\");"),
                "Intervening statement 'System.out.println(\"audit\");' MUST survive patch");

        // SQL injection remediation checks
        assertTrue(patchedSource.contains("PreparedStatement"), "Must introduce PreparedStatement");
        assertTrue(patchedSource.contains("?"), "SQL must be parameterized with '?'");
        assertTrue(patchedSource.contains("setString"), "Parameter binding must be introduced");
        assertTrue(patchedSource.contains("executeQuery()"), "Must call zero-argument executeQuery()");
        assertFalse(patchedSource.contains("WHERE title = '\" + titleFilter"),
                "Must NOT retain raw SQL concatenation");
    }

    @Test
    @DisplayName("H-2 Regression: Line-shift protection allows subsequent findings to target correct construct")
    void testH2LineShiftProtection() {
        // Finding 1 (lines 11-16): SQL injection that introduces multiple lines
        // Finding 2 (lines 20-22): Hardcoded secret on a later line
        String multiFindingCode = """
                package com.example;

                import java.sql.Connection;
                import java.sql.ResultSet;
                import java.sql.SQLException;
                import java.sql.Statement;

                public class MultiIssueService {

                    public ResultSet queryData(Connection conn, String filter) throws SQLException {
                        Statement stmt = conn.createStatement();
                        String query = "SELECT * FROM items WHERE name = '" + filter + "'";
                        ResultSet rs = stmt.executeQuery(query);
                        return rs;
                    }

                    public String getApiKey() {
                        String apiKey = "secret_token_value_12345";
                        return apiKey;
                    }
                }
                """;

        ReviewReport report = orchestrator.auditSourceCode(multiFindingCode, "MultiIssueService.java");
        assertNotNull(report);
        List<SecurityFinding> findings = report.getFindings();

        boolean hasSql = findings.stream().anyMatch(f -> f.getRule() == SecurityRule.SQL_INJECTION);
        boolean hasSecret = findings.stream().anyMatch(f -> f.getRule() == SecurityRule.HARDCODED_SECRET);
        assertTrue(hasSql, "Must find SEC-005");
        assertTrue(hasSecret, "Must find SEC-008");

        List<UnifiedDiffPatch> patches = report.getPatches();
        assertFalse(patches.isEmpty(), "Must generate composite patch");
        UnifiedDiffPatch composed = patches.get(0);

        assertTrue(composed.isAstValid(), "Composed patch must be valid Java 21");
        String patched = composed.getPatchedSource();

        // Verify Finding 1 (SQL injection) was remediated
        assertTrue(patched.contains("PreparedStatement"), "SQL injection must be fixed with PreparedStatement");
        assertTrue(patched.contains("?"), "Query must be parameterized");

        // Verify Finding 2 (Secret) was remediated at its shifted line, NOT modifying unrelated code
        assertTrue(patched.contains("System.getenv(\"API_KEY\")"),
                "Finding 2 at shifted line must be correctly externalized to API_KEY");
        assertFalse(patched.contains("secret_token_value_12345"),
                "Hardcoded secret literal must be removed");

        // Verify queryData method body was not corrupted by the secret patch
        assertTrue(patched.contains("queryData"), "queryData method must remain intact");
        assertTrue(patched.contains("getApiKey"), "getApiKey method must remain intact");
    }

    @Test
    @DisplayName("SEC-005: stmt.execute(rawSql) is rewritten to zero-argument execute()")
    void testStmtExecuteSupport() {
        String executeCode = """
                package com.example.repository;

                import java.sql.Connection;
                import java.sql.SQLException;
                import java.sql.Statement;

                public class ExecuteRepo {
                    public boolean executeCommand(Connection conn, String statusFilter) throws SQLException {
                        Statement stmt = conn.createStatement();
                        String rawSql = "DELETE FROM todos WHERE status = '" + statusFilter + "'";
                        boolean result = stmt.execute(rawSql);
                        return result;
                    }
                }
                """;

        InspectedSource source = inspectionService.inspectSourceCode(executeCode, "ExecuteRepo.java");
        List<SecurityFinding> findings = evaluationService.evaluate(source);

        SecurityFinding sqlFinding = findings.stream()
                .filter(f -> f.getRule() == SecurityRule.SQL_INJECTION)
                .findFirst()
                .orElseThrow(() -> new AssertionError("Expected SEC-005 finding"));

        UnifiedDiffPatch patch = patchService.generatePatch(source, sqlFinding);
        assertNotNull(patch);
        assertTrue(patch.isAstValid(), "Patch must be valid Java 21");

        String patchedSource = patch.getPatchedSource();

        // Verify stmt.execute(rawSql) -> stmt.execute()
        assertTrue(patchedSource.contains("stmt.execute()"), "Must convert stmt.execute(rawSql) to stmt.execute()");
        assertFalse(patchedSource.contains("stmt.execute(rawSql)"), "Must not retain rawSql parameter in execute call");
        assertTrue(patchedSource.contains("PreparedStatement"), "Must introduce PreparedStatement");
        assertTrue(patchedSource.contains("?"), "Must parameterize query");
    }

    @Test
    @DisplayName("SEC-005: Primitive numeric parameters use setObject for type safety")
    void testNumericSqlParameterTypeSafety() {
        String numericParamCode = """
                package com.example.repository;

                import java.sql.Connection;
                import java.sql.ResultSet;
                import java.sql.SQLException;
                import java.sql.Statement;

                public class NumericParamRepository {
                    public ResultSet getById(Connection conn, int userId) throws SQLException {
                        Statement stmt = conn.createStatement();
                        String rawSql = "SELECT * FROM users WHERE id = " + userId;
                        ResultSet rs = stmt.executeQuery(rawSql);
                        return rs;
                    }
                }
                """;

        InspectedSource source = inspectionService.inspectSourceCode(numericParamCode, "NumericParamRepository.java");
        List<SecurityFinding> findings = evaluationService.evaluate(source);

        SecurityFinding sqlFinding = findings.stream()
                .filter(f -> f.getRule() == SecurityRule.SQL_INJECTION)
                .findFirst()
                .orElseThrow(() -> new AssertionError("Expected SEC-005 finding on numeric query"));

        UnifiedDiffPatch patch = patchService.generatePatch(source, sqlFinding);
        assertNotNull(patch);
        assertTrue(patch.isAstValid(), "Patch must be valid Java 21");

        String patchedSource = patch.getPatchedSource();

        // Must use setObject(1, userId) rather than setString(1, userId)
        assertTrue(patchedSource.contains("setObject(1, userId)"),
                "Numeric parameter 'userId' must use setObject for type safety: " + patchedSource);
        assertFalse(patchedSource.contains("setString(1, userId)"),
                "Must NOT use setString for primitive int userId");
        assertTrue(patchedSource.contains("?"), "Query must be parameterized");
    }
}
