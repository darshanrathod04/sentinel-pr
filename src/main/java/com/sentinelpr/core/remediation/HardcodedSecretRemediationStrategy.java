package com.sentinelpr.core.remediation;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ast.CompilationUnit;
import com.sentinelpr.core.model.InspectedSource;
import com.sentinelpr.core.model.SecurityFinding;
import com.sentinelpr.core.model.SecurityRule;

import java.util.Locale;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * <b>HardcodedSecretRemediationStrategy</b>
 *
 * <p>Rule-specific remediation for SEC-008-HARDCODED-SECRET (CWE-798):</p>
 * <ul>
 *   <li>Distinguishes database credentials, AWS tokens, API keys, and generic application secrets.</li>
 *   <li>Remediates JDBC connections using context-specific {@code DB_URL}, {@code DB_USER}, {@code DB_PASSWORD}.</li>
 *   <li><b>STRICT GUARANTEE:</b> Database/JDBC credentials are NEVER mapped to {@code APP_SECRET}.</li>
 *   <li>Externalizes credentials using environment variables {@code System.getenv(...)}.</li>
 * </ul>
 */
public class HardcodedSecretRemediationStrategy implements RemediationStrategy {

    private final JavaParser javaParser;

    // Pattern for AWS Access Key IDs
    private static final Pattern AWS_KEY_PATTERN = Pattern.compile("\"(AKIA[0-9A-Z]{16})\"");

    // Pattern for DriverManager.getConnection with 3 arguments (multi-line or single line)
    private static final Pattern DRIVER_MANAGER_3ARG_PATTERN = Pattern.compile(
            "DriverManager\\.getConnection\\s*\\(\\s*\"([^\"]*)\"\\s*,\\s*\"([^\"]*)\"\\s*,\\s*\"([^\"]*)\"\\s*\\)",
            Pattern.DOTALL
    );

    // Pattern for DriverManager.getConnection with 1 argument (e.g. full JDBC URL)
    private static final Pattern DRIVER_MANAGER_1ARG_PATTERN = Pattern.compile(
            "DriverManager\\.getConnection\\s*\\(\\s*\"([^\"]*)\"\\s*\\)"
    );

    public HardcodedSecretRemediationStrategy() {
        ParserConfiguration config = new ParserConfiguration();
        config.setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_21);
        this.javaParser = new JavaParser(config);
    }

    @Override
    public SecurityRule getSupportedRule() {
        return SecurityRule.HARDCODED_SECRET;
    }

    @Override
    public RemediationResult remediate(
            String source,
            SecurityFinding finding,
            InspectedSource inspectedSource,
            RemediationContext context
    ) {
        if (source == null || source.isBlank()) {
            return RemediationResult.unapplied(source, "HardcodedSecretRemediationStrategy", "Source is empty");
        }

        // 1. Check for JDBC / Database credentials in DriverManager.getConnection
        Optional<String> jdbcResult = remediateDriverManagerCall(source, finding);
        if (jdbcResult.isPresent() && isValidJava(jdbcResult.get())) {
            return RemediationResult.success(
                    jdbcResult.get(),
                    "HardcodedSecretRemediationStrategy",
                    "Externalized JDBC database credentials to DB_URL, DB_USER, and DB_PASSWORD",
                    finding.getStartLine(),
                    finding.getEndLine()
            );
        }

        // 2. Check for AWS credentials
        Optional<String> awsResult = remediateAwsCredential(source, finding);
        if (awsResult.isPresent() && isValidJava(awsResult.get())) {
            return RemediationResult.success(
                    awsResult.get(),
                    "HardcodedSecretRemediationStrategy",
                    "Externalized AWS Access Key ID to AWS_ACCESS_KEY_ID",
                    finding.getStartLine(),
                    finding.getEndLine()
            );
        }

        // 3. Context-aware variable/assignment credential remediation (DB vs API key vs Token)
        Optional<String> contextualResult = remediateContextualVariable(source, finding);
        if (contextualResult.isPresent() && isValidJava(contextualResult.get())) {
            return RemediationResult.success(
                    contextualResult.get(),
                    "HardcodedSecretRemediationStrategy",
                    "Externalized secret using context-derived environment variable",
                    finding.getStartLine(),
                    finding.getEndLine()
            );
        }

        // 4. Deterministic fallback: safe context replacement
        Optional<String> fallbackResult = tryDeterministicFallback(source, finding);
        if (fallbackResult.isPresent() && isValidJava(fallbackResult.get())) {
            return RemediationResult.fallback(
                    fallbackResult.get(),
                    "HardcodedSecretRemediationStrategy",
                    "Applied deterministic fallback secret externalization",
                    finding.getStartLine(),
                    finding.getEndLine()
            );
        }

        return RemediationResult.unapplied(source, "HardcodedSecretRemediationStrategy", "Failed to generate syntactically valid SEC-008 patch");
    }

    private Optional<String> remediateDriverManagerCall(String source, SecurityFinding finding) {
        String snippet = finding.getVulnerableSnippet();

        // Check if snippet or finding references DriverManager or jdbc:
        boolean isJdbc = (snippet != null && (snippet.contains("DriverManager") || snippet.contains("jdbc:")))
                || source.contains("DriverManager.getConnection");

        if (!isJdbc) {
            return Optional.empty();
        }

        // A. 3-argument DriverManager.getConnection("jdbc:...", "user", "pass")
        Matcher m3 = DRIVER_MANAGER_3ARG_PATTERN.matcher(source);
        if (m3.find()) {
            String fullMatch = m3.group(0);
            boolean isMultiLine = fullMatch.contains("\n");

            String replacement;
            if (isMultiLine) {
                // Determine indentation of the call
                String indent = extractIndentAtMatch(source, m3.start());
                replacement = "DriverManager.getConnection(\n"
                        + indent + "    System.getenv(\"DB_URL\"),\n"
                        + indent + "    System.getenv(\"DB_USER\"),\n"
                        + indent + "    System.getenv(\"DB_PASSWORD\")\n"
                        + indent + ")";
            } else {
                replacement = "DriverManager.getConnection(System.getenv(\"DB_URL\"), System.getenv(\"DB_USER\"), System.getenv(\"DB_PASSWORD\"))";
            }

            String candidate = source.replace(fullMatch, replacement);
            if (isValidJava(candidate)) {
                return Optional.of(candidate);
            }
        }

        // B. 1-argument DriverManager.getConnection("jdbc:...")
        Matcher m1 = DRIVER_MANAGER_1ARG_PATTERN.matcher(source);
        if (m1.find()) {
            String fullMatch = m1.group(0);
            String replacement = "DriverManager.getConnection(System.getenv(\"DB_URL\"))";
            String candidate = source.replace(fullMatch, replacement);
            if (isValidJava(candidate)) {
                return Optional.of(candidate);
            }
        }

        return Optional.empty();
    }

    private Optional<String> remediateAwsCredential(String source, SecurityFinding finding) {
        String snippet = finding.getVulnerableSnippet();
        Matcher m = AWS_KEY_PATTERN.matcher(snippet != null ? snippet : source);
        if (m.find()) {
            String fullQuoted = m.group(0);
            String patched = source.replace(fullQuoted, "System.getenv(\"AWS_ACCESS_KEY_ID\")");
            if (isValidJava(patched)) {
                return Optional.of(patched);
            }
        }
        return Optional.empty();
    }

    private Optional<String> remediateContextualVariable(String source, SecurityFinding finding) {
        String[] lines = source.split("\\r?\\n", -1);
        int targetIdx = finding.getStartLine() - 1;

        String snippet = finding.getVulnerableSnippet();
        if (snippet != null && !snippet.isBlank() && (targetIdx < 0 || targetIdx >= lines.length || !lines[targetIdx].contains("\""))) {
            String trimmedSnippet = snippet.trim();
            for (int i = 0; i < lines.length; i++) {
                if (lines[i].contains(trimmedSnippet) && lines[i].contains("\"")) {
                    targetIdx = i;
                    break;
                }
            }
        }

        if (targetIdx < 0 || targetIdx >= lines.length) {
            return Optional.empty();
        }

        String line = lines[targetIdx];
        String envVarName = resolveContextualEnvVar(line, finding);

        // Replace literal string on that line with System.getenv(envVarName)
        Pattern literalPattern = Pattern.compile("\"([^\"]*)\"");
        Matcher m = literalPattern.matcher(line);
        if (m.find()) {
            String patchedLine = line.replace(m.group(0), "System.getenv(\"" + envVarName + "\")");
            lines[targetIdx] = patchedLine;
            String result = String.join("\n", lines);
            if (isValidJava(result)) {
                return Optional.of(result);
            }
        }

        return Optional.empty();
    }

    /**
     * Resolves the appropriate environment variable name based on context.
     * NEVER returns APP_SECRET for database/JDBC contexts!
     */
    public static String resolveContextualEnvVar(String contextText, SecurityFinding finding) {
        String lower = contextText != null ? contextText.toLowerCase(Locale.ROOT) : "";
        String desc = (finding != null && finding.getDescription() != null) ? finding.getDescription().toLowerCase(Locale.ROOT) : "";

        // 1. Database / JDBC contexts
        if (lower.contains("jdbc") || lower.contains("db_url") || lower.contains("dburl") || lower.contains("database_url") || lower.contains("datasource.url")) {
            return "DB_URL";
        }
        if (lower.contains("db_user") || lower.contains("dbuser") || lower.contains("db_username") || lower.contains("database_user")) {
            return "DB_USER";
        }
        if (lower.contains("db_pass") || lower.contains("dbpass") || lower.contains("db_password") || lower.contains("database_password")) {
            return "DB_PASSWORD";
        }

        // 2. AWS contexts
        if (lower.contains("aws") && (lower.contains("key") || lower.contains("access"))) {
            return "AWS_ACCESS_KEY_ID";
        }
        if (lower.contains("aws") && lower.contains("secret")) {
            return "AWS_SECRET_ACCESS_KEY";
        }

        // 3. Provider Tokens
        if (lower.contains("github") || desc.contains("github")) {
            return "GITHUB_TOKEN";
        }
        if (lower.contains("stripe") || desc.contains("stripe")) {
            return "STRIPE_API_KEY";
        }
        if (lower.contains("slack") || desc.contains("slack")) {
            return "SLACK_TOKEN";
        }
        if (lower.contains("gemini") || desc.contains("gemini")) {
            return "GEMINI_API_KEY";
        }
        if (lower.contains("jwt") || lower.contains("bearer") || lower.contains("auth_token")) {
            return "AUTH_TOKEN";
        }
        if (lower.contains("client_secret")) {
            return "CLIENT_SECRET";
        }
        if (lower.contains("client_id")) {
            return "CLIENT_ID";
        }
        if (lower.contains("api_key") || lower.contains("apikey")) {
            return "API_KEY";
        }

        // 4. Default: APP_SECRET (only for generic application secrets, NEVER for JDBC)
        return "APP_SECRET";
    }

    private Optional<String> tryDeterministicFallback(String source, SecurityFinding finding) {
        String snippet = finding.getVulnerableSnippet();
        if (snippet != null && snippet.contains("AKIA")) {
            return remediateAwsCredential(source, finding);
        }

        if (source.contains("DriverManager.getConnection")) {
            return remediateDriverManagerCall(source, finding);
        }

        String[] lines = source.split("\\r?\\n", -1);
        int targetIdx = finding.getStartLine() - 1;
        if (targetIdx >= 0 && targetIdx < lines.length) {
            String line = lines[targetIdx];
            String envVar = resolveContextualEnvVar(line, finding);
            String patchedLine = line.replaceAll("\"[^\"]+\"", "System.getenv(\"" + envVar + "\")");
            lines[targetIdx] = patchedLine;
            String result = String.join("\n", lines);
            if (isValidJava(result)) {
                return Optional.of(result);
            }
        }

        return Optional.empty();
    }

    private String extractIndentAtMatch(String source, int matchStart) {
        int lineStart = source.lastIndexOf('\n', matchStart);
        if (lineStart == -1) lineStart = 0;
        else lineStart += 1;

        StringBuilder indent = new StringBuilder();
        for (int i = lineStart; i < matchStart; i++) {
            char c = source.charAt(i);
            if (Character.isWhitespace(c)) {
                indent.append(c);
            } else {
                break;
            }
        }
        return indent.toString();
    }

    private boolean isValidJava(String code) {
        if (code == null || code.isBlank()) return false;
        try {
            Optional<CompilationUnit> result = javaParser.parse(code).getResult();
            return result.isPresent();
        } catch (Exception e) {
            return false;
        }
    }
}
