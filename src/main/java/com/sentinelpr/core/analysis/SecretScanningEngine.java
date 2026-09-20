package com.sentinelpr.core.analysis;

import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.FieldDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.AnnotationExpr;
import com.github.javaparser.ast.expr.AssignExpr;
import com.github.javaparser.ast.expr.NameExpr;
import com.github.javaparser.ast.expr.StringLiteralExpr;
import com.sentinelpr.core.model.InspectedSource;
import com.sentinelpr.core.model.SecurityFinding;
import com.sentinelpr.core.model.SecurityRule;
import com.sentinelpr.core.model.Severity;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * <b>SecretScanningEngine</b>
 *
 * <p>Scans Java source files for embedded secrets, AWS credentials, private keys, high-entropy tokens,
 * and hardcoded passwords with Shannon entropy scoring and regex pattern matchers.</p>
 */
public class SecretScanningEngine {

    // Shannon entropy threshold for high-entropy tokens (>= 16 chars)
    public static final double ENTROPY_THRESHOLD = 3.2;

    // Pattern Matchers
    private static final Pattern AWS_KEY_PATTERN = Pattern.compile("\\b(AKIA[0-9A-Z]{16})\\b");
    private static final Pattern PRIVATE_KEY_PATTERN = Pattern.compile("-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----");
    private static final Pattern GENERIC_API_KEY_PATTERN = Pattern.compile(
            "(?i)\\b(?:bearer\\s+[a-zA-Z0-9_\\-\\.]{20,}|(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\\s*[:=]\\s*[\"']([a-zA-Z0-9_\\-]{16,})[\"'])"
    );
    private static final Pattern PASSWORD_VAR_PATTERN = Pattern.compile(
            "(?i).*(password|passwd|pwd|db_pass|secret_key|api_key|client_secret).*"
    );

    // Common non-secret annotations
    private static final Set<String> WHITELISTED_ANNOTATIONS = Set.of(
            "SuppressWarnings", "RequestMapping", "GetMapping", "PostMapping", "PutMapping",
            "DeleteMapping", "Qualifier", "Table", "Column", "Value", "ConditionalOnProperty"
    );

    // Whitelist for common dummy/placeholder passwords in test/sample code
    private static final Set<String> PLACEHOLDER_WHITELIST = Set.of(
            "password", "password123", "admin", "test", "dummy", "changeme", "123456",
            "secret", "example", "placeholder", "todo", "fixme", "none", "default",
            "localhost", "root", "guest", "user", "sample", "unknown"
    );

    /**
     * Scans an inspected source file for hardcoded secrets and high-entropy credentials.
     */
    public List<SecurityFinding> scan(InspectedSource source) {
        List<SecurityFinding> findings = new ArrayList<>();
        if (source == null || source.getCompilationUnit() == null) {
            return findings;
        }

        String pathStr = source.getFilePath() != null ? source.getFilePath().toString() : "UnknownSource.java";
        Set<Integer> reportedLines = new HashSet<>();

        // 1. High-confidence regex match: AWS Access Key IDs across entire source or string literals
        for (StringLiteralExpr literal : source.getStringLiterals()) {
            String value = literal.getValue();
            if (value == null || value.isBlank()) {
                continue;
            }

            // Skip if inside whitelisted annotations
            if (isInsideWhitelistedAnnotation(literal)) {
                continue;
            }

            int line = literal.getBegin().map(p -> p.line).orElse(0);

            // A. AWS Key Match
            Matcher awsMatcher = AWS_KEY_PATTERN.matcher(value);
            if (awsMatcher.find()) {
                String matchedKey = awsMatcher.group(1);
                addSecretFinding(findings, source, literal, "AWS Access Key ID", matchedKey, line, pathStr);
                reportedLines.add(line);
                continue;
            }

            // B. Private Key Match
            Matcher privKeyMatcher = PRIVATE_KEY_PATTERN.matcher(value);
            if (privKeyMatcher.find()) {
                addSecretFinding(findings, source, literal, "Embedded Private Key", value, line, pathStr);
                reportedLines.add(line);
                continue;
            }

            // C. Generic API Key / Bearer token Match
            Matcher apiKeyMatcher = GENERIC_API_KEY_PATTERN.matcher(value);
            if (apiKeyMatcher.find()) {
                String token = apiKeyMatcher.groupCount() >= 1 && apiKeyMatcher.group(1) != null
                        ? apiKeyMatcher.group(1)
                        : value;
                if (!isWhitelistedPlaceholder(token)) {
                    addSecretFinding(findings, source, literal, "API Key / Token", token, line, pathStr);
                    reportedLines.add(line);
                    continue;
                }
            }

            // D. Shannon Entropy check for high-entropy string tokens
            if (value.length() >= 16 && !isWhitelistedPlaceholder(value) && !value.contains(" ") && !value.startsWith("http")) {
                double entropy = calculateShannonEntropy(value);
                if (entropy >= ENTROPY_THRESHOLD && hasVariedCharset(value)) {
                    addSecretFinding(findings, source, literal, "High-Entropy Secret (entropy: " + String.format(Locale.ROOT, "%.2f", entropy) + ")", value, line, pathStr);
                    reportedLines.add(line);
                }
            }
        }

        // 2. Variable declarations with sensitive names: String db_pass = "xyz";
        for (VariableDeclarator varDecl : source.getVariableDeclarations()) {
            String varName = varDecl.getNameAsString();
            int line = varDecl.getBegin().map(p -> p.line).orElse(0);
            if (reportedLines.contains(line)) {
                continue;
            }

            if (PASSWORD_VAR_PATTERN.matcher(varName).matches() && varDecl.getInitializer().isPresent()) {
                varDecl.getInitializer().ifPresent(init -> {
                    if (init instanceof StringLiteralExpr literal) {
                        String secretVal = literal.getValue();
                        if (!isWhitelistedPlaceholder(secretVal)) {
                            addSecretFinding(findings, source, varDecl, "Hardcoded Credential in variable '" + varName + "'", secretVal, line, pathStr);
                            reportedLines.add(line);
                        }
                    }
                });
            }
        }

        // 3. Assignment expressions: password = "xyz";
        for (AssignExpr assign : source.getAssignExpressions()) {
            int line = assign.getBegin().map(p -> p.line).orElse(0);
            if (reportedLines.contains(line)) {
                continue;
            }

            if (assign.getTarget() instanceof NameExpr nameExpr) {
                String varName = nameExpr.getNameAsString();
                if (PASSWORD_VAR_PATTERN.matcher(varName).matches() && assign.getValue() instanceof StringLiteralExpr literal) {
                    String secretVal = literal.getValue();
                    if (!isWhitelistedPlaceholder(secretVal)) {
                        addSecretFinding(findings, source, assign, "Hardcoded Credential in assignment to '" + varName + "'", secretVal, line, pathStr);
                        reportedLines.add(line);
                    }
                }
            }
        }

        return findings;
    }

    /**
     * Calculates Shannon entropy for a string: H(s) = - \sum p_i * log2(p_i)
     */
    public static double calculateShannonEntropy(String s) {
        if (s == null || s.isEmpty()) {
            return 0.0;
        }

        Map<Character, Integer> counts = new HashMap<>();
        for (char c : s.toCharArray()) {
            counts.put(c, counts.getOrDefault(c, 0) + 1);
        }

        double entropy = 0.0;
        int len = s.length();
        for (int count : counts.values()) {
            double p = (double) count / len;
            entropy -= p * (Math.log(p) / Math.log(2));
        }

        return entropy;
    }

    /**
     * Redacts a secret, exposing only the first 4 and last 4 characters.
     */
    public static String redactSecret(String secret) {
        if (secret == null || secret.length() <= 8) {
            return "******";
        }
        return secret.substring(0, 4) + "..." + secret.substring(secret.length() - 4);
    }

    private boolean isWhitelistedPlaceholder(String val) {
        if (val == null || val.isBlank()) {
            return true;
        }
        String lower = val.trim().toLowerCase(Locale.ROOT);
        if (PLACEHOLDER_WHITELIST.contains(lower)) {
            return true;
        }
        // Repetitive patterns (e.g. aaaaaaa or 111111)
        if (lower.chars().distinct().count() <= 2) {
            return true;
        }
        return false;
    }

    private boolean hasVariedCharset(String s) {
        boolean hasUpper = false;
        boolean hasLower = false;
        boolean hasDigit = false;
        for (char c : s.toCharArray()) {
            if (Character.isUpperCase(c)) hasUpper = true;
            if (Character.isLowerCase(c)) hasLower = true;
            if (Character.isDigit(c)) hasDigit = true;
        }
        // At least two character classes
        int classes = (hasUpper ? 1 : 0) + (hasLower ? 1 : 0) + (hasDigit ? 1 : 0);
        return classes >= 2;
    }

    private boolean isInsideWhitelistedAnnotation(Node node) {
        Node current = node.getParentNode().orElse(null);
        while (current != null) {
            if (current instanceof AnnotationExpr ann) {
                String annName = ann.getNameAsString();
                for (String whitelisted : WHITELISTED_ANNOTATIONS) {
                    if (annName.contains(whitelisted)) {
                        return true;
                    }
                }
            }
            current = current.getParentNode().orElse(null);
        }
        return false;
    }

    private void addSecretFinding(
            List<SecurityFinding> findings,
            InspectedSource source,
            Node node,
            String secretType,
            String secretValue,
            int line,
            String pathStr
    ) {
        int endLine = node.getEnd().map(p -> p.line).orElse(line);
        MethodDeclaration method = node.findAncestor(MethodDeclaration.class).orElse(null);
        String methodName = method != null ? method.getNameAsString() : "classScope";

        String redacted = redactSecret(secretValue);
        String rationale = String.format(
                "Potential hardcoded %s detected (%s). Storing secrets or API keys in source code risks unauthorized credential access, repository leakage, and lateral movement.",
                secretType, redacted
        );

        String remediation = "Externalize secret using environment variables: System.getenv(\"...\") or inject via Spring @Value(\"${secret.name}\") backed by a secure secret manager.";

        findings.add(new SecurityFinding(
                "FND-" + UUID.randomUUID().toString().substring(0, 8),
                SecurityRule.HARDCODED_SECRET,
                Severity.HIGH,
                pathStr,
                source.getPrimaryClassName(),
                methodName,
                line,
                endLine,
                node.toString(),
                "Hardcoded secret detected: " + secretType,
                rationale,
                remediation,
                0.96
        ));
    }
}
