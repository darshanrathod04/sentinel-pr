package com.sentinelpr.core.analysis;

import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.FieldDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.AnnotationExpr;
import com.github.javaparser.ast.expr.ArrayInitializerExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.NormalAnnotationExpr;
import com.github.javaparser.ast.expr.SingleMemberAnnotationExpr;
import com.github.javaparser.ast.expr.StringLiteralExpr;
import com.sentinelpr.core.model.InspectedSource;
import com.sentinelpr.core.model.SecurityFinding;
import com.sentinelpr.core.model.SecurityRule;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * <b>SuppressionManager</b>
 *
 * <p>Evaluates false-positive suppressions across:</p>
 * <ol>
 *   <li>Java Annotations: {@code @SuppressWarnings("sentinel:<RULE_ID>")} or {@code @SuppressWarnings("sentinel:all")}</li>
 *   <li>Inline Comments: {@code // sentinel-ignore <RULE_ID> [optional reason]} on preceding or current line</li>
 *   <li>Repository File: {@code .sentinelignore} configuration file</li>
 * </ol>
 */
public class SuppressionManager {

    private static final Pattern INLINE_COMMENT_PATTERN = Pattern.compile(
            "(?i)//\\s*sentinel-ignore\\s+([A-Za-z0-9\\-_:]+)(?:\\s+(.*))?"
    );

    private static final Pattern BLOCK_COMMENT_PATTERN = Pattern.compile(
            "(?i)/\\*+\\s*sentinel-ignore\\s+([A-Za-z0-9\\-_:]+)(?:\\s+([\\s\\S]*?))?\\*+/"
    );

    /**
     * Evaluates whether a finding should be suppressed.
     *
     * @param finding security finding to evaluate
     * @param source  inspected source containing the finding
     * @param rootDir root search path for .sentinelignore (may be null)
     * @return SuppressionResult
     */
    public SuppressionResult evaluateSuppression(SecurityFinding finding, InspectedSource source, Path rootDir) {
        if (finding == null || source == null) {
            return SuppressionResult.notSuppressed();
        }

        // 1. Check Java Annotations
        SuppressionResult annotationResult = checkAnnotations(finding, source);
        if (annotationResult.isSuppressed()) {
            return annotationResult;
        }

        // 2. Check Inline Comments
        SuppressionResult commentResult = checkInlineComments(finding, source);
        if (commentResult.isSuppressed()) {
            return commentResult;
        }

        // 3. Check .sentinelignore file
        SuppressionResult ignoreFileResult = checkSentinelIgnore(finding, source, rootDir);
        if (ignoreFileResult.isSuppressed()) {
            return ignoreFileResult;
        }

        return SuppressionResult.notSuppressed();
    }

    // ─── Annotation Inspection ───────────────────────────────────────────────

    private SuppressionResult checkAnnotations(SecurityFinding finding, InspectedSource source) {
        SecurityRule rule = finding.getRule();

        // Check method enclosing the finding
        if (finding.getMethodName() != null && !finding.getMethodName().isBlank()) {
            for (MethodDeclaration method : source.getMethods()) {
                if (method.getNameAsString().equals(finding.getMethodName())) {
                    SuppressionResult res = inspectNodeAnnotations(method, rule, "method '" + finding.getMethodName() + "'");
                    if (res.isSuppressed()) return res;
                }
            }
        }

        // Check enclosing class
        for (ClassOrInterfaceDeclaration classDecl : source.getClassDeclarations()) {
            if (classDecl.getNameAsString().equals(source.getPrimaryClassName())
                    || classDecl.getNameAsString().equals(finding.getClassName())) {
                SuppressionResult res = inspectNodeAnnotations(classDecl, rule, "class '" + classDecl.getNameAsString() + "'");
                if (res.isSuppressed()) return res;
            }
        }

        // Check field declarations (for volatile compound ops)
        for (FieldDeclaration field : source.getFields()) {
            int fieldLine = field.getBegin().map(p -> p.line).orElse(-1);
            if (fieldLine == finding.getStartLine() || field.toString().contains(finding.getVulnerableSnippet())) {
                SuppressionResult res = inspectNodeAnnotations(field, rule, "field");
                if (res.isSuppressed()) return res;
            }
        }

        return SuppressionResult.notSuppressed();
    }

    private SuppressionResult inspectNodeAnnotations(Node node, SecurityRule rule, String context) {
        List<AnnotationExpr> annotations = (node instanceof com.github.javaparser.ast.nodeTypes.NodeWithAnnotations<?> withAnnotations)
                ? withAnnotations.getAnnotations()
                : List.of();
        for (AnnotationExpr annotation : annotations) {
            String name = annotation.getNameAsString();
            if ("SuppressWarnings".equals(name) || "java.lang.SuppressWarnings".equals(name)) {
                List<String> values = extractAnnotationValues(annotation);
                for (String val : values) {
                    if (matchesRuleSuppression(val, rule)) {
                        return SuppressionResult.suppressed(
                                String.format("@SuppressWarnings(\"%s\") on %s", val, context),
                                "ANNOTATION"
                        );
                    }
                }
            }
        }
        return SuppressionResult.notSuppressed();
    }

    private List<String> extractAnnotationValues(AnnotationExpr annotation) {
        List<String> values = new ArrayList<>();
        if (annotation instanceof SingleMemberAnnotationExpr single) {
            extractStringValues(single.getMemberValue(), values);
        } else if (annotation instanceof NormalAnnotationExpr normal) {
            normal.getPairs().forEach(pair -> {
                if ("value".equals(pair.getNameAsString())) {
                    extractStringValues(pair.getValue(), values);
                }
            });
        }
        return values;
    }

    private void extractStringValues(Expression expr, List<String> values) {
        if (expr instanceof StringLiteralExpr str) {
            values.add(str.getValue());
        } else if (expr instanceof ArrayInitializerExpr array) {
            array.getValues().forEach(v -> extractStringValues(v, values));
        }
    }

    // ─── Inline Comment Inspection ───────────────────────────────────────────

    private SuppressionResult checkInlineComments(SecurityFinding finding, InspectedSource source) {
        String rawSource = source.getRawSource();
        if (rawSource == null || rawSource.isBlank()) {
            return SuppressionResult.notSuppressed();
        }

        String[] lines = rawSource.split("\\r?\\n", -1);
        int startLine = finding.getStartLine(); // 1-indexed

        // Lines to inspect: preceding line (startLine - 2) and current line (startLine - 1)
        int minLine = Math.max(0, startLine - 2);
        int maxLine = Math.min(lines.length - 1, startLine);

        for (int i = minLine; i <= maxLine; i++) {
            String line = lines[i];

            // 1. Line comment check
            Matcher lineMatcher = INLINE_COMMENT_PATTERN.matcher(line);
            if (lineMatcher.find()) {
                String token = lineMatcher.group(1).trim();
                String reason = lineMatcher.group(2) != null ? lineMatcher.group(2).trim() : "Unspecified";
                if (matchesRuleSuppression(token, finding.getRule())) {
                    return SuppressionResult.suppressed(
                            String.format("Inline comment '// sentinel-ignore %s %s' at line %d", token, reason, i + 1),
                            "INLINE_COMMENT"
                    );
                }
            }

            // 2. Block comment check
            Matcher blockMatcher = BLOCK_COMMENT_PATTERN.matcher(line);
            if (blockMatcher.find()) {
                String token = blockMatcher.group(1).trim();
                String reason = blockMatcher.group(2) != null ? blockMatcher.group(2).trim() : "Unspecified";
                if (matchesRuleSuppression(token, finding.getRule())) {
                    return SuppressionResult.suppressed(
                            String.format("Inline block comment '/* sentinel-ignore %s %s */' at line %d", token, reason, i + 1),
                            "INLINE_COMMENT"
                    );
                }
            }
        }

        return SuppressionResult.notSuppressed();
    }

    // ─── .sentinelignore File Inspection ────────────────────────────────────

    private SuppressionResult checkSentinelIgnore(SecurityFinding finding, InspectedSource source, Path rootDir) {
        Path ignoreFile = findSentinelIgnoreFile(source.getFilePath(), rootDir);
        if (ignoreFile == null || !Files.exists(ignoreFile)) {
            return SuppressionResult.notSuppressed();
        }

        try {
            List<String> lines = Files.readAllLines(ignoreFile);
            String targetFileName = source.getFilePath() != null
                    ? source.getFilePath().getFileName().toString()
                    : "";
            String targetFullPath = source.getFilePath() != null
                    ? source.getFilePath().toString().replace("\\", "/")
                    : "";

            for (String rawLine : lines) {
                String line = rawLine.trim();
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }

                // Format 1: SEC-001 [reason]
                // Format 2: path/to/File.java:SEC-001 [reason]
                // Format 3: path/to/File.java
                if (line.contains(":")) {
                    String[] parts = line.split(":", 2);
                    String filePattern = parts[0].trim();
                    String ruleAndReason = parts[1].trim();

                    if (targetFullPath.endsWith(filePattern) || targetFileName.equals(filePattern)) {
                        String ruleToken = ruleAndReason.split("\\s+", 2)[0];
                        if (matchesRuleSuppression(ruleToken, finding.getRule())) {
                            return SuppressionResult.suppressed(
                                    String.format(".sentinelignore matched '%s'", line),
                                    "IGNORE_FILE"
                            );
                        }
                    }
                } else {
                    String[] tokens = line.split("\\s+", 2);
                    String ruleToken = tokens[0].trim();

                    // Check if entire file is ignored
                    if (targetFullPath.endsWith(ruleToken) || targetFileName.equals(ruleToken)) {
                        return SuppressionResult.suppressed(
                                String.format(".sentinelignore file exclusion for '%s'", ruleToken),
                                "IGNORE_FILE"
                        );
                    }

                    if (matchesRuleSuppression(ruleToken, finding.getRule())) {
                        return SuppressionResult.suppressed(
                                String.format(".sentinelignore rule '%s'", line),
                                "IGNORE_FILE"
                        );
                    }
                }
            }
        } catch (IOException e) {
            // Ignore file read warning
        }

        return SuppressionResult.notSuppressed();
    }

    private Path findSentinelIgnoreFile(Path filePath, Path rootDir) {
        if (rootDir != null) {
            Path candidate = rootDir.resolve(".sentinelignore");
            if (Files.exists(candidate)) return candidate;
        }

        if (filePath != null) {
            Path dir = Files.isDirectory(filePath) ? filePath : filePath.getParent();
            while (dir != null) {
                Path candidate = dir.resolve(".sentinelignore");
                if (Files.exists(candidate)) return candidate;
                dir = dir.getParent();
            }
        }

        Path defaultRoot = Path.of(".sentinelignore");
        if (Files.exists(defaultRoot)) return defaultRoot;

        return null;
    }

    // ─── Rule Token Matching ────────────────────────────────────────────────

    private boolean matchesRuleSuppression(String rawToken, SecurityRule rule) {
        if (rawToken == null) return false;
        String token = rawToken.trim().toLowerCase(Locale.ROOT);

        // Normalize "sentinel:SEC-001" -> "sec-001"
        if (token.startsWith("sentinel:")) {
            token = token.substring("sentinel:".length()).trim();
        }

        if ("all".equals(token) || "*".equals(token)) {
            return true;
        }

        String fullRuleId = rule.getRuleId().toLowerCase(Locale.ROOT); // e.g. sec-001-fail-open
        String ruleEnum = rule.name().toLowerCase(Locale.ROOT);        // e.g. fail_open_security

        // Match full rule ID: sec-001-fail-open
        if (token.equals(fullRuleId) || token.equals(ruleEnum)) {
            return true;
        }

        // Match prefix token: sec-001, sec-002, sec-003, sec-004
        String[] parts = fullRuleId.split("-");
        if (parts.length >= 2) {
            String shortId = parts[0] + "-" + parts[1]; // sec-001
            if (token.equals(shortId)) {
                return true;
            }
        }

        return false;
    }
}
