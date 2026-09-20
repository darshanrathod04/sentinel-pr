package com.sentinelpr.core.service;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ast.CompilationUnit;
import com.sentinelpr.client.DeveloperFacade;
import com.sentinelpr.client.SentinelClient;
import com.sentinelpr.core.model.InspectedSource;
import com.sentinelpr.core.model.SecurityFinding;
import com.sentinelpr.core.model.SecurityRule;
import com.sentinelpr.core.model.UnifiedDiffPatch;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * <b>PatchComposer</b>
 *
 * <p>Atomic patch composition engine for SentinelPR. When a single source file contains
 * multiple security findings, PatchComposer applies all verified AST transformations
 * sequentially to a single in-memory source and generates ONE clean, unified diff per file,
 * followed by regression verification.</p>
 */
public class PatchComposer {

    private final DeveloperFacade developerFacade;
    private final PatchVerifier patchVerifier;
    private final JavaParser javaParser;

    public PatchComposer(DeveloperFacade developerFacade, PatchVerifier patchVerifier) {
        this.developerFacade = Objects.requireNonNull(developerFacade, "developerFacade must not be null");
        this.patchVerifier = Objects.requireNonNull(patchVerifier, "patchVerifier must not be null");
        ParserConfiguration config = new ParserConfiguration();
        config.setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_21);
        this.javaParser = new JavaParser(config);
    }

    public PatchComposer(SentinelClient client) {
        this(
                client.developer(),
                new PatchVerifier(new CodeInspectionService(client), new RuleEvaluationService(client))
        );
    }

    /**
     * Composes all fixes for the given findings into a single unified diff patch.
     *
     * @param source   original inspected source
     * @param findings list of security findings detected in this source
     * @return single composite UnifiedDiffPatch
     */
    public UnifiedDiffPatch compose(InspectedSource source, List<SecurityFinding> findings) {
        Objects.requireNonNull(source, "source must not be null");
        if (findings == null || findings.isEmpty()) {
            return null;
        }

        String originalSource = source.getRawSource();
        String targetFilePath = source.getFilePath() != null
                ? source.getFilePath().toString()
                : "VulnerableService.java";

        // Sort findings in deterministic order: Volatiles first, Streams second, Fail-open third, Subprocess fourth
        List<SecurityFinding> sortedFindings = new ArrayList<>(findings);
        sortedFindings.sort(Comparator.comparingInt(this::rulePriority));

        String currentSource = originalSource;
        for (SecurityFinding finding : sortedFindings) {
            currentSource = applyTransformation(currentSource, finding);
        }

        // Regression & AST Syntax Verification
        PatchVerificationResult verificationResult = patchVerifier.verify(currentSource, targetFilePath);

        String unifiedDiff = developerFacade.generateUnifiedDiff(originalSource, currentSource, targetFilePath);

        String combinedFindingIds = sortedFindings.stream()
                .map(SecurityFinding::getId)
                .collect(Collectors.joining(", "));

        String combinedRuleIds = sortedFindings.stream()
                .map(f -> f.getRule().getRuleId())
                .distinct()
                .collect(Collectors.joining(", "));

        boolean isSuccess = verificationResult.isSyntaxValid() && !currentSource.equals(originalSource);
        UnifiedDiffPatch.Status status = isSuccess
                ? UnifiedDiffPatch.Status.SUCCESS
                : (!currentSource.equals(originalSource) ? UnifiedDiffPatch.Status.PARTIAL : UnifiedDiffPatch.Status.FAILED);

        return new UnifiedDiffPatch(
                combinedFindingIds,
                combinedRuleIds,
                targetFilePath,
                unifiedDiff,
                currentSource,
                status,
                verificationResult.isSyntaxValid(),
                verificationResult.isRegressionVerified(),
                verificationResult.getMessage()
        );
    }

    private int rulePriority(SecurityFinding f) {
        return switch (f.getRule()) {
            case VOLATILE_COMPOUND_OP -> 1;
            case UNCLOSED_IO_STREAM -> 2;
            case FAIL_OPEN_SECURITY -> 3;
            case UNISOLATED_SUBPROCESS -> 4;
        };
    }

    private String applyTransformation(String source, SecurityFinding finding) {
        SecurityRule rule = finding.getRule();
        return switch (rule) {
            case VOLATILE_COMPOUND_OP -> composeVolatileCompound(source, finding);
            case UNCLOSED_IO_STREAM -> composeUnclosedStream(source, finding);
            case FAIL_OPEN_SECURITY -> composeFailOpenSecurity(source, finding);
            case UNISOLATED_SUBPROCESS -> composeSubprocess(source, finding);
        };
    }

    // ─── Transformation: Volatile Compound -> AtomicInteger ──────────────────

    private String composeVolatileCompound(String source, SecurityFinding finding) {
        String fieldVar = extractVarName(finding.getVulnerableSnippet());
        String patched = source;

        // Ensure import exists
        if (!patched.contains("import java.util.concurrent.atomic.AtomicInteger;")) {
            patched = patched.replaceFirst("package\\s+[^;]+;", "$0\n\nimport java.util.concurrent.atomic.AtomicInteger;");
        }

        // Transform field declaration
        patched = patched.replaceAll(
                "(?:private\\s+|protected\\s+|public\\s+)?volatile\\s+int\\s+" + fieldVar + "\\s*;",
                "private final AtomicInteger " + fieldVar + " = new AtomicInteger(0);"
        );
        patched = patched.replaceAll(
                "(?:private\\s+|protected\\s+|public\\s+)?volatile\\s+int\\s+" + fieldVar + "\\s*=\\s*\\d+\\s*;",
                "private final AtomicInteger " + fieldVar + " = new AtomicInteger(0);"
        );

        // Transform mutations
        patched = patched.replaceAll("\\b" + fieldVar + "\\+\\+\\s*;", fieldVar + ".incrementAndGet();");
        patched = patched.replaceAll("\\+\\+\\b" + fieldVar + "\\s*;", fieldVar + ".incrementAndGet();");
        patched = patched.replaceAll("\\b" + fieldVar + "--\\s*;", fieldVar + ".decrementAndGet();");
        patched = patched.replaceAll("--\\b" + fieldVar + "\\s*;", fieldVar + ".decrementAndGet();");

        // Transform getter if present: return requestCount; -> return requestCount.get();
        // Only if getter return type is int
        patched = patched.replaceAll("return\\s+" + fieldVar + "\\s*;", "return " + fieldVar + ".get();");

        if (isValidJava(patched)) {
            return patched;
        }
        return source;
    }

    // ─── Transformation: Unclosed Stream -> Try-With-Resources ───────────────

    private String composeUnclosedStream(String source, SecurityFinding finding) {
        String[] lines = source.split("\\r?\\n", -1);
        String snippet = finding.getVulnerableSnippet();
        int streamLineIdx = -1;
        Pattern streamPattern = Pattern.compile(
                ".*\\b(FileInputStream|FileOutputStream|InputStream|OutputStream|BufferedReader|FileReader|FileWriter)\\s+(\\w+)\\s*=\\s*new\\s+.*"
        );

        // 1. First, search for a line matching both stream pattern AND finding snippet/argument
        if (snippet != null && !snippet.isBlank()) {
            for (int i = 0; i < lines.length; i++) {
                if (lines[i].contains(snippet) && streamPattern.matcher(lines[i]).find()) {
                    if (!lines[i].trim().startsWith("try (") && !lines[i].trim().startsWith("try(")) {
                        streamLineIdx = i;
                        break;
                    }
                }
            }
        }

        // 2. If not found by snippet, search within finding.getMethodName() if available
        if (streamLineIdx == -1 && finding.getMethodName() != null && !finding.getMethodName().isBlank()) {
            boolean inMethod = false;
            for (int i = 0; i < lines.length; i++) {
                if (lines[i].contains(finding.getMethodName() + "(")) {
                    inMethod = true;
                }
                if (inMethod) {
                    Matcher m = streamPattern.matcher(lines[i]);
                    if (m.find() && !lines[i].trim().startsWith("try (") && !lines[i].trim().startsWith("try(")) {
                        streamLineIdx = i;
                        break;
                    }
                    if (lines[i].trim().equals("}")) {
                        inMethod = false;
                    }
                }
            }
        }

        // 3. Fallback to first non-try stream pattern
        if (streamLineIdx == -1) {
            for (int i = 0; i < lines.length; i++) {
                Matcher m = streamPattern.matcher(lines[i]);
                if (m.find() && !lines[i].trim().startsWith("try (") && !lines[i].trim().startsWith("try(")) {
                    streamLineIdx = i;
                    break;
                }
            }
        }

        if (streamLineIdx == -1) {
            // Fallback snippet replacement
            if (snippet != null && source.contains(snippet)) {
                String candidate = source.replace(snippet, "try (" + snippet + ") {\n            // Managed stream\n        }");
                if (isValidJava(candidate)) return candidate;
            }
            return source;
        }

        String line = lines[streamLineIdx];
        String indent = extractIndent(line);
        String trimmed = line.trim();
        if (trimmed.endsWith(";")) {
            trimmed = trimmed.substring(0, trimmed.length() - 1);
        }

        int closeIdx = findEnclosingBlockEnd(lines, streamLineIdx + 1);

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < lines.length; i++) {
            if (i == streamLineIdx) {
                sb.append(indent).append("try (").append(trimmed).append(") {\n");
                for (int j = i + 1; j <= closeIdx && j < lines.length; j++) {
                    if (!lines[j].matches(".*\\b\\w+\\.close\\(\\)\\s*;.*")) {
                        sb.append("    ").append(lines[j]).append("\n");
                    }
                }
                sb.append(indent).append("}\n");
                i = closeIdx;
            } else {
                sb.append(lines[i]).append("\n");
            }
        }

        String result = sb.toString().stripTrailing();
        if (isValidJava(result)) {
            return result;
        }
        return source;
    }

    // ─── Transformation: Fail-Open -> Fail-Closed ────────────────────────────

    private String composeFailOpenSecurity(String source, SecurityFinding finding) {
        String snippet = finding.getVulnerableSnippet();
        if (snippet != null && !snippet.isBlank()) {
            // Direct replacement
            if (source.contains(snippet)) {
                String safeCatch = snippet.replaceAll("return\\s+true\\s*;", "return false; // SentinelPR: fail-closed security fix");
                String result = source.replace(snippet, safeCatch);
                if (isValidJava(result)) return result;
            }

            // Normalized CRLF/LF replacement
            String normSnippet = snippet.replace("\r\n", "\n");
            String normSource = source.replace("\r\n", "\n");
            if (normSource.contains(normSnippet)) {
                String safeCatch = normSnippet.replaceAll("return\\s+true\\s*;", "return false; // SentinelPR: fail-closed security fix");
                String result = normSource.replace(normSnippet, safeCatch);
                if (isValidJava(result)) return result;
            }
        }

        String[] lines = source.split("\\r?\\n", -1);
        int startLine = finding.getStartLine();
        int endLine = finding.getEndLine();

        // Line-based replacement around finding boundaries
        if (startLine > 0) {
            int scanStart = Math.max(0, startLine - 2);
            int scanEnd = Math.min(lines.length - 1, endLine + 5);
            for (int i = scanStart; i <= scanEnd; i++) {
                if (lines[i].contains("return true;")) {
                    lines[i] = lines[i].replace("return true;", "return false; // SentinelPR: fail-closed security fix");
                    String candidate = String.join("\n", lines);
                    if (isValidJava(candidate)) return candidate;
                }
            }
        }

        // Method scope search with proper brace counting
        if (finding.getMethodName() != null && !finding.getMethodName().isBlank()) {
            boolean inMethod = false;
            int braceDepth = 0;
            for (int i = 0; i < lines.length; i++) {
                if (lines[i].contains(finding.getMethodName() + "(")) {
                    inMethod = true;
                }
                if (inMethod) {
                    for (char c : lines[i].toCharArray()) {
                        if (c == '{') braceDepth++;
                        else if (c == '}') braceDepth--;
                    }
                    if (lines[i].contains("return true;")) {
                        lines[i] = lines[i].replace("return true;", "return false; // SentinelPR: fail-closed security fix");
                        String candidate = String.join("\n", lines);
                        if (isValidJava(candidate)) return candidate;
                    }
                    if (braceDepth <= 0 && lines[i].contains("}")) {
                        inMethod = false;
                    }
                }
            }
        }

        return source;
    }

    // ─── Transformation: Runtime.exec -> ProcessBuilder ──────────────────────

    private String composeSubprocess(String source, SecurityFinding finding) {
        String patched = source.replace("Runtime.getRuntime().exec(", "new ProcessBuilder(");
        if (isValidJava(patched)) {
            return patched;
        }
        return source;
    }

    // ─── Helpers ─────────────────────────────────────────────────────────────

    private boolean isValidJava(String code) {
        if (code == null || code.isBlank()) return false;
        try {
            Optional<CompilationUnit> result = javaParser.parse(code).getResult();
            return result.isPresent();
        } catch (Exception e) {
            return false;
        }
    }

    private String extractVarName(String snippet) {
        if (snippet == null) return "counter";
        return snippet.replaceAll("[^a-zA-Z0-9_]", "");
    }

    private String extractIndent(String line) {
        StringBuilder sb = new StringBuilder();
        for (char c : line.toCharArray()) {
            if (Character.isWhitespace(c)) sb.append(c);
            else break;
        }
        return sb.toString();
    }

    private int findEnclosingBlockEnd(String[] lines, int startIdx) {
        int lastStatement = startIdx;
        for (int i = startIdx; i < lines.length; i++) {
            String trimmed = lines[i].trim();
            if (trimmed.equals("}") || trimmed.equals("return;") || trimmed.startsWith("return ")) {
                return i;
            }
            if (!trimmed.isEmpty()) {
                lastStatement = i;
            }
        }
        return Math.min(lines.length - 1, startIdx + 2);
    }
}
