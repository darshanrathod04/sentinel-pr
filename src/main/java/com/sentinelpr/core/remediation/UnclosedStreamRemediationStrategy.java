package com.sentinelpr.core.remediation;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ast.CompilationUnit;
import com.sentinelpr.core.model.InspectedSource;
import com.sentinelpr.core.model.SecurityFinding;
import com.sentinelpr.core.model.SecurityRule;

import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Remediation strategy for SEC-002-UNCLOSED-STREAM.
 */
public class UnclosedStreamRemediationStrategy implements RemediationStrategy {

    private final JavaParser javaParser;

    public UnclosedStreamRemediationStrategy() {
        ParserConfiguration config = new ParserConfiguration();
        config.setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_21);
        this.javaParser = new JavaParser(config);
    }

    @Override
    public SecurityRule getSupportedRule() {
        return SecurityRule.UNCLOSED_IO_STREAM;
    }

    @Override
    public RemediationResult remediate(String source, SecurityFinding finding, InspectedSource inspectedSource, RemediationContext context) {
        String[] lines = source.split("\\r?\\n", -1);
        String snippet = finding.getVulnerableSnippet();
        int streamLineIdx = -1;
        Pattern streamPattern = Pattern.compile(
                ".*\\b(FileInputStream|FileOutputStream|InputStream|OutputStream|BufferedReader|FileReader|FileWriter)\\s+(\\w+)\\s*=\\s*new\\s+.*"
        );

        // 1. Search for a line matching both stream pattern AND finding snippet/argument
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

        // 2. Search within finding.getMethodName()
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
            if (snippet != null && source.contains(snippet)) {
                String candidate = source.replace(snippet, "try (" + snippet + ") {\n            // Managed stream\n        }");
                if (isValidJava(candidate)) {
                    return RemediationResult.fallback(candidate, "UnclosedStreamRemediationStrategy", "Enclosed stream instantiation in try-with-resources snippet", finding.getStartLine(), finding.getEndLine());
                }
            }
            return RemediationResult.unapplied(source, "UnclosedStreamRemediationStrategy", "Stream instantiation line not located");
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
            return RemediationResult.success(result, "UnclosedStreamRemediationStrategy", "Converted unclosed stream into try-with-resources block", streamLineIdx + 1, closeIdx + 1);
        }

        return RemediationResult.unapplied(source, "UnclosedStreamRemediationStrategy", "Synthesized stream patch failed Java syntax validation");
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
