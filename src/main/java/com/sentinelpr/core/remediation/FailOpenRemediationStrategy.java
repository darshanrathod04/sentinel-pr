package com.sentinelpr.core.remediation;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ast.CompilationUnit;
import com.sentinelpr.core.model.InspectedSource;
import com.sentinelpr.core.model.SecurityFinding;
import com.sentinelpr.core.model.SecurityRule;

import java.util.Optional;

/**
 * Remediation strategy for SEC-001-FAIL-OPEN.
 */
public class FailOpenRemediationStrategy implements RemediationStrategy {

    private final JavaParser javaParser;

    public FailOpenRemediationStrategy() {
        ParserConfiguration config = new ParserConfiguration();
        config.setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_21);
        this.javaParser = new JavaParser(config);
    }

    @Override
    public SecurityRule getSupportedRule() {
        return SecurityRule.FAIL_OPEN_SECURITY;
    }

    @Override
    public RemediationResult remediate(String source, SecurityFinding finding, InspectedSource inspectedSource, RemediationContext context) {
        String snippet = finding.getVulnerableSnippet();
        if (snippet != null && !snippet.isBlank()) {
            if (source.contains(snippet)) {
                String safeCatch = snippet.replaceAll("return\\s+true\\s*;", "return false; // SentinelPR: fail-closed security fix");
                String result = source.replace(snippet, safeCatch);
                if (isValidJava(result)) {
                    return RemediationResult.success(result, "FailOpenRemediationStrategy", "Replaced fail-open return true with fail-closed return false", finding.getStartLine(), finding.getEndLine());
                }
            }

            String normSnippet = snippet.replace("\r\n", "\n");
            String normSource = source.replace("\r\n", "\n");
            if (normSource.contains(normSnippet)) {
                String safeCatch = normSnippet.replaceAll("return\\s+true\\s*;", "return false; // SentinelPR: fail-closed security fix");
                String result = normSource.replace(normSnippet, safeCatch);
                if (isValidJava(result)) {
                    return RemediationResult.success(result, "FailOpenRemediationStrategy", "Replaced fail-open return true with fail-closed return false", finding.getStartLine(), finding.getEndLine());
                }
            }
        }

        String[] lines = source.split("\\r?\\n", -1);
        int startLine = finding.getStartLine();
        int endLine = finding.getEndLine();

        if (startLine > 0) {
            int scanStart = Math.max(0, startLine - 2);
            int scanEnd = Math.min(lines.length - 1, endLine + 5);
            for (int i = scanStart; i <= scanEnd; i++) {
                if (lines[i].contains("return true;")) {
                    lines[i] = lines[i].replace("return true;", "return false; // SentinelPR: fail-closed security fix");
                    String candidate = String.join("\n", lines);
                    if (isValidJava(candidate)) {
                        return RemediationResult.fallback(candidate, "FailOpenRemediationStrategy", "Applied line-based fallback fail-closed fix", finding.getStartLine(), finding.getEndLine());
                    }
                }
            }
        }

        return RemediationResult.unapplied(source, "FailOpenRemediationStrategy", "Failed to apply fail-closed fix");
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
