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
 * Remediation strategy for SEC-006-PATH-TRAVERSAL.
 */
public class PathTraversalRemediationStrategy implements RemediationStrategy {

    private final JavaParser javaParser;

    public PathTraversalRemediationStrategy() {
        ParserConfiguration config = new ParserConfiguration();
        config.setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_21);
        this.javaParser = new JavaParser(config);
    }

    @Override
    public SecurityRule getSupportedRule() {
        return SecurityRule.PATH_TRAVERSAL;
    }

    @Override
    public RemediationResult remediate(String source, SecurityFinding finding, InspectedSource inspectedSource, RemediationContext context) {
        String[] lines = source.split("\\r?\\n", -1);
        int targetIdx = finding.getStartLine() - 1;

        if (targetIdx >= 0 && targetIdx < lines.length) {
            String line = lines[targetIdx];
            String indent = extractIndent(line);

            // Case A: File file = new File(baseDir, filename);
            Pattern pFile = Pattern.compile(".*\\bFile\\s+(\\w+)\\s*=\\s*new\\s+File\\s*\\(\\s*(\\w+)\\s*,\\s*(\\w+)\\s*\\)\\s*;.*");
            Matcher mFile = pFile.matcher(line);
            if (mFile.find()) {
                String fileVar = mFile.group(1);
                String baseVar = mFile.group(2);
                String fileArg = mFile.group(3);
                String replacement = indent + "File " + fileVar + " = new File(" + baseVar + ", " + fileArg + ").getCanonicalFile();\n"
                        + indent + "if (!" + fileVar + ".toPath().startsWith(" + baseVar + ".toPath().normalize())) {\n"
                        + indent + "    throw new SecurityException(\"Path traversal attempt detected\");\n"
                        + indent + "}";
                lines[targetIdx] = replacement;
                String result = String.join("\n", lines);
                if (isValidJava(result)) {
                    return RemediationResult.success(result, "PathTraversalRemediationStrategy", "Added canonical path containment validation for File instantiation", finding.getStartLine(), finding.getEndLine());
                }
            }

            // Case B: Path target = Path.of(basePath, userPath);
            Pattern pPath = Pattern.compile(".*\\bPath\\s+(\\w+)\\s*=\\s*Path(?:s)?\\.(?:of|get)\\s*\\(\\s*(\\w+)\\s*,\\s*(\\w+)\\s*\\)\\s*;.*");
            Matcher mPath = pPath.matcher(line);
            if (mPath.find()) {
                String pathVar = mPath.group(1);
                String baseVar = mPath.group(2);
                String pathArg = mPath.group(3);
                String replacement = indent + "Path " + pathVar + " = Path.of(" + baseVar + ".toString(), " + pathArg + ").normalize();\n"
                        + indent + "if (!" + pathVar + ".startsWith(" + baseVar + ".normalize())) {\n"
                        + indent + "    throw new SecurityException(\"Path traversal attempt detected\");\n"
                        + indent + "}";
                lines[targetIdx] = replacement;
                String result = String.join("\n", lines);
                if (isValidJava(result)) {
                    return RemediationResult.success(result, "PathTraversalRemediationStrategy", "Added normalized path containment validation for Path creation", finding.getStartLine(), finding.getEndLine());
                }
            }
        }

        String snippet = finding.getVulnerableSnippet();
        if (snippet != null && snippet.startsWith("new File(") && source.contains(snippet)) {
            String candidate = source.replace(snippet, snippet + ".getCanonicalFile()");
            if (isValidJava(candidate)) {
                return RemediationResult.fallback(candidate, "PathTraversalRemediationStrategy", "Applied fallback getCanonicalFile path normalization", finding.getStartLine(), finding.getEndLine());
            }
        }

        return RemediationResult.unapplied(source, "PathTraversalRemediationStrategy", "Failed to apply path containment check");
    }

    private String extractIndent(String line) {
        StringBuilder sb = new StringBuilder();
        for (char c : line.toCharArray()) {
            if (Character.isWhitespace(c)) sb.append(c);
            else break;
        }
        return sb.toString();
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
