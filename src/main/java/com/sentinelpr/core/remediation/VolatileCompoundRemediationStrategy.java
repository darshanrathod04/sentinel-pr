package com.sentinelpr.core.remediation;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ast.CompilationUnit;
import com.sentinelpr.core.model.InspectedSource;
import com.sentinelpr.core.model.SecurityFinding;
import com.sentinelpr.core.model.SecurityRule;

import java.util.Optional;

/**
 * Remediation strategy for SEC-003-VOLATILE-COMPOUND.
 */
public class VolatileCompoundRemediationStrategy implements RemediationStrategy {

    private final JavaParser javaParser;

    public VolatileCompoundRemediationStrategy() {
        ParserConfiguration config = new ParserConfiguration();
        config.setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_21);
        this.javaParser = new JavaParser(config);
    }

    @Override
    public SecurityRule getSupportedRule() {
        return SecurityRule.VOLATILE_COMPOUND_OP;
    }

    @Override
    public RemediationResult remediate(String source, SecurityFinding finding, InspectedSource inspectedSource, RemediationContext context) {
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

        // Transform getter if present
        patched = patched.replaceAll("return\\s+" + fieldVar + "\\s*;", "return " + fieldVar + ".get();");

        if (isValidJava(patched)) {
            return RemediationResult.success(patched, "VolatileCompoundRemediationStrategy", "Converted volatile int to AtomicInteger with atomic increment/decrement", finding.getStartLine(), finding.getEndLine());
        }

        return RemediationResult.unapplied(source, "VolatileCompoundRemediationStrategy", "Failed to transform volatile variable to AtomicInteger");
    }

    private String extractVarName(String snippet) {
        if (snippet == null) return "counter";
        return snippet.replaceAll("[^a-zA-Z0-9_]", "");
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
