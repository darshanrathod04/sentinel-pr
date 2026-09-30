package com.sentinelpr.core.remediation;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ast.CompilationUnit;
import com.sentinelpr.core.model.InspectedSource;
import com.sentinelpr.core.model.SecurityFinding;
import com.sentinelpr.core.model.SecurityRule;

import java.util.Optional;

/**
 * Remediation strategy for SEC-009-SPRING-SECURITY-CSRF-DISABLED.
 */
public class SpringCsrfRemediationStrategy implements RemediationStrategy {

    private final JavaParser javaParser;

    public SpringCsrfRemediationStrategy() {
        ParserConfiguration config = new ParserConfiguration();
        config.setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_21);
        this.javaParser = new JavaParser(config);
    }

    @Override
    public SecurityRule getSupportedRule() {
        return SecurityRule.SPRING_SECURITY_CSRF_DISABLED;
    }

    @Override
    public RemediationResult remediate(String source, SecurityFinding finding, InspectedSource inspectedSource, RemediationContext context) {
        String snippet = finding.getVulnerableSnippet();
        if (snippet != null && source.contains(snippet)) {
            String candidate = source.replace(snippet, "// CSRF protection preserved");
            if (isValidJava(candidate)) {
                return RemediationResult.success(candidate, "SpringCsrfRemediationStrategy", "Removed insecure csrf().disable() invocation", finding.getStartLine(), finding.getEndLine());
            }
        }
        return RemediationResult.unapplied(source, "SpringCsrfRemediationStrategy", "CSRF snippet not matched in source");
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
