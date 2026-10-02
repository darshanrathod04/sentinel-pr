package com.sentinelpr.core.remediation;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ast.CompilationUnit;
import com.sentinelpr.core.model.InspectedSource;
import com.sentinelpr.core.model.SecurityFinding;
import com.sentinelpr.core.model.SecurityRule;

import java.util.Optional;

/**
 * Remediation strategy for SEC-010-SPRING-PERMISSIVE-CORS.
 */
public class PermissiveCorsRemediationStrategy implements RemediationStrategy {

    private final JavaParser javaParser;

    public PermissiveCorsRemediationStrategy() {
        ParserConfiguration config = new ParserConfiguration();
        config.setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_21);
        this.javaParser = new JavaParser(config);
    }

    @Override
    public SecurityRule getSupportedRule() {
        return SecurityRule.SPRING_PERMISSIVE_CORS;
    }

    @Override
    public RemediationResult remediate(String source, SecurityFinding finding, InspectedSource inspectedSource, RemediationContext context) {
        String patched = source
                .replace("@CrossOrigin(origins = \"*\")", "@CrossOrigin(origins = \"https://trusted.domain.com\")")
                .replace("@CrossOrigin(\"*\")", "@CrossOrigin(origins = \"https://trusted.domain.com\")")
                .replace("@CrossOrigin(originPatterns = \"*\")", "@CrossOrigin(origins = \"https://trusted.domain.com\")")
                .replace(".addAllowedOrigin(\"*\")", ".addAllowedOrigin(\"https://trusted.domain.com\")")
                .replace(".allowedOrigins(\"*\")", ".allowedOrigins(\"https://trusted.domain.com\")")
                .replace(".addAllowedOriginPattern(\"*\")", ".addAllowedOrigin(\"https://trusted.domain.com\")");

        if (isValidJava(patched)) {
            return RemediationResult.success(patched, "PermissiveCorsRemediationStrategy", "Restricted permissive CORS origin to trusted domain", finding.getStartLine(), finding.getEndLine());
        }

        return RemediationResult.unapplied(source, "PermissiveCorsRemediationStrategy", "Failed to restrict permissive CORS");
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
