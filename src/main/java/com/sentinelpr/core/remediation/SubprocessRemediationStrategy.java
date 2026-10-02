package com.sentinelpr.core.remediation;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ast.CompilationUnit;
import com.sentinelpr.core.model.InspectedSource;
import com.sentinelpr.core.model.SecurityFinding;
import com.sentinelpr.core.model.SecurityRule;

import java.util.Optional;

/**
 * Remediation strategy for SEC-004-UNISOLATED-SUBPROCESS.
 */
public class SubprocessRemediationStrategy implements RemediationStrategy {

    private final JavaParser javaParser;

    public SubprocessRemediationStrategy() {
        ParserConfiguration config = new ParserConfiguration();
        config.setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_21);
        this.javaParser = new JavaParser(config);
    }

    @Override
    public SecurityRule getSupportedRule() {
        return SecurityRule.UNISOLATED_SUBPROCESS;
    }

    @Override
    public RemediationResult remediate(String source, SecurityFinding finding, InspectedSource inspectedSource, RemediationContext context) {
        String patched = source.replace("Runtime.getRuntime().exec(", "new ProcessBuilder(");
        if (isValidJava(patched)) {
            return RemediationResult.success(patched, "SubprocessRemediationStrategy", "Replaced un-isolated Runtime.getRuntime().exec with ProcessBuilder", finding.getStartLine(), finding.getEndLine());
        }
        return RemediationResult.unapplied(source, "SubprocessRemediationStrategy", "Failed to replace Runtime.exec with ProcessBuilder");
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
