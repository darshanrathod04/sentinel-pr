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
 * Remediation strategy for SEC-007-INSECURE-DESERIALIZATION.
 */
public class InsecureDeserializationRemediationStrategy implements RemediationStrategy {

    private final JavaParser javaParser;

    public InsecureDeserializationRemediationStrategy() {
        ParserConfiguration config = new ParserConfiguration();
        config.setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_21);
        this.javaParser = new JavaParser(config);
    }

    @Override
    public SecurityRule getSupportedRule() {
        return SecurityRule.INSECURE_DESERIALIZATION;
    }

    @Override
    public RemediationResult remediate(String source, SecurityFinding finding, InspectedSource inspectedSource, RemediationContext context) {
        if (finding.getMethodName() != null && !finding.getMethodName().isBlank()) {
            Pattern oisPattern = Pattern.compile("(\\bObjectInputStream\\s+(\\w+)\\s*=\\s*new\\s+ObjectInputStream\\([^)]+\\);)");
            Matcher m = oisPattern.matcher(source);
            if (m.find()) {
                String match = m.group(1);
                String oisVar = m.group(2);
                String patched = source.replace(match, match + "\n        " + oisVar + ".setObjectInputFilter(java.io.ObjectInputFilter.Config.createFilter(\"java.lang.*;java.util.*;!*\"));");
                if (isValidJava(patched)) {
                    return RemediationResult.success(patched, "InsecureDeserializationRemediationStrategy", "Configured strict ObjectInputFilter on ObjectInputStream", finding.getStartLine(), finding.getEndLine());
                }
            }
        }

        return RemediationResult.unapplied(source, "InsecureDeserializationRemediationStrategy", "ObjectInputStream creation pattern not found");
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
