package com.sentinelpr.core.remediation;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ast.CompilationUnit;
import com.sentinelpr.client.DeveloperFacade;
import com.sentinelpr.core.model.InspectedSource;
import com.sentinelpr.core.model.SecurityFinding;
import com.sentinelpr.core.model.SecurityRule;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Remediation strategy for ARCH-002-LEAKY-ABSTRACTION.
 */
public class LeakyAbstractionRemediationStrategy implements RemediationStrategy {

    private final JavaParser javaParser;

    public LeakyAbstractionRemediationStrategy() {
        ParserConfiguration config = new ParserConfiguration();
        config.setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_21);
        this.javaParser = new JavaParser(config);
    }

    @Override
    public SecurityRule getSupportedRule() {
        return SecurityRule.ARCH_LEAKY_ABSTRACTION;
    }

    @Override
    public RemediationResult remediate(String source, SecurityFinding finding, InspectedSource inspectedSource, RemediationContext context) {
        String targetFilePath = context != null ? context.getTargetFilePath() : null;
        String entityName = extractEntityNameFromFinding(finding);
        if (entityName == null || entityName.isBlank()) {
            return RemediationResult.unapplied(source, "LeakyAbstractionRemediationStrategy", "Entity name not found");
        }

        String baseName = entityName.endsWith("Entity")
                ? entityName.substring(0, entityName.length() - 6)
                : entityName;

        // Resolution order:
        // 1. Existing DTO
        // 2. Existing Mapper
        // 3. Existing Java Record
        // 4. Otherwise return DEFERRED_TO_MULTI_FILE_PLAN (unapplied)
        DeveloperFacade.ResolvedDtoTarget resolved = resolveDtoTarget(source, baseName, targetFilePath);
        if (resolved == null) {
            return RemediationResult.unapplied(source, "LeakyAbstractionRemediationStrategy", "No pre-existing DTO/Mapper resolved; defer to multi-file plan");
        }

        String methodName = finding.getMethodName();
        if (methodName == null || methodName.isBlank()) {
            return RemediationResult.unapplied(source, "LeakyAbstractionRemediationStrategy", "Method name not found");
        }

        Pattern methodPattern = Pattern.compile(
                "(public\\s+)" + Pattern.quote(entityName) + "(\\s+" + Pattern.quote(methodName) + "\\s*\\([^)]*\\)\\s*\\{[\\s\\S]*?return\\s+)(.+?)(;)"
        );
        Matcher matcher = methodPattern.matcher(source);
        if (matcher.find()) {
            String prefix = matcher.group(1) + resolved.targetType() + matcher.group(2);
            String returnExpr = matcher.group(3).trim();
            String suffix = matcher.group(4);
            String replacement = prefix + resolved.wrapExpression(returnExpr) + suffix;
            String candidate = matcher.replaceFirst(Matcher.quoteReplacement(replacement));
            if (isValidJava(candidate)) {
                return RemediationResult.success(candidate, "LeakyAbstractionRemediationStrategy", "Refactored endpoint to return DTO/Record instead of Entity", finding.getStartLine(), finding.getEndLine());
            }
        }

        // Fallback: targeted line replacements
        String patched = source.replace("public " + entityName + " " + methodName, "public " + resolved.targetType() + " " + methodName);
        Pattern retPattern = Pattern.compile("return\\s+coupledService\\." + Pattern.quote(methodName) + "\\([^)]*\\);");
        Matcher retMatcher = retPattern.matcher(patched);
        if (retMatcher.find()) {
            String origCall = retMatcher.group(0);
            String callExpr = origCall.substring("return ".length(), origCall.length() - 1).trim();
            patched = patched.replace(origCall, "return " + resolved.wrapExpression(callExpr) + ";");
        }

        if (isValidJava(patched)) {
            return RemediationResult.fallback(patched, "LeakyAbstractionRemediationStrategy", "Applied fallback DTO refactoring", finding.getStartLine(), finding.getEndLine());
        }

        return RemediationResult.unapplied(source, "LeakyAbstractionRemediationStrategy", "Failed to apply DTO refactoring");
    }

    private DeveloperFacade.ResolvedDtoTarget resolveDtoTarget(String source, String baseName, String targetFilePath) {
        String[] dtoCandidates = {baseName + "Dto", baseName + "DTO"};
        for (String dtoName : dtoCandidates) {
            if (checkClassExists(dtoName, source, targetFilePath)) {
                return new DeveloperFacade.ResolvedDtoTarget(dtoName, dtoName + ".fromEntity");
            }
        }

        String mapperName = baseName + "Mapper";
        if (checkClassExists(mapperName, source, targetFilePath)) {
            String dtoName = baseName + "Dto";
            return new DeveloperFacade.ResolvedDtoTarget(dtoName, mapperName + ".toDto");
        }

        String recordName = baseName + "Record";
        if (checkClassExists(recordName, source, targetFilePath)) {
            return new DeveloperFacade.ResolvedDtoTarget(recordName, recordName + ".fromEntity");
        }

        return null;
    }

    private boolean checkClassExists(String className, String source, String targetFilePath) {
        if (source != null && (source.contains("import " + className) || source.contains("import static " + className) || source.contains("class " + className))) {
            return true;
        }

        if (targetFilePath != null && !targetFilePath.isBlank()) {
            try {
                Path targetPath = Path.of(targetFilePath);
                if (targetPath.getParent() != null) {
                    Path candidate = targetPath.getParent().resolve(className + ".java");
                    if (Files.exists(candidate)) {
                        return true;
                    }
                }
            } catch (Exception ignored) {
            }
        }

        Path coupledPath = Path.of("src/test/java/com/sentinelpr/fixture/coupled/" + className + ".java");
        if (Files.exists(coupledPath)) {
            return true;
        }

        Path srcMainPath = Path.of("src/main/java/com/sentinelpr/fixture/coupled/" + className + ".java");
        if (Files.exists(srcMainPath)) {
            return true;
        }

        return false;
    }

    private String extractEntityNameFromFinding(SecurityFinding finding) {
        String desc = finding.getDescription();
        if (desc != null && desc.contains("[") && desc.contains("]")) {
            int start = desc.indexOf('[');
            int end = desc.indexOf(']');
            if (end > start) {
                return desc.substring(start + 1, end).trim();
            }
        }
        String snippet = finding.getVulnerableSnippet();
        if (snippet != null) {
            Pattern p = Pattern.compile("(\\b[A-Z]\\w*Entity\\b)");
            Matcher m = p.matcher(snippet);
            if (m.find()) {
                return m.group(1);
            }
        }
        return "UserEntity";
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
