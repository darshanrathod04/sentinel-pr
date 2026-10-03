package com.sentinelpr.core.analysis.architecture;

import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.Parameter;
import com.github.javaparser.ast.expr.AnnotationExpr;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.sentinelpr.core.model.InspectedSource;
import com.sentinelpr.core.model.SecurityFinding;
import com.sentinelpr.core.model.SecurityRule;
import com.sentinelpr.core.model.Severity;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * <b>ArchitectureReviewEngine</b>
 *
 * <p>Analyzes AST symbol graphs across source files to identify enterprise architectural anti-patterns:</p>
 * <ul>
 *   <li><b>ARCH-001</b>: Cyclic dependencies between packages or classes.</li>
 *   <li><b>ARCH-002</b>: Leaky abstractions (Database entities directly exposed in @RestController endpoints).</li>
 *   <li><b>ARCH-003</b>: Direct System.currentTimeMillis() or Random calls in business services (non-deterministic testing anti-pattern).</li>
 * </ul>
 */
public class ArchitectureReviewEngine {

    public ArchitectureReviewEngine() {
    }

    /**
     * Evaluates architectural hygiene rules across a single source file.
     */
    public List<SecurityFinding> evaluate(InspectedSource source) {
        return evaluate(source, List.of(source));
    }

    /**
     * Evaluates architectural hygiene rules across a collection of project source files.
     */
    public List<SecurityFinding> evaluate(InspectedSource source, List<InspectedSource> allSources) {
        List<SecurityFinding> findings = new ArrayList<>();
        if (source == null) {
            return findings;
        }

        findings.addAll(evaluateLeakyAbstractions(source, allSources));
        findings.addAll(evaluateNonDeterministicCalls(source));
        findings.addAll(evaluateCyclicDependencies(source, allSources));

        return findings;
    }

    /**
     * ARCH-002: Detects database entities directly exposed in REST Controller endpoints.
     */
    public List<SecurityFinding> evaluateLeakyAbstractions(InspectedSource source) {
        return evaluateLeakyAbstractions(source, List.of(source));
    }

    /**
     * ARCH-002: Detects database entities directly exposed in REST Controller endpoints with cross-file symbol resolution.
     */
    public List<SecurityFinding> evaluateLeakyAbstractions(InspectedSource source, List<InspectedSource> allSources) {
        List<SecurityFinding> findings = new ArrayList<>();

        boolean isController = source.getClassDeclarations().stream().anyMatch(c ->
                c.getAnnotations().stream().anyMatch(a -> {
                    String name = a.getNameAsString();
                    return name.contains("RestController") || name.contains("Controller");
                })
        );

        if (!isController) {
            return findings;
        }

        for (MethodDeclaration method : source.getMethods()) {
            boolean isEndpoint = method.getAnnotations().stream().anyMatch(a -> {
                String name = a.getNameAsString();
                return name.contains("Mapping") || name.contains("GetMapping")
                        || name.contains("PostMapping") || name.contains("PutMapping")
                        || name.contains("DeleteMapping");
            });

            if (!isEndpoint) {
                continue;
            }

            String returnType = method.getTypeAsString();
            boolean returnsEntity = isEntityType(returnType, source, allSources);

            boolean acceptsEntity = false;
            String paramName = "";
            for (Parameter p : method.getParameters()) {
                if (isEntityType(p.getTypeAsString(), source, allSources)) {
                    acceptsEntity = true;
                    paramName = p.getNameAsString() + " (" + p.getTypeAsString() + ")";
                    break;
                }
            }

            if (returnsEntity || acceptsEntity) {
                int startLine = method.getBegin().map(p -> p.line).orElse(0);
                int endLine = method.getEnd().map(p -> p.line).orElse(0);
                String snippet = method.getDeclarationAsString();

                String entityDesc = returnsEntity ? cleanTypeName(returnType) : cleanTypeName(paramName);
                String detail = returnsEntity
                        ? "Endpoint returns internal database entity [" + entityDesc + "]"
                        : "Endpoint accepts internal database entity parameter [" + paramName + "]";

                String rationale = "Exposing database persistence entities in @RestController endpoints leaks internal schema details, causes tight coupling between API contracts and database models, and exposes the application to mass-assignment / over-posting vulnerabilities.";
                String remediation = "Map internal database entities to dedicated request/response Data Transfer Objects (DTOs) or records before returning from the controller.";

                findings.add(new SecurityFinding(
                        "FND-" + UUID.randomUUID().toString().substring(0, 8),
                        SecurityRule.ARCH_LEAKY_ABSTRACTION,
                        Severity.HIGH,
                        source.getFilePath() != null ? source.getFilePath().toString() : "UnknownController.java",
                        source.getPrimaryClassName(),
                        method.getNameAsString(),
                        startLine,
                        endLine,
                        snippet,
                        "Leaky abstraction: " + detail + " without DTO encapsulation",
                        rationale,
                        remediation,
                        0.92
                ));
            }
        }

        return findings;
    }

    /**
     * ARCH-003: Detects direct System.currentTimeMillis() or Random calls in business services.
     */
    public List<SecurityFinding> evaluateNonDeterministicCalls(InspectedSource source) {
        List<SecurityFinding> findings = new ArrayList<>();

        boolean isService = source.getClassDeclarations().stream().anyMatch(c ->
                c.getAnnotations().stream().anyMatch(a -> a.getNameAsString().contains("Service"))
        ) || source.getPrimaryClassName().endsWith("Service");

        if (!isService) {
            return findings;
        }

        // 1. Check method calls
        for (MethodCallExpr call : source.getMethodCalls()) {
            String callStr = call.toString();
            boolean isSystemTime = callStr.contains("System.currentTimeMillis()")
                    || callStr.contains("System.nanoTime()")
                    || callStr.contains("Math.random()");

            if (isSystemTime) {
                int startLine = call.getBegin().map(p -> p.line).orElse(0);
                int endLine = call.getEnd().map(p -> p.line).orElse(0);
                MethodDeclaration method = call.findAncestor(MethodDeclaration.class).orElse(null);
                String methodName = method != null ? method.getNameAsString() : "unknownMethod";

                String rationale = "Direct invocation of '" + callStr + "' in business service '" + source.getPrimaryClassName()
                        + "' introduces non-deterministic behavior that cannot be mocked, controlled, or frozen in test suites, leading to flaky tests.";
                String remediation = "Inject 'java.time.Clock' bean (e.g., clock.instant() or clock.millis()) to enable deterministic time manipulation in unit tests.";

                findings.add(new SecurityFinding(
                        "FND-" + UUID.randomUUID().toString().substring(0, 8),
                        SecurityRule.ARCH_NON_DETERMINISTIC_CALL,
                        Severity.MEDIUM,
                        source.getFilePath() != null ? source.getFilePath().toString() : "UnknownService.java",
                        source.getPrimaryClassName(),
                        methodName,
                        startLine,
                        endLine,
                        callStr,
                        "Non-deterministic system time invocation in business service: " + callStr,
                        rationale,
                        remediation,
                        0.90
                ));
            }
        }

        // 2. Check Random instantiations
        for (ObjectCreationExpr creation : source.getObjectCreations()) {
            String typeName = creation.getTypeAsString();
            if ("Random".equals(typeName) || "java.util.Random".equals(typeName)) {
                int startLine = creation.getBegin().map(p -> p.line).orElse(0);
                int endLine = creation.getEnd().map(p -> p.line).orElse(0);
                MethodDeclaration method = creation.findAncestor(MethodDeclaration.class).orElse(null);
                String methodName = method != null ? method.getNameAsString() : "unknownMethod";

                String rationale = "Direct instantiation of 'java.util.Random' in business service produces non-deterministic values and is cryptographically insecure for tokens, IDs, or security-sensitive numbers.";
                String remediation = "Inject a seeded pseudo-random service for business reproducibility or use 'java.security.SecureRandom' for security-sensitive tokens.";

                findings.add(new SecurityFinding(
                        "FND-" + UUID.randomUUID().toString().substring(0, 8),
                        SecurityRule.ARCH_NON_DETERMINISTIC_CALL,
                        Severity.MEDIUM,
                        source.getFilePath() != null ? source.getFilePath().toString() : "UnknownService.java",
                        source.getPrimaryClassName(),
                        methodName,
                        startLine,
                        endLine,
                        creation.toString(),
                        "Non-deterministic java.util.Random instantiation in business service",
                        rationale,
                        remediation,
                        0.88
                ));
            }
        }

        return findings;
    }

    /**
     * ARCH-001: Detects cyclic dependencies between packages or classes.
     */
    public List<SecurityFinding> evaluateCyclicDependencies(InspectedSource source, List<InspectedSource> allSources) {
        List<SecurityFinding> findings = new ArrayList<>();
        if (allSources == null || allSources.size() < 2) {
            return findings;
        }

        String currentClass = source.getPrimaryClassName();
        String currentPackage = source.getPackageName();
        Set<String> referencedClasses = extractReferencedClasses(source);

        for (InspectedSource other : allSources) {
            String otherClass = other.getPrimaryClassName();
            if (otherClass.equals(currentClass)) {
                continue;
            }

            // Check if current references other
            boolean currentReferencesOther = referencedClasses.contains(otherClass);
            if (!currentReferencesOther) {
                continue;
            }

            // Check if other references current
            Set<String> otherReferences = extractReferencedClasses(other);
            if (otherReferences.contains(currentClass)) {
                int startLine = source.getClassDeclarations().isEmpty()
                        ? 1
                        : source.getClassDeclarations().get(0).getBegin().map(p -> p.line).orElse(1);

                String rationale = String.format(
                        "Cyclic dependency detected: '%s' references '%s', and '%s' reciprocally references '%s'. Circular dependencies violate clean architecture layering and prevent independent modularization.",
                        currentClass, otherClass, otherClass, currentClass
                );

                String remediation = String.format(
                        "Break the cycle between '%s' and '%s' by applying Dependency Inversion (introduce an interface) or extracting the shared domain model into a separate module.",
                        currentClass, otherClass
                );

                findings.add(new SecurityFinding(
                        "FND-" + UUID.randomUUID().toString().substring(0, 8),
                        SecurityRule.ARCH_CYCLIC_DEPENDENCY,
                        Severity.MEDIUM,
                        source.getFilePath() != null ? source.getFilePath().toString() : currentClass + ".java",
                        currentClass,
                        "classLevel",
                        startLine,
                        startLine,
                        "class " + currentClass + " <---> class " + otherClass,
                        "Cyclic dependency detected between " + currentClass + " and " + otherClass,
                        rationale,
                        remediation,
                        0.85
                ));
            }
        }

        return findings;
    }

    public boolean isEntityType(String typeName, InspectedSource source) {
        return isEntityType(typeName, source, List.of(source));
    }

    public boolean isEntityType(String typeName, InspectedSource source, List<InspectedSource> allSources) {
        if (typeName == null || typeName.isBlank()) {
            return false;
        }
        String cleanType = cleanTypeName(typeName);
        if (cleanType.isBlank()) {
            return false;
        }

        // 1. Authoritative cross-file JPA @Entity resolution against all project sources
        if (allSources != null && !allSources.isEmpty()) {
            Boolean resolvedEntity = resolveCrossFileJpaEntity(cleanType, source, allSources);
            if (resolvedEntity != null && resolvedEntity) {
                return true;
            }
        }

        // 2. Existing *Entity naming heuristic fallback (preserves benchmark and standalone file behavior)
        if (cleanType.endsWith("Entity")) {
            return true;
        }

        // 3. Fallback: single-file heuristic checking persistence import and entity in class name
        boolean hasEntityImport = source != null && source.getImports() != null && source.getImports().stream()
                .anyMatch(i -> i.endsWith("Entity") || i.contains("persistence.Entity"));

        return hasEntityImport && cleanType.toLowerCase().contains("entity");
    }

    private String cleanTypeName(String typeName) {
        if (typeName == null) return "";
        String clean = typeName;
        clean = clean.replace("List<", "")
                .replace("Set<", "")
                .replace("Collection<", "")
                .replace("Iterable<", "")
                .replace("ResponseEntity<", "")
                .replace("Optional<", "")
                .replace(">", "")
                .replace("[]", "")
                .trim();
        if (clean.contains("<") && clean.endsWith(">")) {
            clean = clean.substring(clean.indexOf('<') + 1, clean.lastIndexOf('>')).trim();
        }
        return clean;
    }

    private Boolean resolveCrossFileJpaEntity(String cleanType, InspectedSource source, List<InspectedSource> allSources) {
        String simpleName = cleanType.contains(".") ? cleanType.substring(cleanType.lastIndexOf('.') + 1) : cleanType;
        String explicitFqcn = cleanType.contains(".") ? cleanType : findImportedFqcn(simpleName, source);

        // A. If an explicit FQCN is known (from import or qualified type), find exact match
        if (explicitFqcn != null) {
            for (InspectedSource candidate : allSources) {
                if (matchesFqcn(candidate, simpleName, explicitFqcn)) {
                    return hasJpaEntityAnnotation(candidate, simpleName);
                }
            }
        }

        // B. Check same package as controller source
        if (source != null && source.getPackageName() != null && !source.getPackageName().isBlank()) {
            String samePkg = source.getPackageName();
            for (InspectedSource candidate : allSources) {
                if (samePkg.equals(candidate.getPackageName()) && matchesSimpleName(candidate, simpleName)) {
                    return hasJpaEntityAnnotation(candidate, simpleName);
                }
            }
        }

        // C. Match candidates by simple name across allSources
        List<InspectedSource> nameMatches = new ArrayList<>();
        for (InspectedSource candidate : allSources) {
            if (matchesSimpleName(candidate, simpleName)) {
                nameMatches.add(candidate);
            }
        }

        if (nameMatches.size() == 1) {
            return hasJpaEntityAnnotation(nameMatches.get(0), simpleName);
        } else if (nameMatches.size() > 1) {
            // Disambiguation: if source imports a package containing one of the candidates, choose it
            for (InspectedSource match : nameMatches) {
                if (isPackageImported(match.getPackageName(), source)) {
                    return hasJpaEntityAnnotation(match, simpleName);
                }
            }
            // If any matching class is an @Entity, check if it has entity annotation
            for (InspectedSource match : nameMatches) {
                if (hasJpaEntityAnnotation(match, simpleName)) {
                    return true;
                }
            }
            return false;
        }

        return null;
    }

    private String findImportedFqcn(String simpleName, InspectedSource source) {
        if (source == null || source.getImports() == null) {
            return null;
        }
        for (String imp : source.getImports()) {
            if (imp.endsWith("." + simpleName)) {
                return imp;
            }
        }
        return null;
    }

    private boolean matchesFqcn(InspectedSource candidate, String simpleName, String fqcn) {
        if (candidate == null || simpleName == null || fqcn == null) return false;
        String candidatePkg = candidate.getPackageName() != null ? candidate.getPackageName() : "";
        String primaryName = candidate.getPrimaryClassName();
        if (primaryName != null) {
            String primaryFqcn = candidatePkg.isEmpty() ? primaryName : candidatePkg + "." + primaryName;
            if (primaryFqcn.equals(fqcn) && matchesSimpleName(candidate, simpleName)) {
                return true;
            }
        }
        for (ClassOrInterfaceDeclaration clazz : candidate.getClassDeclarations()) {
            String className = clazz.getNameAsString();
            String classFqcn = candidatePkg.isEmpty() ? className : candidatePkg + "." + className;
            if (classFqcn.equals(fqcn) && simpleName.equals(className)) {
                return true;
            }
        }
        return false;
    }

    private boolean matchesSimpleName(InspectedSource candidate, String simpleName) {
        if (candidate == null || simpleName == null) return false;
        if (simpleName.equals(candidate.getPrimaryClassName())) {
            return true;
        }
        return candidate.getClassDeclarations().stream()
                .anyMatch(c -> simpleName.equals(c.getNameAsString()));
    }

    private boolean isPackageImported(String packageName, InspectedSource source) {
        if (packageName == null || source == null || source.getImports() == null) {
            return false;
        }
        return source.getImports().contains(packageName + ".*");
    }

    private boolean hasJpaEntityAnnotation(InspectedSource candidate, String simpleName) {
        if (candidate == null) return false;
        for (ClassOrInterfaceDeclaration clazz : candidate.getClassDeclarations()) {
            if (simpleName.equals(clazz.getNameAsString())) {
                for (AnnotationExpr annotation : clazz.getAnnotations()) {
                    String annName = annotation.getNameAsString();
                    if ("Entity".equals(annName)) {
                        boolean hasConflictingImport = candidate.getImports().stream()
                                .anyMatch(i -> i.endsWith(".Entity")
                                        && !i.startsWith("jakarta.persistence")
                                        && !i.startsWith("javax.persistence"));
                        if (!hasConflictingImport) {
                            return true;
                        }
                    } else if ("jakarta.persistence.Entity".equals(annName) || "javax.persistence.Entity".equals(annName)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private Set<String> extractReferencedClasses(InspectedSource source) {
        Set<String> refs = new HashSet<>();
        // 1. Imports
        for (String imp : source.getImports()) {
            int lastDot = imp.lastIndexOf('.');
            if (lastDot >= 0 && lastDot < imp.length() - 1) {
                refs.add(imp.substring(lastDot + 1));
            }
        }

        // 2. Field types
        for (var field : source.getFields()) {
            for (var varDecl : field.getVariables()) {
                String typeStr = varDecl.getTypeAsString();
                refs.add(cleanSimpleTypeName(typeStr));
            }
        }

        // 3. Method parameters & return types
        for (var method : source.getMethods()) {
            refs.add(cleanSimpleTypeName(method.getTypeAsString()));
            for (var param : method.getParameters()) {
                refs.add(cleanSimpleTypeName(param.getTypeAsString()));
            }
        }

        return refs;
    }

    private String cleanSimpleTypeName(String typeStr) {
        if (typeStr == null) return "";
        return typeStr.replaceAll("<.*>", "").trim();
    }
}
