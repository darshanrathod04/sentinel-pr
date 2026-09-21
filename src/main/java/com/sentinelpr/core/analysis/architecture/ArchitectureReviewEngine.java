package com.sentinelpr.core.analysis.architecture;

import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.Parameter;
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

        findings.addAll(evaluateLeakyAbstractions(source));
        findings.addAll(evaluateNonDeterministicCalls(source));
        findings.addAll(evaluateCyclicDependencies(source, allSources));

        return findings;
    }

    /**
     * ARCH-002: Detects database entities directly exposed in REST Controller endpoints.
     */
    public List<SecurityFinding> evaluateLeakyAbstractions(InspectedSource source) {
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
            boolean returnsEntity = isEntityType(returnType, source);

            boolean acceptsEntity = false;
            String paramName = "";
            for (Parameter p : method.getParameters()) {
                if (isEntityType(p.getTypeAsString(), source)) {
                    acceptsEntity = true;
                    paramName = p.getNameAsString() + " (" + p.getTypeAsString() + ")";
                    break;
                }
            }

            if (returnsEntity || acceptsEntity) {
                int startLine = method.getBegin().map(p -> p.line).orElse(0);
                int endLine = method.getEnd().map(p -> p.line).orElse(0);
                String snippet = method.getDeclarationAsString();

                String detail = returnsEntity
                        ? "Endpoint returns internal database entity [" + returnType + "]"
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

    private boolean isEntityType(String typeName, InspectedSource source) {
        if (typeName == null || typeName.isBlank()) {
            return false;
        }
        String cleanType = typeName.replace("List<", "")
                .replace("Set<", "")
                .replace("Collection<", "")
                .replace("ResponseEntity<", "")
                .replace("Optional<", "")
                .replace(">", "")
                .trim();

        if (cleanType.endsWith("Entity")) {
            return true;
        }

        // Check imports for javax.persistence.Entity or jakarta.persistence.Entity
        boolean hasEntityImport = source.getImports().stream()
                .anyMatch(i -> i.endsWith("Entity") || i.contains("persistence.Entity"));

        return hasEntityImport && cleanType.toLowerCase().contains("entity");
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
