package com.sentinelpr.core.analysis;

import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.AnnotationExpr;
import com.github.javaparser.ast.expr.ArrayInitializerExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.NormalAnnotationExpr;
import com.github.javaparser.ast.expr.SingleMemberAnnotationExpr;
import com.github.javaparser.ast.expr.StringLiteralExpr;
import com.sentinelpr.core.model.InspectedSource;
import com.sentinelpr.core.model.SecurityFinding;
import com.sentinelpr.core.model.SecurityRule;
import com.sentinelpr.core.model.Severity;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * <b>FrameworkContextAnalyzer</b>
 *
 * <p>Analyzes Spring Boot framework security contexts for critical misconfigurations:</p>
 * <ol>
 *   <li>SEC-009: CSRF protection disabled on stateful sessions</li>
 *   <li>SEC-010: Permissive wildcard CORS origin policies</li>
 * </ol>
 */
public class FrameworkContextAnalyzer {

    /**
     * Evaluates all Spring Framework security context rules on the inspected source.
     */
    public List<SecurityFinding> analyze(InspectedSource source) {
        List<SecurityFinding> findings = new ArrayList<>();
        if (source == null || source.getCompilationUnit() == null) {
            return findings;
        }

        findings.addAll(evaluateCsrfDisabled(source));
        findings.addAll(evaluatePermissiveCors(source));
        return findings;
    }

    /**
     * Rule SEC-009: Detects SecurityFilterChain beans where csrf.disable() is called without SessionCreationPolicy.STATELESS.
     */
    public List<SecurityFinding> evaluateCsrfDisabled(InspectedSource source) {
        List<SecurityFinding> findings = new ArrayList<>();
        String pathStr = source.getFilePath() != null ? source.getFilePath().toString() : "UnknownSource.java";

        for (MethodDeclaration method : source.getMethods()) {
            String returnType = method.getTypeAsString();
            boolean isSecurityConfig = returnType.contains("SecurityFilterChain")
                    || returnType.contains("WebSecurityConfigurer")
                    || method.getParameters().stream().anyMatch(p -> p.getTypeAsString().contains("HttpSecurity"));

            if (!isSecurityConfig) {
                continue;
            }

            String methodBody = method.getBody().map(Node::toString).orElse("");
            boolean disablesCsrf = methodBody.contains(".disable()") && methodBody.contains("csrf")
                    || methodBody.contains("AbstractHttpConfigurer::disable");

            if (!disablesCsrf) {
                continue;
            }

            boolean isStateless = methodBody.contains("SessionCreationPolicy.STATELESS")
                    || methodBody.contains("STATELESS");

            if (!isStateless) {
                int startLine = method.getBegin().map(p -> p.line).orElse(0);
                int endLine = method.getEnd().map(p -> p.line).orElse(0);

                // Try to pinpoint the exact csrf call
                Node targetNode = method.findAll(MethodCallExpr.class).stream()
                        .filter(call -> call.getNameAsString().equals("disable") && call.toString().contains("csrf"))
                        .findFirst()
                        .map(n -> (Node) n)
                        .orElse(method);

                String rationale = String.format(
                        "CSRF protection is explicitly disabled in '%s' without configuring SessionCreationPolicy.STATELESS. State-changing requests on session-based endpoints are vulnerable to Cross-Site Request Forgery (CSRF).",
                        method.getNameAsString()
                );

                String remediation = "Either keep CSRF enabled (default in Spring Security) or explicitly configure stateless session creation: " +
                        ".sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))";

                findings.add(new SecurityFinding(
                        "FND-" + UUID.randomUUID().toString().substring(0, 8),
                        SecurityRule.SPRING_SECURITY_CSRF_DISABLED,
                        Severity.HIGH,
                        pathStr,
                        source.getPrimaryClassName(),
                        method.getNameAsString(),
                        targetNode.getBegin().map(p -> p.line).orElse(startLine),
                        targetNode.getEnd().map(p -> p.line).orElse(endLine),
                        targetNode.toString(),
                        "Spring Security CSRF protection disabled without stateless session policy",
                        rationale,
                        remediation,
                        0.97
                ));
            }
        }

        return findings;
    }

    /**
     * Rule SEC-010: Detects permissive CORS origins (@CrossOrigin(origins = "*") or CorsConfiguration.addAllowedOrigin("*")).
     */
    public List<SecurityFinding> evaluatePermissiveCors(InspectedSource source) {
        List<SecurityFinding> findings = new ArrayList<>();
        String pathStr = source.getFilePath() != null ? source.getFilePath().toString() : "UnknownSource.java";

        // 1. Check @CrossOrigin annotations on classes and methods
        for (AnnotationExpr annotation : source.getAnnotations()) {
            String annName = annotation.getNameAsString();
            if ("CrossOrigin".equals(annName) || "org.springframework.web.bind.annotation.CrossOrigin".equals(annName)) {
                if (hasPermissiveOrigin(annotation)) {
                    int line = annotation.getBegin().map(p -> p.line).orElse(0);
                    int endLine = annotation.getEnd().map(p -> p.line).orElse(line);
                    MethodDeclaration method = annotation.findAncestor(MethodDeclaration.class).orElse(null);
                    ClassOrInterfaceDeclaration clazz = annotation.findAncestor(ClassOrInterfaceDeclaration.class).orElse(null);
                    String contextName = method != null ? method.getNameAsString() : (clazz != null ? clazz.getNameAsString() : "classScope");

                    String rationale = String.format(
                            "Permissive CORS policy detected on '%s'. Wildcard origin '*' allows arbitrary third-party websites to issue cross-origin requests and read sensitive response data.",
                            contextName
                    );

                    String remediation = "Replace wildcard '*' with explicit, trusted origin domains: @CrossOrigin(origins = \"https://trusted.domain.com\")";

                    findings.add(new SecurityFinding(
                            "FND-" + UUID.randomUUID().toString().substring(0, 8),
                            SecurityRule.SPRING_PERMISSIVE_CORS,
                            Severity.MEDIUM,
                            pathStr,
                            source.getPrimaryClassName(),
                            contextName,
                            line,
                            endLine,
                            annotation.toString(),
                            "Permissive wildcard CORS policy detected: " + annotation.toString(),
                            rationale,
                            remediation,
                            0.98
                    ));
                }
            }
        }

        // 2. Check CorsConfiguration method calls: addAllowedOrigin("*"), allowedOrigins("*")
        for (MethodCallExpr call : source.getMethodCalls()) {
            String methodName = call.getNameAsString();
            if ("addAllowedOrigin".equals(methodName) || "allowedOrigins".equals(methodName)
                    || "addAllowedOriginPattern".equals(methodName) || "allowedOriginPatterns".equals(methodName)) {
                for (Expression arg : call.getArguments()) {
                    if (arg instanceof StringLiteralExpr literal && "*".equals(literal.getValue())) {
                        int line = call.getBegin().map(p -> p.line).orElse(0);
                        int endLine = call.getEnd().map(p -> p.line).orElse(line);
                        MethodDeclaration method = call.findAncestor(MethodDeclaration.class).orElse(null);
                        String methodNameContext = method != null ? method.getNameAsString() : "configuration";

                        findings.add(new SecurityFinding(
                                "FND-" + UUID.randomUUID().toString().substring(0, 8),
                                SecurityRule.SPRING_PERMISSIVE_CORS,
                                Severity.MEDIUM,
                                pathStr,
                                source.getPrimaryClassName(),
                                methodNameContext,
                                line,
                                endLine,
                                call.toString(),
                                "Permissive CORS configuration detected: " + call.toString(),
                                "Wildcard origin '*' allows unauthorized cross-origin requests from any domain.",
                                "Restrict allowed origins to trusted domains, e.g., config.addAllowedOrigin(\"https://trusted.domain.com\");",
                                0.98
                        ));
                    }
                }
            }
        }

        return findings;
    }

    private boolean hasPermissiveOrigin(AnnotationExpr annotation) {
        // @CrossOrigin without arguments defaults to "*"
        if (annotation.isMarkerAnnotationExpr()) {
            return true;
        }

        // @CrossOrigin("*")
        if (annotation instanceof SingleMemberAnnotationExpr single) {
            return isWildcard(single.getMemberValue());
        }

        // @CrossOrigin(origins = "*", ...) or @CrossOrigin(originPatterns = "*")
        if (annotation instanceof NormalAnnotationExpr normal) {
            boolean hasExplicitOrigins = false;
            for (var pair : normal.getPairs()) {
                String name = pair.getNameAsString();
                if ("origins".equals(name) || "value".equals(name) || "originPatterns".equals(name)) {
                    hasExplicitOrigins = true;
                    if (isWildcard(pair.getValue())) {
                        return true;
                    }
                }
            }
            // If @CrossOrigin has arguments but no origins specified, defaults to "*"
            return !hasExplicitOrigins;
        }

        return false;
    }

    private boolean isWildcard(Expression expr) {
        if (expr instanceof StringLiteralExpr literal) {
            return "*".equals(literal.getValue());
        }
        if (expr instanceof ArrayInitializerExpr array) {
            for (Expression item : array.getValues()) {
                if (item instanceof StringLiteralExpr lit && "*".equals(lit.getValue())) {
                    return true;
                }
            }
        }
        return false;
    }
}
