package com.sentinelpr.core.analysis.multilang.python.framework;

import com.sentinelpr.core.analysis.multilang.python.ast.*;
import com.sentinelpr.core.model.InspectedSource;
import com.sentinelpr.core.model.SecurityFinding;
import com.sentinelpr.core.model.SecurityRule;
import com.sentinelpr.core.model.Severity;

import java.util.*;

/**
 * <b>PythonFrameworkSecurityEngine</b>
 *
 * <p>Framework-specific static security intelligence for Flask, Django, and FastAPI.</p>
 */
public class PythonFrameworkSecurityEngine {

    public List<SecurityFinding> evaluate(PythonModule module, InspectedSource source) {
        if (module == null) {
            return Collections.emptyList();
        }

        List<SecurityFinding> findings = new ArrayList<>();
        String filePath = source.getFilePath() != null ? source.getFilePath().toString() : "app.py";

        // 1. Flask checks
        evaluateFlask(module, filePath, findings);

        // 2. Django checks
        evaluateDjango(module, filePath, findings);

        // 3. FastAPI checks
        evaluateFastApi(module, filePath, findings);

        return findings;
    }

    private void evaluateFlask(PythonModule module, String filePath, List<SecurityFinding> findings) {
        for (PythonCallExpr call : module.findAllCalls()) {
            String fullCallee = call.getFullCalleeName();
            String shortCallee = call.getCalleeName();

            // SSTI / XSS via render_template_string
            if ("render_template_string".equals(shortCallee) || fullCallee.endsWith(".render_template_string")) {
                List<PythonAstNode> posArgs = call.getPositionalArguments();
                if (!posArgs.isEmpty() && !(posArgs.get(0) instanceof PythonLiteralExpr lit && lit.getKind() == PythonLiteralExpr.Kind.STRING)) {
                    findings.add(createFinding(
                            SecurityRule.XSS,
                            Severity.CRITICAL,
                            filePath,
                            "FlaskModule",
                            "render_template_string",
                            call.getLine(),
                            call.getLine(),
                            call.getRawText(),
                            "Server-Side Template Injection / XSS in Flask render_template_string",
                            "Dynamic template string evaluated without escaping allows Jinja2 template injection and remote code execution (CWE-79 / CWE-1336).",
                            "Use render_template() with static template files instead of evaluating dynamic strings.",
                            0.99
                    ));
                }
            }

            // XSS via flask.Markup / Markup
            if ("Markup".equals(shortCallee) || fullCallee.endsWith(".Markup")) {
                List<PythonAstNode> posArgs = call.getPositionalArguments();
                if (!posArgs.isEmpty() && !(posArgs.get(0) instanceof PythonLiteralExpr lit && lit.getKind() == PythonLiteralExpr.Kind.STRING)) {
                    findings.add(createFinding(
                            SecurityRule.XSS,
                            Severity.HIGH,
                            filePath,
                            "FlaskModule",
                            "Markup",
                            call.getLine(),
                            call.getLine(),
                            call.getRawText(),
                            "Cross-Site Scripting (XSS) via Flask Markup()",
                            "Unsanitized user content marked as safe HTML via Markup() bypasses Jinja2 auto-escaping (CWE-79).",
                            "Ensure content passed to Markup() is strictly sanitized using an HTML sanitizer or escape().",
                            0.95
                    ));
                }
            }
        }

        // Flask configuration checks (DEBUG = True)
        for (PythonAssignStmt assign : module.findAllAssignments()) {
            String raw = assign.getRawText();
            if ((raw.contains("app.config['DEBUG']") || raw.contains("app.config[\"DEBUG\"]") || raw.contains("app.debug"))
                    && raw.matches(".*=\\s*True.*")) {
                findings.add(createFinding(
                        SecurityRule.FAIL_OPEN_SECURITY,
                        Severity.HIGH,
                        filePath,
                        "FlaskConfig",
                        "config",
                        assign.getLine(),
                        assign.getLine(),
                        assign.getRawText(),
                        "Flask Debug Mode Enabled in Production Configuration",
                        "Running Flask with debug enabled exposes interactive Werkzeug debugger enabling arbitrary code execution (CWE-489).",
                        "Disable debug mode in production: set DEBUG = False.",
                        0.98
                ));
            }
        }
    }

    private void evaluateDjango(PythonModule module, String filePath, List<SecurityFinding> findings) {
        for (PythonCallExpr call : module.findAllCalls()) {
            String fullCallee = call.getFullCalleeName();
            String shortCallee = call.getCalleeName();

            // Django mark_safe XSS
            if ("mark_safe".equals(shortCallee) || fullCallee.endsWith(".mark_safe")) {
                List<PythonAstNode> posArgs = call.getPositionalArguments();
                if (!posArgs.isEmpty() && !(posArgs.get(0) instanceof PythonLiteralExpr lit && lit.getKind() == PythonLiteralExpr.Kind.STRING)) {
                    findings.add(createFinding(
                            SecurityRule.XSS,
                            Severity.HIGH,
                            filePath,
                            "DjangoView",
                            "mark_safe",
                            call.getLine(),
                            call.getLine(),
                            call.getRawText(),
                            "Cross-Site Scripting (XSS) via Django mark_safe()",
                            "Directly marking dynamic untrusted string as safe HTML disables Django template escaping (CWE-79).",
                            "Sanitize user input using bleach or html.escape before passing to mark_safe().",
                            0.96
                    ));
                }
            }

            // Django raw SQL: Model.objects.raw(sql) with dynamic string
            if ("raw".equals(shortCallee) && fullCallee.contains(".raw")) {
                List<PythonAstNode> posArgs = call.getPositionalArguments();
                if (!posArgs.isEmpty()) {
                    PythonAstNode queryArg = posArgs.get(0);
                    if (queryArg instanceof PythonBinaryExpr || (queryArg instanceof PythonLiteralExpr lit && lit.getKind() == PythonLiteralExpr.Kind.FSTRING)) {
                        findings.add(createFinding(
                                SecurityRule.SQL_INJECTION,
                                Severity.CRITICAL,
                                filePath,
                                "DjangoModel",
                                "raw",
                                call.getLine(),
                                call.getLine(),
                                call.getRawText(),
                                "SQL Injection in Django Model.objects.raw()",
                                "Raw SQL query constructed with dynamic string interpolation passed to Django ORM (CWE-89).",
                                "Use parameterized query placeholders and pass parameters via the params argument: Model.objects.raw(sql, [params]).",
                                0.98
                        ));
                    }
                }
            }
        }

        // Django settings.py checks: ALLOWED_HOSTS = ['*'], DEBUG = True
        boolean isSettingsFile = filePath.toLowerCase(Locale.ROOT).contains("setting");
        for (PythonAssignStmt assign : module.findAllAssignments()) {
            for (String target : assign.getTargets()) {
                if ("ALLOWED_HOSTS".equals(target)) {
                    String rawVal = assign.getValue() != null ? assign.getValue().getRawText() : "";
                    if (rawVal.contains("'*'") || rawVal.contains("\"*\"")) {
                        findings.add(createFinding(
                                SecurityRule.FAIL_OPEN_SECURITY,
                                Severity.HIGH,
                                filePath,
                                "DjangoSettings",
                                "ALLOWED_HOSTS",
                                assign.getLine(),
                                assign.getLine(),
                                assign.getRawText(),
                                "Django Permissive ALLOWED_HOSTS Wildcard",
                                "Setting ALLOWED_HOSTS = ['*'] allows HTTP Host header poisoning and cache poisoning attacks (CWE-942).",
                                "Explicitly list allowed domain names in ALLOWED_HOSTS.",
                                0.95
                        ));
                    }
                }

                if (isSettingsFile && "DEBUG".equals(target)) {
                    String rawVal = assign.getValue() != null ? assign.getValue().getRawText() : "";
                    if ("True".equals(rawVal.trim())) {
                        findings.add(createFinding(
                                SecurityRule.FAIL_OPEN_SECURITY,
                                Severity.HIGH,
                                filePath,
                                "DjangoSettings",
                                "DEBUG",
                                assign.getLine(),
                                assign.getLine(),
                                assign.getRawText(),
                                "Django DEBUG Enabled in Settings",
                                "DEBUG = True leaks sensitive stack traces, database schema, and settings details to users upon unhandled exceptions (CWE-489).",
                                "Ensure DEBUG is configured as False for production environments.",
                                0.97
                        ));
                    }
                }
            }
        }
    }

    private void evaluateFastApi(PythonModule module, String filePath, List<SecurityFinding> findings) {
        for (PythonCallExpr call : module.findAllCalls()) {
            String fullCallee = call.getFullCalleeName();

            // FastAPI CORS middleware: allow_origins=["*"] with allow_credentials=True
            if (fullCallee.contains("add_middleware") || fullCallee.contains("CORSMiddleware")) {
                PythonAstNode origins = call.getKeywordArgument("allow_origins");
                PythonAstNode creds = call.getKeywordArgument("allow_credentials");

                boolean wildcardOrigins = origins != null && (origins.getRawText().contains("'*'") || origins.getRawText().contains("\"*\""));
                boolean allowCreds = creds != null && "True".equalsIgnoreCase(creds.getRawText().trim());

                if (wildcardOrigins && allowCreds) {
                    findings.add(createFinding(
                            SecurityRule.SPRING_PERMISSIVE_CORS,
                            Severity.HIGH,
                            filePath,
                            "FastAPIMiddleware",
                            "CORSMiddleware",
                            call.getLine(),
                            call.getLine(),
                            call.getRawText(),
                            "Overly Permissive FastAPI CORS with Credentials",
                            "CORS policy allowing wildcard origins ['*'] alongside allow_credentials=True enables cross-origin credential leakage (CWE-942).",
                            "Specify explicit origins instead of wildcard '*' when credentials are enabled.",
                            0.97
                    ));
                }
            }
        }
    }

    private SecurityFinding createFinding(
            SecurityRule rule,
            Severity severity,
            String filePath,
            String className,
            String methodName,
            int startLine,
            int endLine,
            String codeSnippet,
            String title,
            String rationale,
            String remediation,
            double confidence
    ) {
        return new SecurityFinding(
                "FND-" + UUID.randomUUID().toString().substring(0, 8),
                rule,
                severity,
                filePath,
                className != null && !className.isBlank() ? className : "Module",
                methodName != null && !methodName.isBlank() ? methodName : "moduleScope",
                startLine,
                endLine,
                codeSnippet,
                title,
                rationale,
                remediation,
                confidence
        );
    }
}
