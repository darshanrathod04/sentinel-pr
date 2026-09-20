package com.sentinelpr.client;

import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.FieldDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.Parameter;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.AssignExpr;
import com.github.javaparser.ast.expr.BinaryExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.NameExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.github.javaparser.ast.expr.StringLiteralExpr;
import com.github.javaparser.ast.expr.UnaryExpr;
import com.github.javaparser.ast.stmt.CatchClause;
import com.github.javaparser.ast.stmt.ReturnStmt;
import com.github.javaparser.ast.stmt.Statement;
import com.github.javaparser.ast.stmt.TryStmt;
import com.sentinelpr.core.analysis.DataflowTracker;
import com.sentinelpr.core.analysis.FrameworkContextAnalyzer;
import com.sentinelpr.core.analysis.SecretScanningEngine;
import com.sentinelpr.core.analysis.taint.TaintFlow;
import com.sentinelpr.core.model.InspectedSource;
import com.sentinelpr.core.model.SecurityFinding;
import com.sentinelpr.core.model.SecurityRule;
import com.sentinelpr.core.model.Severity;
import com.shreeai.os.platform.kernels.reasoning.engine.DefaultCausalReasoningEngine;
import com.shreeai.os.platform.sdk.ShreeAI;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * Reasoning facade providing cognitive AST rule evaluation and causal vulnerability analysis.
 */
public class ReasoningFacade {

    private final ShreeAI shreeAi;
    private final DefaultCausalReasoningEngine causalEngine;
    private final DataflowTracker dataflowTracker;
    private final SecretScanningEngine secretScanningEngine;
    private final FrameworkContextAnalyzer frameworkAnalyzer;

    private static final Set<String> STREAM_TYPES = Set.of(
            "FileInputStream", "FileOutputStream", "InputStream", "OutputStream",
            "FileReader", "FileWriter", "BufferedReader", "BufferedWriter",
            "BufferedInputStream", "BufferedOutputStream", "DataInputStream", "DataOutputStream"
    );

    private static final Set<String> FAIL_OPEN_EXCEPTIONS = Set.of(
            "NullPointerException", "Exception", "Throwable", "RuntimeException", "SecurityException"
    );

    public ReasoningFacade(ShreeAI shreeAi) {
        this(shreeAi, new DataflowTracker(), new SecretScanningEngine(), new FrameworkContextAnalyzer());
    }

    public ReasoningFacade(ShreeAI shreeAi, DataflowTracker dataflowTracker) {
        this(shreeAi, dataflowTracker, new SecretScanningEngine(), new FrameworkContextAnalyzer());
    }

    public ReasoningFacade(
            ShreeAI shreeAi,
            DataflowTracker dataflowTracker,
            SecretScanningEngine secretScanningEngine,
            FrameworkContextAnalyzer frameworkAnalyzer
    ) {
        this.shreeAi = Objects.requireNonNull(shreeAi, "shreeAi must not be null");
        this.causalEngine = new DefaultCausalReasoningEngine();
        this.dataflowTracker = Objects.requireNonNull(dataflowTracker, "dataflowTracker must not be null");
        this.secretScanningEngine = Objects.requireNonNull(secretScanningEngine, "secretScanningEngine must not be null");
        this.frameworkAnalyzer = Objects.requireNonNull(frameworkAnalyzer, "frameworkAnalyzer must not be null");
    }

    /**
     * Evaluates all security and architectural rules on the inspected source.
     */
    public List<SecurityFinding> evaluateAll(InspectedSource source) {
        List<SecurityFinding> findings = new ArrayList<>();
        findings.addAll(evaluateFailOpenSecurity(source));
        findings.addAll(evaluateUnclosedIoStreams(source));
        findings.addAll(evaluateVolatileCompoundOps(source));
        findings.addAll(evaluateSubprocessCalls(source));
        findings.addAll(evaluateSqlInjection(source));
        findings.addAll(evaluatePathTraversal(source));
        findings.addAll(evaluateInsecureDeserialization(source));
        findings.addAll(evaluateHardcodedSecrets(source));
        findings.addAll(evaluateSpringCsrfDisabled(source));
        findings.addAll(evaluateSpringPermissiveCors(source));
        return findings;
    }

    /**
     * Rule 1: Fail-open security blocks (e.g., catching NPE and granting access / returning true).
     */
    public List<SecurityFinding> evaluateFailOpenSecurity(InspectedSource source) {
        List<SecurityFinding> findings = new ArrayList<>();

        for (CatchClause catchClause : source.getCatchClauses()) {
            String exceptionType = catchClause.getParameter().getTypeAsString();
            boolean isTargetException = FAIL_OPEN_EXCEPTIONS.stream().anyMatch(exceptionType::contains);

            if (!isTargetException) {
                continue;
            }

            // Check if inside a method that returns boolean or has security-sensitive signature
            MethodDeclaration method = catchClause.findAncestor(MethodDeclaration.class).orElse(null);
            String methodName = method != null ? method.getNameAsString() : "unknownMethod";
            String returnType = method != null ? method.getTypeAsString() : "";

            boolean isSecurityContext = isSecurityMethodContext(methodName, returnType);

            // Check catch body statements
            List<ReturnStmt> returnStmts = catchClause.getBody().findAll(ReturnStmt.class);
            boolean returnsTrue = returnStmts.stream().anyMatch(ret ->
                    ret.getExpression().map(Expression::toString).filter("true"::equalsIgnoreCase).isPresent()
            );

            if (returnsTrue || (isSecurityContext && returnsAccessGranted(catchClause))) {
                int startLine = catchClause.getBegin().map(p -> p.line).orElse(0);
                int endLine = catchClause.getEnd().map(p -> p.line).orElse(0);
                String snippet = catchClause.toString();

                String rationale = String.format(
                        "Catching [%s] and returning true creates an exploitable fail-open bypass in '%s'. An unexpected error elevates privileges or authorizes unauthorized access.",
                        exceptionType, methodName
                );

                String remediation = "Fail securely by returning false, throwing an AccessDeniedException, or propagating a verified SecurityException.";

                findings.add(new SecurityFinding(
                        "FND-" + UUID.randomUUID().toString().substring(0, 8),
                        SecurityRule.FAIL_OPEN_SECURITY,
                        Severity.CRITICAL,
                        source.getFilePath() != null ? source.getFilePath().toString() : "UnknownSource.java",
                        source.getPrimaryClassName(),
                        methodName,
                        startLine,
                        endLine,
                        snippet,
                        "Fail-open security catch block grants access upon " + exceptionType,
                        rationale,
                        remediation,
                        0.98
                ));
            }
        }

        return findings;
    }

    /**
     * Rule 2: Unclosed I/O streams.
     */
    public List<SecurityFinding> evaluateUnclosedIoStreams(InspectedSource source) {
        List<SecurityFinding> findings = new ArrayList<>();

        for (ObjectCreationExpr creation : source.getObjectCreations()) {
            String typeName = creation.getTypeAsString();
            if (!STREAM_TYPES.contains(typeName)) {
                continue;
            }

            // Check if inside try-with-resources
            TryStmt tryStmt = creation.findAncestor(TryStmt.class).orElse(null);
            boolean inTryWithResources = false;
            if (tryStmt != null) {
                inTryWithResources = tryStmt.getResources().stream().anyMatch(res ->
                        res.isAncestorOf(creation) || res.toString().contains(creation.toString())
                );
            }

            if (inTryWithResources) {
                continue;
            }

            // Check if assigned to a local variable that is closed in a finally block
            VariableDeclarator varDecl = creation.findAncestor(VariableDeclarator.class).orElse(null);
            boolean closedInFinally = false;
            if (varDecl != null && tryStmt != null && tryStmt.getFinallyBlock().isPresent()) {
                String varName = varDecl.getNameAsString();
                List<MethodCallExpr> finallyCalls = tryStmt.getFinallyBlock().get().findAll(MethodCallExpr.class);
                closedInFinally = finallyCalls.stream().anyMatch(call ->
                        "close".equals(call.getNameAsString()) && call.getScope().map(s -> s.toString().equals(varName)).orElse(false)
                );
            }

            if (!closedInFinally) {
                int startLine = creation.getBegin().map(p -> p.line).orElse(0);
                int endLine = creation.getEnd().map(p -> p.line).orElse(0);
                MethodDeclaration method = creation.findAncestor(MethodDeclaration.class).orElse(null);
                String methodName = method != null ? method.getNameAsString() : "unknownMethod";

                String rationale = String.format(
                        "Stream [%s] allocated at line %d is not managed by try-with-resources. If an exception occurs, the operating system file descriptor remains open until GC, risking descriptor exhaustion under load.",
                        typeName, startLine
                );

                String remediation = "Enclose stream instantiation in a try-with-resources statement: try (" + typeName + " stream = ...) { ... }";

                findings.add(new SecurityFinding(
                        "FND-" + UUID.randomUUID().toString().substring(0, 8),
                        SecurityRule.UNCLOSED_IO_STREAM,
                        Severity.HIGH,
                        source.getFilePath() != null ? source.getFilePath().toString() : "UnknownSource.java",
                        source.getPrimaryClassName(),
                        methodName,
                        startLine,
                        endLine,
                        creation.toString(),
                        "Unclosed I/O resource stream detected: " + typeName,
                        rationale,
                        remediation,
                        0.95
                ));
            }
        }

        return findings;
    }

    /**
     * Rule 3: Volatile compound operations without atomics.
     */
    public List<SecurityFinding> evaluateVolatileCompoundOps(InspectedSource source) {
        List<SecurityFinding> findings = new ArrayList<>();

        Set<String> volatileFieldNames = new HashSet<>();
        for (FieldDeclaration field : source.getFields()) {
            if (field.isVolatile()) {
                field.getVariables().forEach(v -> volatileFieldNames.add(v.getNameAsString()));
            }
        }

        if (volatileFieldNames.isEmpty()) {
            return findings;
        }

        for (UnaryExpr unaryExpr : source.getUnaryExpressions()) {
            UnaryExpr.Operator op = unaryExpr.getOperator();
            if (op == UnaryExpr.Operator.POSTFIX_INCREMENT || op == UnaryExpr.Operator.PREFIX_INCREMENT
                    || op == UnaryExpr.Operator.POSTFIX_DECREMENT || op == UnaryExpr.Operator.PREFIX_DECREMENT) {
                if (unaryExpr.getExpression() instanceof NameExpr nameExpr) {
                    String varName = nameExpr.getNameAsString();
                    if (volatileFieldNames.contains(varName)) {
                        addVolatileCompoundFinding(source, findings, unaryExpr, varName, op.name());
                    }
                }
            }
        }

        for (AssignExpr assignExpr : source.getAssignExpressions()) {
            AssignExpr.Operator op = assignExpr.getOperator();
            if (op != AssignExpr.Operator.ASSIGN) {
                if (assignExpr.getTarget() instanceof NameExpr nameExpr) {
                    String varName = nameExpr.getNameAsString();
                    if (volatileFieldNames.contains(varName)) {
                        addVolatileCompoundFinding(source, findings, assignExpr, varName, op.name());
                    }
                }
            }
        }

        return findings;
    }

    /**
     * Rule 4: Un-isolated subprocess calls with taint tracking enrichment.
     */
    public List<SecurityFinding> evaluateSubprocessCalls(InspectedSource source) {
        List<SecurityFinding> findings = new ArrayList<>();
        String pathStr = source.getFilePath() != null ? source.getFilePath().toString() : "UnknownSource.java";

        for (MethodCallExpr call : source.getMethodCalls()) {
            boolean isRuntimeExec = "exec".equals(call.getNameAsString())
                    && call.getScope().map(s -> s.toString().contains("Runtime.getRuntime()")).orElse(false);

            if (isRuntimeExec) {
                int startLine = call.getBegin().map(p -> p.line).orElse(0);
                int endLine = call.getEnd().map(p -> p.line).orElse(0);
                MethodDeclaration method = call.findAncestor(MethodDeclaration.class).orElse(null);
                String methodName = method != null ? method.getNameAsString() : "unknownMethod";

                // Check for taint flow reaching this call
                String rationale = "Direct invocation of Runtime.getRuntime().exec without argument isolation or containerized sandbox presents command injection risks.";
                double confidence = 0.94;

                if (method != null) {
                    List<TaintFlow> flows = dataflowTracker.analyzeMethod(method, pathStr);
                    Optional<TaintFlow> matching = flows.stream()
                            .filter(f -> f.getSink().getLine() == startLine && !f.isSanitized())
                            .findFirst();

                    if (matching.isPresent()) {
                        rationale = "Taint trace: " + matching.get().formatTrace() + ". " + rationale;
                        confidence = 0.99;
                    }
                }

                findings.add(new SecurityFinding(
                        "FND-" + UUID.randomUUID().toString().substring(0, 8),
                        SecurityRule.UNISOLATED_SUBPROCESS,
                        Severity.CRITICAL,
                        source.getFilePath() != null ? source.getFilePath().toString() : "UnknownSource.java",
                        source.getPrimaryClassName(),
                        methodName,
                        startLine,
                        endLine,
                        call.toString(),
                        "Un-isolated Runtime.exec() call detected",
                        rationale,
                        "Use ProcessBuilder with explicit tokenized argument array and strict execution timeout.",
                        confidence
                ));
            }
        }

        return findings;
    }

    private void addVolatileCompoundFinding(
            InspectedSource source,
            List<SecurityFinding> findings,
            Node node,
            String varName,
            String opName
    ) {
        int startLine = node.getBegin().map(p -> p.line).orElse(0);
        int endLine = node.getEnd().map(p -> p.line).orElse(0);
        MethodDeclaration method = node.findAncestor(MethodDeclaration.class).orElse(null);
        String methodName = method != null ? method.getNameAsString() : "unknownMethod";

        String rationale = String.format(
                "Compound mutation '%s' on volatile variable '%s' at line %d is non-atomic. Volatile guarantees visibility, not mutual exclusion or atomic read-modify-write. Concurrent threads will drop updates.",
                node.toString(), varName, startLine
        );

        String remediation = String.format(
                "Replace 'volatile int %s' with 'java.util.concurrent.atomic.AtomicInteger %s = new AtomicInteger();' and use .incrementAndGet() / .decrementAndGet().",
                varName, varName
        );

        findings.add(new SecurityFinding(
                "FND-" + UUID.randomUUID().toString().substring(0, 8),
                SecurityRule.VOLATILE_COMPOUND_OP,
                Severity.HIGH,
                source.getFilePath() != null ? source.getFilePath().toString() : "UnknownSource.java",
                source.getPrimaryClassName(),
                methodName,
                startLine,
                endLine,
                node.toString(),
                "Non-atomic compound operation on volatile field: " + varName,
                rationale,
                remediation,
                0.97
        ));
    }

    private boolean isSecurityMethodContext(String methodName, String returnType) {
        String lower = methodName.toLowerCase(Locale.ROOT);
        return "boolean".equalsIgnoreCase(returnType)
                || lower.contains("auth")
                || lower.contains("security")
                || lower.contains("permission")
                || lower.contains("access")
                || lower.contains("check")
                || lower.contains("verify")
                || lower.contains("validate")
                || lower.contains("can");
    }

    private boolean returnsAccessGranted(CatchClause catchClause) {
        String body = catchClause.getBody().toString();
        return body.contains("return true") || body.contains("grantAccess") || body.contains("authorized = true");
    }

    // ─── Rule 5: SQL Injection (A03:2021-Injection) ─────────────────────────

    private static final Set<String> SQL_SINK_METHOD_NAMES = Set.of(
            "executeQuery", "executeUpdate", "execute", "prepareStatement", "prepareCall",
            "createQuery", "createNativeQuery", "query", "update", "queryForList",
            "queryForObject", "queryForMap", "queryForRowSet"
    );

    public List<SecurityFinding> evaluateSqlInjection(InspectedSource source) {
        List<SecurityFinding> findings = new ArrayList<>();
        String pathStr = source.getFilePath() != null ? source.getFilePath().toString() : "UnknownSource.java";

        for (MethodCallExpr call : source.getMethodCalls()) {
            String methodName = call.getNameAsString();
            if (!SQL_SINK_METHOD_NAMES.contains(methodName)) {
                continue;
            }

            if (call.getArguments().isEmpty()) {
                continue;
            }

            Expression sqlArg = call.getArgument(0);
            boolean isVulnerable = isConcatenatedOrFormatted(sqlArg, source);

            MethodDeclaration enclosingMethod = call.findAncestor(MethodDeclaration.class).orElse(null);
            String enclosingMethodName = enclosingMethod != null ? enclosingMethod.getNameAsString() : "unknownMethod";

            Optional<TaintFlow> matchingFlow = Optional.empty();
            if (enclosingMethod != null) {
                int callLine = call.getBegin().map(p -> p.line).orElse(0);
                List<TaintFlow> flows = dataflowTracker.analyzeMethod(enclosingMethod, pathStr);
                matchingFlow = flows.stream()
                        .filter(f -> f.getSink().getLine() == callLine && !f.isSanitized())
                        .findFirst();
                if (matchingFlow.isPresent()) {
                    isVulnerable = true;
                }
            }

            if (isVulnerable) {
                int startLine = call.getBegin().map(p -> p.line).orElse(0);
                int endLine = call.getEnd().map(p -> p.line).orElse(0);

                String rationale = "Dynamic SQL query constructed via un-parameterized concatenation or string formatting passed into SQL execution sink. Allows SQL injection (CWE-89 / OWASP A03:2021) enabling unauthorized data exfiltration, authentication bypass, or data tampering.";
                double confidence = 0.96;

                if (matchingFlow.isPresent()) {
                    rationale = "Taint trace: " + matchingFlow.get().formatTrace() + ". " + rationale;
                    confidence = 0.99;
                }

                String remediation = "Use parameterized queries with PreparedStatement placeholders ('?') or ORM bind parameters (e.g. :param) instead of raw string concatenation.";

                findings.add(new SecurityFinding(
                        "FND-" + UUID.randomUUID().toString().substring(0, 8),
                        SecurityRule.SQL_INJECTION,
                        Severity.CRITICAL,
                        pathStr,
                        source.getPrimaryClassName(),
                        enclosingMethodName,
                        startLine,
                        endLine,
                        call.toString(),
                        "SQL Injection vulnerability in " + methodName + "() call",
                        rationale,
                        remediation,
                        confidence
                ));
            }
        }

        return findings;
    }

    // ─── Rule 6: Path Traversal (A01:2021-Broken Access Control) ─────────────

    private static final Set<String> PATH_CONSTRUCTORS = Set.of(
            "File", "FileInputStream", "FileOutputStream", "FileReader", "FileWriter"
    );

    public List<SecurityFinding> evaluatePathTraversal(InspectedSource source) {
        List<SecurityFinding> findings = new ArrayList<>();
        String pathStr = source.getFilePath() != null ? source.getFilePath().toString() : "UnknownSource.java";

        // A. Object creations: new File(...), new FileInputStream(...), etc.
        for (ObjectCreationExpr creation : source.getObjectCreations()) {
            String typeName = creation.getTypeAsString();
            if (!PATH_CONSTRUCTORS.contains(typeName) || creation.getArguments().isEmpty()) {
                continue;
            }

            MethodDeclaration enclosingMethod = creation.findAncestor(MethodDeclaration.class).orElse(null);
            if (enclosingMethod == null || hasPathGuards(enclosingMethod)) {
                continue;
            }

            int line = creation.getBegin().map(p -> p.line).orElse(0);
            int endLine = creation.getEnd().map(p -> p.line).orElse(line);
            String methodName = enclosingMethod.getNameAsString();

            boolean hasDynamicArg = creation.getArguments().stream().anyMatch(arg -> !(arg instanceof StringLiteralExpr));
            boolean hasStringPath = hasStringPathArgument(creation.getArguments(), enclosingMethod);
            if (!hasDynamicArg || !hasStringPath) {
                continue;
            }

            List<TaintFlow> flows = dataflowTracker.analyzeMethod(enclosingMethod, pathStr);
            Optional<TaintFlow> matching = flows.stream()
                    .filter(f -> f.getSink().getLine() == line && !f.isSanitized())
                    .findFirst();

            String rationale = "User-controlled input flows directly into file/path constructor without path normalization (.normalize() / getCanonicalFile()) or directory containment checks. Enables Path Traversal (CWE-22 / OWASP A01:2021) allowing unauthorized filesystem access.";
            double confidence = 0.95;
            if (matching.isPresent()) {
                rationale = "Taint trace: " + matching.get().formatTrace() + ". " + rationale;
                confidence = 0.99;
            }

            findings.add(new SecurityFinding(
                    "FND-" + UUID.randomUUID().toString().substring(0, 8),
                    SecurityRule.PATH_TRAVERSAL,
                    Severity.CRITICAL,
                    pathStr,
                    source.getPrimaryClassName(),
                    methodName,
                    line,
                    endLine,
                    creation.toString(),
                    "Path Traversal vulnerability in " + typeName + " instantiation",
                    rationale,
                    "Canonicalize and normalize the path (.normalize() / getCanonicalFile()) and verify that the target path starts with the designated base directory.",
                    confidence
            ));
        }

        // B. Method calls: Path.of(...), Paths.get(...)
        for (MethodCallExpr call : source.getMethodCalls()) {
            String name = call.getNameAsString();
            if (("of".equals(name) || "get".equals(name)) && call.getScope().map(s -> s.toString().contains("Path")).orElse(false)) {
                MethodDeclaration enclosingMethod = call.findAncestor(MethodDeclaration.class).orElse(null);
                if (enclosingMethod == null || hasPathGuards(enclosingMethod)) {
                    continue;
                }

                boolean hasDynamicArg = call.getArguments().stream().anyMatch(arg -> !(arg instanceof StringLiteralExpr));
                boolean hasStringPath = hasStringPathArgument(call.getArguments(), enclosingMethod);
                if (!hasDynamicArg || !hasStringPath) {
                    continue;
                }

                int line = call.getBegin().map(p -> p.line).orElse(0);
                int endLine = call.getEnd().map(p -> p.line).orElse(line);
                String methodName = enclosingMethod.getNameAsString();

                List<TaintFlow> flows = dataflowTracker.analyzeMethod(enclosingMethod, pathStr);
                Optional<TaintFlow> matching = flows.stream()
                        .filter(f -> f.getSink().getLine() == line && !f.isSanitized())
                        .findFirst();

                String rationale = "User-controlled path input passed to Path." + name + "() without normalization (.normalize()) or directory containment validation (startsWith(baseDir)). Enables Path Traversal (CWE-22 / OWASP A01:2021).";
                double confidence = 0.95;
                if (matching.isPresent()) {
                    rationale = "Taint trace: " + matching.get().formatTrace() + ". " + rationale;
                    confidence = 0.99;
                }

                findings.add(new SecurityFinding(
                        "FND-" + UUID.randomUUID().toString().substring(0, 8),
                        SecurityRule.PATH_TRAVERSAL,
                        Severity.CRITICAL,
                        pathStr,
                        source.getPrimaryClassName(),
                        methodName,
                        line,
                        endLine,
                        call.toString(),
                        "Path Traversal vulnerability in Path." + name + "() call",
                        rationale,
                        "Normalize path via .normalize() and verify that the path starts with the trusted base directory.",
                        confidence
                ));
            }
        }

        return findings;
    }

    // ─── Rule 7: Insecure Deserialization (A08:2021) ─────────────────────────

    public List<SecurityFinding> evaluateInsecureDeserialization(InspectedSource source) {
        List<SecurityFinding> findings = new ArrayList<>();
        String pathStr = source.getFilePath() != null ? source.getFilePath().toString() : "UnknownSource.java";

        for (MethodCallExpr call : source.getMethodCalls()) {
            String name = call.getNameAsString();
            if ("readObject".equals(name) || "readUnshared".equals(name)) {
                MethodDeclaration method = call.findAncestor(MethodDeclaration.class).orElse(null);
                String methodName = method != null ? method.getNameAsString() : "unknownMethod";

                if (!hasDeserializationFilter(method, source)) {
                    int line = call.getBegin().map(p -> p.line).orElse(0);
                    int endLine = call.getEnd().map(p -> p.line).orElse(line);

                    findings.add(new SecurityFinding(
                            "FND-" + UUID.randomUUID().toString().substring(0, 8),
                            SecurityRule.INSECURE_DESERIALIZATION,
                            Severity.CRITICAL,
                            pathStr,
                            source.getPrimaryClassName(),
                            methodName,
                            line,
                            endLine,
                            call.toString(),
                            "Insecure Java deserialization: " + call.toString(),
                            "Invocation of ObjectInputStream.readObject() without an active ObjectInputFilter or LookAheadObjectInputStream. Untrusted Java deserialization can lead to arbitrary remote code execution (RCE) via gadget chains (CWE-502 / OWASP A08:2021).",
                            "Configure a strict ObjectInputFilter using stream.setObjectInputFilter(...) or migrate from Java native serialization to safe serialization formats like JSON (Jackson) or Protocol Buffers.",
                            0.98
                    ));
                }
            }
        }

        return findings;
    }

    // ─── Rule 8: Hardcoded Secrets (CWE-798) ─────────────────────────────────

    public List<SecurityFinding> evaluateHardcodedSecrets(InspectedSource source) {
        return secretScanningEngine.scan(source);
    }

    // ─── Rule 9: Spring CSRF Disabled (CWE-352) ──────────────────────────────

    public List<SecurityFinding> evaluateSpringCsrfDisabled(InspectedSource source) {
        return frameworkAnalyzer.evaluateCsrfDisabled(source);
    }

    // ─── Rule 10: Spring Permissive CORS (CWE-942) ───────────────────────────

    public List<SecurityFinding> evaluateSpringPermissiveCors(InspectedSource source) {
        return frameworkAnalyzer.evaluatePermissiveCors(source);
    }

    // ─── Helpers ─────────────────────────────────────────────────────────────

    private boolean isConcatenatedOrFormatted(Expression expr, InspectedSource source) {
        if (expr instanceof BinaryExpr binary && binary.getOperator() == BinaryExpr.Operator.PLUS) {
            return hasNonLiteralString(binary);
        }
        if (expr instanceof MethodCallExpr call) {
            String name = call.getNameAsString();
            if ("format".equals(name) || "formatted".equals(name)) {
                return true;
            }
        }
        if (expr instanceof NameExpr nameExpr) {
            String varName = nameExpr.getNameAsString();
            for (VariableDeclarator varDecl : source.getVariableDeclarations()) {
                if (varDecl.getNameAsString().equals(varName) && varDecl.getInitializer().isPresent()) {
                    if (isConcatenatedOrFormatted(varDecl.getInitializer().get(), source)) {
                        return true;
                    }
                }
            }
            for (AssignExpr assign : source.getAssignExpressions()) {
                if (assign.getTarget() instanceof NameExpr target && target.getNameAsString().equals(varName)) {
                    if (isConcatenatedOrFormatted(assign.getValue(), source)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private boolean hasNonLiteralString(BinaryExpr binary) {
        Expression left = binary.getLeft();
        Expression right = binary.getRight();
        if (left instanceof BinaryExpr subBinary && hasNonLiteralString(subBinary)) {
            return true;
        }
        if (right instanceof BinaryExpr subBinary && hasNonLiteralString(subBinary)) {
            return true;
        }
        return !(left instanceof StringLiteralExpr) || !(right instanceof StringLiteralExpr);
    }

    private boolean hasPathGuards(MethodDeclaration method) {
        if (method == null || method.getBody().isEmpty()) {
            return false;
        }
        String body = method.getBody().get().toString();
        return body.contains(".normalize()")
                || body.contains("getCanonicalPath()")
                || body.contains("getCanonicalFile()")
                || body.contains("toRealPath()")
                || (body.contains(".startsWith(") && (body.contains("base") || body.contains("root") || body.contains("Dir") || body.contains("Path")));
    }

    private boolean hasDeserializationFilter(MethodDeclaration method, InspectedSource source) {
        if (method != null && method.getBody().isPresent()) {
            String body = method.getBody().get().toString();
            if (body.contains("setObjectInputFilter") || body.contains("ObjectInputFilter")
                    || body.contains("LookAheadObjectInputStream") || body.contains("ValidatingObjectInputStream")) {
                return true;
            }
        }
        for (String imp : source.getImports()) {
            if (imp.contains("LookAheadObjectInputStream") || imp.contains("ValidatingObjectInputStream") || imp.contains("ObjectInputFilter")) {
                return true;
            }
        }
        return false;
    }

    private boolean hasStringPathArgument(List<Expression> args, MethodDeclaration method) {
        if (args == null || method == null) {
            return false;
        }
        for (Expression arg : args) {
            if (arg instanceof BinaryExpr binary && binary.getOperator() == BinaryExpr.Operator.PLUS) {
                return true;
            }
            if (arg instanceof NameExpr nameExpr) {
                String varName = nameExpr.getNameAsString();
                for (Parameter param : method.getParameters()) {
                    if (param.getNameAsString().equals(varName)) {
                        String type = param.getTypeAsString();
                        if ("String".equals(type) || "CharSequence".equals(type)) {
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }

    public DefaultCausalReasoningEngine getCausalEngine() {
        return causalEngine;
    }

    public DataflowTracker getDataflowTracker() {
        return dataflowTracker;
    }

    public SecretScanningEngine getSecretScanningEngine() {
        return secretScanningEngine;
    }

    public FrameworkContextAnalyzer getFrameworkAnalyzer() {
        return frameworkAnalyzer;
    }
}
