package com.sentinelpr.core.analysis;

import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.Parameter;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.AssignExpr;
import com.github.javaparser.ast.expr.BinaryExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.NameExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.github.javaparser.ast.stmt.BlockStmt;
import com.github.javaparser.ast.stmt.ExpressionStmt;
import com.github.javaparser.ast.stmt.IfStmt;
import com.github.javaparser.ast.stmt.ReturnStmt;
import com.github.javaparser.ast.stmt.Statement;
import com.sentinelpr.core.analysis.taint.TaintFlow;
import com.sentinelpr.core.analysis.taint.TaintSink;
import com.sentinelpr.core.analysis.taint.TaintSource;
import com.sentinelpr.core.model.InspectedSource;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * <b>DataflowTracker</b>
 *
 * <p>Intra-procedural taint and dataflow analysis engine for SentinelPR. Tracks untrusted sources
 * (method parameters, HTTP inputs), propagation through assignments and method calls, sanitizers,
 * and reaches to sensitive sinks (command execution, file I/O, raw SQL).</p>
 */
public class DataflowTracker {

    private static final Set<String> HTTP_INPUT_METHODS = Set.of(
            "getParameter", "getHeader", "getQueryString", "getInputStream", "getReader", "getPart", "getCookies"
    );

    private static final Set<String> SINK_METHODS = Set.of(
            "exec", "executeQuery", "executeUpdate", "execute", "prepareStatement"
    );

    private static final Set<String> SINK_OBJECTS = Set.of(
            "ProcessBuilder", "FileInputStream", "FileOutputStream", "FileReader", "FileWriter"
    );

    /**
     * Analyzes all methods in an inspected source for taint flows.
     */
    public List<TaintFlow> analyze(InspectedSource source) {
        List<TaintFlow> allFlows = new ArrayList<>();
        if (source == null || source.getMethods() == null) {
            return allFlows;
        }

        String pathStr = source.getFilePath() != null ? source.getFilePath().toString() : "UnknownSource.java";
        for (MethodDeclaration method : source.getMethods()) {
            allFlows.addAll(analyzeMethod(method, pathStr));
        }
        return allFlows;
    }

    /**
     * Analyzes a single method declaration for intra-procedural taint flows.
     */
    public List<TaintFlow> analyzeMethod(MethodDeclaration method, String filePath) {
        List<TaintFlow> flows = new ArrayList<>();
        if (method == null || method.getBody().isEmpty()) {
            return flows;
        }

        BlockStmt body = method.getBody().get();

        // 1. Initialize tainted variables with method parameters
        Map<String, TaintSource> activeTaint = new HashMap<>();
        Map<String, List<String>> propagationHistory = new HashMap<>();
        Set<String> sanitizedVars = new HashSet<>();

        for (Parameter param : method.getParameters()) {
            String paramName = param.getNameAsString();
            int line = param.getBegin().map(p -> p.line).orElse(0);
            TaintSource source = new TaintSource(
                    paramName,
                    TaintSource.SourceType.METHOD_PARAMETER,
                    line,
                    param.toString()
            );
            activeTaint.put(paramName, source);
            propagationHistory.put(paramName, new ArrayList<>());
        }

        // 2. Walk statements in order
        for (Statement stmt : body.getStatements()) {
            processStatement(stmt, activeTaint, propagationHistory, sanitizedVars, flows);
        }

        return flows;
    }

    private void processStatement(
            Statement stmt,
            Map<String, TaintSource> activeTaint,
            Map<String, List<String>> propagationHistory,
            Set<String> sanitizedVars,
            List<TaintFlow> flows
    ) {
        // Detect sanitizers in conditional guards: if (isValid(x)) or if (!validate(x)) ...
        if (stmt instanceof IfStmt ifStmt) {
            Expression condition = ifStmt.getCondition();
            checkSanitizerInExpression(condition, activeTaint, sanitizedVars);
        }

        // Variable declarations: String cmd = prefix + userInput;
        List<VariableDeclarator> varDecls = stmt.findAll(VariableDeclarator.class);
        for (VariableDeclarator varDecl : varDecls) {
            String targetVar = varDecl.getNameAsString();
            varDecl.getInitializer().ifPresent(initExpr -> {
                // Check if init expression is an untrusted source directly (e.g. request.getParameter)
                TaintSource directSource = detectDirectSource(initExpr);
                if (directSource != null) {
                    activeTaint.put(targetVar, directSource);
                    propagationHistory.put(targetVar, new ArrayList<>(List.of(targetVar)));
                    return;
                }

                // Check if init expression references any active taint
                Set<String> referencedTaint = findReferencedTaint(initExpr, activeTaint.keySet());
                if (!referencedTaint.isEmpty()) {
                    boolean isSanitized = isExpressionSanitized(initExpr) || isAnySanitized(referencedTaint, sanitizedVars);
                    if (isSanitized) {
                        sanitizedVars.add(targetVar);
                    }

                    // Propagate taint from the first matching source
                    String parentTaint = referencedTaint.iterator().next();
                    TaintSource originalSource = activeTaint.get(parentTaint);
                    activeTaint.put(targetVar, originalSource);

                    List<String> history = new ArrayList<>(propagationHistory.getOrDefault(parentTaint, List.of()));
                    history.add(targetVar);
                    propagationHistory.put(targetVar, history);
                }
            });
        }

        // Assignment expressions: cmd = sanitize(cmd) or cmd = cmd + " arg";
        List<AssignExpr> assignExprs = stmt.findAll(AssignExpr.class);
        for (AssignExpr assign : assignExprs) {
            if (assign.getTarget() instanceof NameExpr targetName) {
                String targetVar = targetName.getNameAsString();
                Expression valueExpr = assign.getValue();

                // Check if assignment is sanitizing the variable
                if (isExpressionSanitized(valueExpr)) {
                    sanitizedVars.add(targetVar);
                }

                Set<String> referencedTaint = findReferencedTaint(valueExpr, activeTaint.keySet());
                if (!referencedTaint.isEmpty()) {
                    String parentTaint = referencedTaint.iterator().next();
                    TaintSource originalSource = activeTaint.get(parentTaint);
                    activeTaint.put(targetVar, originalSource);

                    List<String> history = new ArrayList<>(propagationHistory.getOrDefault(parentTaint, List.of()));
                    history.add(targetVar + " (assign)");
                    propagationHistory.put(targetVar, history);
                }
            }
        }

        // Check standalone sanitizer calls: validate(cmd); or checkNotNull(cmd);
        List<MethodCallExpr> methodCalls = stmt.findAll(MethodCallExpr.class);
        for (MethodCallExpr call : methodCalls) {
            String callName = call.getNameAsString().toLowerCase(Locale.ROOT);
            if (isSanitizerName(callName)) {
                for (Expression arg : call.getArguments()) {
                    if (arg instanceof NameExpr argName) {
                        sanitizedVars.add(argName.getNameAsString());
                    }
                }
            }
        }

        // Check Sinks: ProcessBuilder, Runtime.exec, FileInputStream, SQL
        checkSinks(stmt, activeTaint, propagationHistory, sanitizedVars, flows);
    }

    private void checkSinks(
            Statement stmt,
            Map<String, TaintSource> activeTaint,
            Map<String, List<String>> propagationHistory,
            Set<String> sanitizedVars,
            List<TaintFlow> flows
    ) {
        // 1. Method call sinks: exec(...), executeQuery(...), etc.
        List<MethodCallExpr> calls = stmt.findAll(MethodCallExpr.class);
        for (MethodCallExpr call : calls) {
            String methodName = call.getNameAsString();
            boolean isExec = "exec".equals(methodName) && call.getScope().map(s -> s.toString().contains("Runtime")).orElse(false);
            boolean isSql = SINK_METHODS.contains(methodName);

            if (isExec || isSql) {
                TaintSink.SinkType sinkType = isExec ? TaintSink.SinkType.COMMAND_EXECUTION : TaintSink.SinkType.RAW_SQL;
                int line = call.getBegin().map(p -> p.line).orElse(0);

                for (Expression arg : call.getArguments()) {
                    Set<String> referencedTaint = findReferencedTaint(arg, activeTaint.keySet());
                    for (String taintVar : referencedTaint) {
                        TaintSource source = activeTaint.get(taintVar);
                        boolean isSanitized = sanitizedVars.contains(taintVar) || isExpressionSanitized(arg);
                        String sanitizer = isSanitized ? "Sanitization Routine" : null;

                        TaintSink sink = new TaintSink(sinkType, call.toString(), line, call.toString());
                        List<String> steps = new ArrayList<>(propagationHistory.getOrDefault(taintVar, List.of()));

                        flows.add(new TaintFlow(source, sink, steps, isSanitized, sanitizer));
                    }
                }
            }
        }

        // 2. Object creation sinks: new ProcessBuilder(...), new FileInputStream(...)
        List<ObjectCreationExpr> creations = stmt.findAll(ObjectCreationExpr.class);
        for (ObjectCreationExpr creation : creations) {
            String typeName = creation.getTypeAsString();
            if (SINK_OBJECTS.contains(typeName)) {
                TaintSink.SinkType sinkType = "ProcessBuilder".equals(typeName)
                        ? TaintSink.SinkType.COMMAND_EXECUTION
                        : TaintSink.SinkType.FILE_IO;
                int line = creation.getBegin().map(p -> p.line).orElse(0);

                for (Expression arg : creation.getArguments()) {
                    Set<String> referencedTaint = findReferencedTaint(arg, activeTaint.keySet());
                    for (String taintVar : referencedTaint) {
                        TaintSource source = activeTaint.get(taintVar);
                        boolean isSanitized = sanitizedVars.contains(taintVar) || isExpressionSanitized(arg);
                        String sanitizer = isSanitized ? "Sanitization Routine" : null;

                        TaintSink sink = new TaintSink(sinkType, creation.toString(), line, creation.toString());
                        List<String> steps = new ArrayList<>(propagationHistory.getOrDefault(taintVar, List.of()));

                        flows.add(new TaintFlow(source, sink, steps, isSanitized, sanitizer));
                    }
                }
            }
        }
    }

    private TaintSource detectDirectSource(Expression expr) {
        if (expr instanceof MethodCallExpr call) {
            String methodName = call.getNameAsString();
            if (HTTP_INPUT_METHODS.contains(methodName)) {
                int line = call.getBegin().map(p -> p.line).orElse(0);
                return new TaintSource(methodName + "()", TaintSource.SourceType.HTTP_REQUEST, line, call.toString());
            }
        }
        return null;
    }

    private Set<String> findReferencedTaint(Expression expr, Set<String> activeTaintedVars) {
        Set<String> found = new HashSet<>();
        List<NameExpr> names = expr.findAll(NameExpr.class);
        for (NameExpr name : names) {
            String varName = name.getNameAsString();
            if (activeTaintedVars.contains(varName)) {
                found.add(varName);
            }
        }
        return found;
    }

    private boolean isExpressionSanitized(Expression expr) {
        if (expr instanceof MethodCallExpr call) {
            String methodName = call.getNameAsString().toLowerCase(Locale.ROOT);
            return isSanitizerName(methodName);
        }
        return false;
    }

    private boolean isSanitizerName(String name) {
        String lower = name.toLowerCase(Locale.ROOT);
        return lower.contains("sanitize")
                || lower.contains("validate")
                || lower.contains("clean")
                || lower.contains("escape")
                || lower.contains("encode")
                || lower.contains("filter")
                || lower.contains("whitelist")
                || lower.contains("isvalid")
                || lower.contains("check");
    }

    private boolean isAnySanitized(Set<String> vars, Set<String> sanitizedVars) {
        for (String v : vars) {
            if (sanitizedVars.contains(v)) {
                return true;
            }
        }
        return false;
    }

    private void checkSanitizerInExpression(Expression expr, Map<String, TaintSource> activeTaint, Set<String> sanitizedVars) {
        List<MethodCallExpr> calls = expr.findAll(MethodCallExpr.class);
        for (MethodCallExpr call : calls) {
            if (isSanitizerName(call.getNameAsString())) {
                for (Expression arg : call.getArguments()) {
                    if (arg instanceof NameExpr name) {
                        sanitizedVars.add(name.getNameAsString());
                    }
                }
            }
        }
    }
}
