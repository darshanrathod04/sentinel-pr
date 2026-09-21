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

    private static final Set<String> SQL_SINK_METHODS = Set.of(
            "executeQuery", "executeUpdate", "execute", "prepareStatement",
            "createQuery", "createNativeQuery", "query", "update", "queryForList",
            "queryForObject", "queryForMap", "queryForRowSet", "prepareCall"
    );

    private static final Set<String> SINK_OBJECTS = Set.of(
            "ProcessBuilder", "FileInputStream", "FileOutputStream", "FileReader", "FileWriter",
            "File", "RandomAccessFile"
    );

    /**
     * Analyzes all methods in an inspected source for taint flows.
     */
    public List<TaintFlow> analyze(InspectedSource source) {
        return analyze(source, List.of(source));
    }

    /**
     * Analyzes all methods in an inspected source with cross-file context awareness.
     */
    public List<TaintFlow> analyze(InspectedSource source, List<InspectedSource> contextSources) {
        List<TaintFlow> allFlows = new ArrayList<>();
        if (source == null || source.getMethods() == null) {
            return allFlows;
        }

        String pathStr = source.getFilePath() != null ? source.getFilePath().toString() : "UnknownSource.java";
        List<InspectedSource> effectiveContext = (contextSources != null && !contextSources.isEmpty())
                ? contextSources
                : List.of(source);

        for (MethodDeclaration method : source.getMethods()) {
            allFlows.addAll(analyzeMethod(method, pathStr, effectiveContext));
        }
        return allFlows;
    }

    /**
     * Analyzes a single method declaration for intra-procedural taint flows.
     */
    public List<TaintFlow> analyzeMethod(MethodDeclaration method, String filePath) {
        return analyzeMethod(method, filePath, List.of());
    }

    /**
     * Analyzes a single method declaration with cross-file inter-procedural taint flows.
     */
    public List<TaintFlow> analyzeMethod(
            MethodDeclaration method,
            String filePath,
            List<InspectedSource> contextSources
    ) {
        return analyzeMethodInternal(method, filePath, contextSources, new HashSet<>(), null, null, null);
    }

    private List<TaintFlow> analyzeMethodInternal(
            MethodDeclaration method,
            String filePath,
            List<InspectedSource> contextSources,
            Set<String> callStack,
            TaintSource initialSource,
            List<String> initialHistory,
            String seededParamName
    ) {
        List<TaintFlow> flows = new ArrayList<>();
        if (method == null || method.getBody().isEmpty()) {
            return flows;
        }

        BlockStmt body = method.getBody().get();
        String className = method.findAncestor(com.github.javaparser.ast.body.ClassOrInterfaceDeclaration.class)
                .map(com.github.javaparser.ast.body.ClassOrInterfaceDeclaration::getNameAsString)
                .orElse(extractClassNameFromPath(filePath));

        String methodSig = className + "#" + method.getNameAsString();
        if (callStack.contains(methodSig) || callStack.size() >= 5) {
            return flows;
        }
        Set<String> currentCallStack = new HashSet<>(callStack);
        currentCallStack.add(methodSig);

        // 1. Initialize tainted variables with method parameters
        Map<String, TaintSource> activeTaint = new HashMap<>();
        Map<String, List<String>> propagationHistory = new HashMap<>();
        Set<String> sanitizedVars = new HashSet<>();

        if (initialSource != null && !method.getParameters().isEmpty()) {
            Parameter targetParam = method.getParameters().stream()
                    .filter(p -> seededParamName != null && p.getNameAsString().equals(seededParamName))
                    .findFirst()
                    .orElse(method.getParameter(0));
            String paramName = targetParam.getNameAsString();
            activeTaint.put(paramName, initialSource);
            propagationHistory.put(paramName, new ArrayList<>(initialHistory != null ? initialHistory : List.of()));
        } else {
            for (Parameter param : method.getParameters()) {
                String paramName = param.getNameAsString();
                int line = param.getBegin().map(p -> p.line).orElse(0);
                String qualifiedName = className + "." + method.getNameAsString() + "(" + paramName + ")";
                TaintSource source = new TaintSource(
                        paramName,
                        qualifiedName,
                        TaintSource.SourceType.METHOD_PARAMETER,
                        line,
                        param.toString()
                );
                activeTaint.put(paramName, source);
                propagationHistory.put(paramName, new ArrayList<>());
            }
        }

        // 2. Walk statements in order
        for (Statement stmt : body.getStatements()) {
            processStatement(stmt, activeTaint, propagationHistory, sanitizedVars, flows, contextSources, currentCallStack, className);
        }

        return flows;
    }

    private void processStatement(
            Statement stmt,
            Map<String, TaintSource> activeTaint,
            Map<String, List<String>> propagationHistory,
            Set<String> sanitizedVars,
            List<TaintFlow> flows,
            List<InspectedSource> contextSources,
            Set<String> callStack,
            String currentClassName
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

                // Check return-value propagation from method call
                if (initExpr instanceof MethodCallExpr call) {
                    MethodCallTaintResult callTaint = checkMethodCallReturnTaint(call, activeTaint, propagationHistory, contextSources);
                    if (callTaint != null) {
                        activeTaint.put(targetVar, callTaint.source);
                        List<String> hist = new ArrayList<>(callTaint.history);
                        hist.add(targetVar);
                        propagationHistory.put(targetVar, hist);
                        return;
                    }
                }

                // Check if init expression references any active taint (local vars or fields)
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

        // Assignment expressions: cmd = sanitize(cmd) or this.query = cmd + " arg";
        List<AssignExpr> assignExprs = stmt.findAll(AssignExpr.class);
        for (AssignExpr assign : assignExprs) {
            String targetVar = null;
            String fieldAccessStr = null;

            if (assign.getTarget() instanceof NameExpr targetName) {
                targetVar = targetName.getNameAsString();
            } else if (assign.getTarget() instanceof com.github.javaparser.ast.expr.FieldAccessExpr fieldAccess) {
                targetVar = fieldAccess.getNameAsString();
                fieldAccessStr = fieldAccess.toString();
            }

            if (targetVar != null) {
                Expression valueExpr = assign.getValue();

                if (isExpressionSanitized(valueExpr)) {
                    sanitizedVars.add(targetVar);
                    if (fieldAccessStr != null) {
                        sanitizedVars.add(fieldAccessStr);
                    }
                }

                if (valueExpr instanceof MethodCallExpr call) {
                    MethodCallTaintResult callTaint = checkMethodCallReturnTaint(call, activeTaint, propagationHistory, contextSources);
                    if (callTaint != null) {
                        activeTaint.put(targetVar, callTaint.source);
                        List<String> hist = new ArrayList<>(callTaint.history);
                        hist.add(targetVar + " (assign)");
                        propagationHistory.put(targetVar, hist);
                        if (fieldAccessStr != null) {
                            activeTaint.put(fieldAccessStr, callTaint.source);
                            propagationHistory.put(fieldAccessStr, hist);
                        }
                        continue;
                    }
                }

                Set<String> referencedTaint = findReferencedTaint(valueExpr, activeTaint.keySet());
                if (!referencedTaint.isEmpty()) {
                    String parentTaint = referencedTaint.iterator().next();
                    TaintSource originalSource = activeTaint.get(parentTaint);
                    activeTaint.put(targetVar, originalSource);

                    List<String> history = new ArrayList<>(propagationHistory.getOrDefault(parentTaint, List.of()));
                    history.add(targetVar + " (assign)");
                    propagationHistory.put(targetVar, history);

                    if (fieldAccessStr != null) {
                        activeTaint.put(fieldAccessStr, originalSource);
                        propagationHistory.put(fieldAccessStr, history);
                    }
                }
            }
        }

        // Inter-procedural calls: check if method calls pass tainted arguments into other methods reaching sinks
        List<MethodCallExpr> methodCalls = stmt.findAll(MethodCallExpr.class);
        for (MethodCallExpr call : methodCalls) {
            String callName = call.getNameAsString().toLowerCase(Locale.ROOT);
            if (isSanitizerName(callName)) {
                for (Expression arg : call.getArguments()) {
                    if (arg instanceof NameExpr argName) {
                        sanitizedVars.add(argName.getNameAsString());
                    }
                }
            } else if (contextSources != null && !contextSources.isEmpty()) {
                // Inter-procedural taint propagation across method boundaries
                for (int i = 0; i < call.getArguments().size(); i++) {
                    Expression arg = call.getArgument(i);
                    Set<String> refTaint = findReferencedTaint(arg, activeTaint.keySet());
                    if (!refTaint.isEmpty()) {
                        String parentVar = refTaint.iterator().next();
                        TaintSource origSource = activeTaint.get(parentVar);
                        MethodDeclaration calleeMethod = resolveMethod(call, contextSources);
                        if (calleeMethod != null && calleeMethod.getBody().isPresent() && i < calleeMethod.getParameters().size()) {
                            String calleeClass = getMethodClassName(calleeMethod, "CalleeService");
                            String calleeSig = calleeClass + "#" + calleeMethod.getNameAsString();
                            if (!callStack.contains(calleeSig) && callStack.size() < 5) {
                                String calleeParam = calleeMethod.getParameter(i).getNameAsString();
                                List<String> calleeHistory = new ArrayList<>(propagationHistory.getOrDefault(parentVar, List.of()));
                                calleeHistory.add(calleeClass + "." + calleeMethod.getNameAsString() + "(" + calleeParam + ")");

                                List<TaintFlow> interFlows = analyzeMethodInternal(
                                        calleeMethod,
                                        calleeClass + ".java",
                                        contextSources,
                                        callStack,
                                        origSource,
                                        calleeHistory,
                                        calleeParam
                                );
                                flows.addAll(interFlows);
                            }
                        }
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
            boolean isSql = SQL_SINK_METHODS.contains(methodName);
            boolean isPathMethod = ("of".equals(methodName) || "get".equals(methodName))
                    && call.getScope().map(s -> s.toString().contains("Path")).orElse(false);

            if (isExec || isSql || isPathMethod) {
                TaintSink.SinkType sinkType = isExec ? TaintSink.SinkType.COMMAND_EXECUTION
                        : (isSql ? TaintSink.SinkType.RAW_SQL : TaintSink.SinkType.FILE_IO);
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

    private static class MethodCallTaintResult {
        final TaintSource source;
        final List<String> history;

        MethodCallTaintResult(TaintSource source, List<String> history) {
            this.source = source;
            this.history = history;
        }
    }

    private MethodCallTaintResult checkMethodCallReturnTaint(
            MethodCallExpr call,
            Map<String, TaintSource> activeTaint,
            Map<String, List<String>> propagationHistory,
            List<InspectedSource> contextSources
    ) {
        if (contextSources == null || contextSources.isEmpty()) {
            return null;
        }

        for (int i = 0; i < call.getArguments().size(); i++) {
            Expression arg = call.getArgument(i);
            Set<String> refTaint = findReferencedTaint(arg, activeTaint.keySet());
            if (!refTaint.isEmpty()) {
                String parentTaint = refTaint.iterator().next();
                TaintSource origSource = activeTaint.get(parentTaint);
                MethodDeclaration md = resolveMethod(call, contextSources);
                if (md != null && methodReturnsParameter(md, i)) {
                    String targetClass = getMethodClassName(md, "Unknown");
                    String paramName = md.getParameter(i).getNameAsString();
                    List<String> hist = new ArrayList<>(propagationHistory.getOrDefault(parentTaint, List.of()));
                    hist.add(targetClass + "." + md.getNameAsString() + "(" + paramName + ")");
                    return new MethodCallTaintResult(origSource, hist);
                }
            }
        }
        return null;
    }

    private MethodDeclaration resolveMethod(MethodCallExpr call, List<InspectedSource> contextSources) {
        if (contextSources == null) return null;
        String methodName = call.getNameAsString();
        int argCount = call.getArguments().size();
        String scopeStr = call.getScope().map(Expression::toString).orElse("");

        // First attempt: match by scope and method name
        for (InspectedSource cs : contextSources) {
            String className = cs.getPrimaryClassName();
            boolean scopeMatches = scopeStr.isBlank()
                    || (className != null && (className.equalsIgnoreCase(scopeStr)
                    || className.toLowerCase(Locale.ROOT).contains(scopeStr.toLowerCase(Locale.ROOT))
                    || scopeStr.toLowerCase(Locale.ROOT).contains(className.toLowerCase(Locale.ROOT))));

            if (scopeMatches && cs.getMethods() != null) {
                for (MethodDeclaration md : cs.getMethods()) {
                    if (md.getNameAsString().equals(methodName) && md.getParameters().size() == argCount) {
                        return md;
                    }
                }
            }
        }

        // Second attempt: match by method name and parameter count
        for (InspectedSource cs : contextSources) {
            if (cs.getMethods() != null) {
                for (MethodDeclaration md : cs.getMethods()) {
                    if (md.getNameAsString().equals(methodName) && md.getParameters().size() == argCount) {
                        return md;
                    }
                }
            }
        }

        return null;
    }

    private boolean methodReturnsParameter(MethodDeclaration md, int paramIdx) {
        if (md.getBody().isEmpty() || paramIdx < 0 || paramIdx >= md.getParameters().size()) {
            return false;
        }
        String paramName = md.getParameter(paramIdx).getNameAsString();
        BlockStmt body = md.getBody().get();
        Set<String> taintedInMethod = new HashSet<>();
        taintedInMethod.add(paramName);

        for (Statement s : body.getStatements()) {
            for (VariableDeclarator vd : s.findAll(VariableDeclarator.class)) {
                if (vd.getInitializer().isPresent()) {
                    Set<String> ref = findReferencedTaint(vd.getInitializer().get(), taintedInMethod);
                    if (!ref.isEmpty()) {
                        taintedInMethod.add(vd.getNameAsString());
                    }
                }
            }
            for (AssignExpr ae : s.findAll(AssignExpr.class)) {
                Set<String> ref = findReferencedTaint(ae.getValue(), taintedInMethod);
                if (!ref.isEmpty()) {
                    if (ae.getTarget() instanceof NameExpr ne) {
                        taintedInMethod.add(ne.getNameAsString());
                    } else if (ae.getTarget() instanceof com.github.javaparser.ast.expr.FieldAccessExpr fae) {
                        taintedInMethod.add(fae.getNameAsString());
                        taintedInMethod.add(fae.toString());
                    }
                }
            }
        }

        List<ReturnStmt> returns = body.findAll(ReturnStmt.class);
        for (ReturnStmt ret : returns) {
            if (ret.getExpression().isPresent()) {
                Expression retExpr = ret.getExpression().get();
                Set<String> ref = findReferencedTaint(retExpr, taintedInMethod);
                if (!ref.isEmpty()) {
                    return true;
                }
                if (retExpr.toString().contains(paramName)) {
                    return true;
                }
            }
        }
        return false;
    }

    private String getMethodClassName(MethodDeclaration md, String defaultName) {
        return md.findAncestor(com.github.javaparser.ast.body.ClassOrInterfaceDeclaration.class)
                .map(com.github.javaparser.ast.body.ClassOrInterfaceDeclaration::getNameAsString)
                .orElse(defaultName);
    }

    private String extractClassNameFromPath(String filePath) {
        if (filePath == null || filePath.isBlank()) return "Unknown";
        String normalized = filePath.replace("\\", "/");
        int lastSlash = normalized.lastIndexOf('/');
        String filename = lastSlash >= 0 ? normalized.substring(lastSlash + 1) : normalized;
        if (filename.endsWith(".java")) {
            return filename.substring(0, filename.length() - 5);
        }
        return filename;
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
        List<com.github.javaparser.ast.expr.FieldAccessExpr> fieldAccesses = expr.findAll(com.github.javaparser.ast.expr.FieldAccessExpr.class);
        for (var fa : fieldAccesses) {
            String faStr = fa.toString();
            String faName = fa.getNameAsString();
            if (activeTaintedVars.contains(faStr)) {
                found.add(faStr);
            } else if (activeTaintedVars.contains(faName)) {
                found.add(faName);
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
                || lower.contains("check")
                || lower.contains("normalize")
                || lower.contains("canonical")
                || lower.contains("torealpath")
                || lower.contains("startswith")
                || lower.contains("setparameter")
                || lower.contains("setstring")
                || lower.contains("setint");
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
