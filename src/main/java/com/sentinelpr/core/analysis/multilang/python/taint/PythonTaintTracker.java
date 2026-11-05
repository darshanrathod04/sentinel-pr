package com.sentinelpr.core.analysis.multilang.python.taint;

import com.sentinelpr.core.analysis.multilang.python.ast.*;

import java.util.*;
import java.util.regex.Pattern;

/**
 * <b>PythonTaintTracker</b>
 *
 * <p>Intra-procedural function-local taint analysis tracking untrusted sources
 * (HTTP requests, framework parameters, sys.argv) through multi-hop variable assignments,
 * string formatting/interpolations, recognizing sanitizers (shlex.quote, realpath, allowlists),
 * to vulnerable sinks.</p>
 */
public class PythonTaintTracker {

    public record TaintTrace(
            String sourceDescription,
            String sinkName,
            List<String> propagationChain,
            boolean isSanitized,
            int sinkLine,
            String codeSnippet
    ) {}

    public List<TaintTrace> traceTaint(PythonFunctionDef func) {
        if (func == null) {
            return Collections.emptyList();
        }

        // 1. Initialize tainted variables in scope
        Map<String, List<String>> taintedVars = new LinkedHashMap<>();
        Set<String> sanitizedVars = new HashSet<>();

        // Check if function is a web route/handler (decorated with @app.route, @router.get, etc.)
        boolean isRouteHandler = isWebRouteHandler(func);
        for (String param : func.getParameters()) {
            if ("self".equals(param) || "cls".equals(param)) continue;
            if (isRouteHandler || isSourceParameter(param)) {
                List<String> chain = new ArrayList<>();
                chain.add("param:" + param);
                taintedVars.put(param, chain);
            }
        }

        // 2. Linear / intra-procedural propagation over statements
        for (PythonAstNode stmt : func.getBody()) {
            propagateStatement(stmt, taintedVars, sanitizedVars);
        }

        // 3. Scan for sinks consuming tainted variables
        List<TaintTrace> traces = new ArrayList<>();
        for (PythonCallExpr call : func.getCalls()) {
            checkCallSink(call, taintedVars, sanitizedVars, traces);
        }

        return traces;
    }

    private void propagateStatement(
            PythonAstNode stmt,
            Map<String, List<String>> taintedVars,
            Set<String> sanitizedVars
    ) {
        if (stmt instanceof PythonAssignStmt assign) {
            PythonAstNode val = assign.getValue();
            String rawVal = val != null ? val.getRawText() : "";

            // Check if right-hand side is a direct source (e.g. request.args.get('id'), sys.argv[1])
            String sourceDesc = identifyDirectSource(val);
            if (sourceDesc != null) {
                for (String target : assign.getTargets()) {
                    List<String> chain = new ArrayList<>();
                    chain.add(sourceDesc);
                    chain.add(target);
                    taintedVars.put(target, chain);
                    sanitizedVars.remove(target);
                }
                return;
            }

            // Check if right-hand side applies a sanitizer (shlex.quote, realpath, SafeLoader)
            if (isSanitizerCall(val)) {
                for (String target : assign.getTargets()) {
                    sanitizedVars.add(target);
                    taintedVars.remove(target);
                }
                return;
            }

            // Check if right-hand side derives from an existing tainted variable
            String taintedOrigin = findTaintedVariableInExpr(val, taintedVars);
            if (taintedOrigin != null) {
                List<String> parentChain = taintedVars.get(taintedOrigin);
                for (String target : assign.getTargets()) {
                    List<String> chain = new ArrayList<>(parentChain);
                    chain.add(target);
                    taintedVars.put(target, chain);
                }
            }
        }
    }

    private void checkCallSink(
            PythonCallExpr call,
            Map<String, List<String>> taintedVars,
            Set<String> sanitizedVars,
            List<TaintTrace> traces
    ) {
        String fullCallee = call.getFullCalleeName();
        String shortCallee = call.getCalleeName();

        boolean isSink = isSecuritySink(fullCallee, shortCallee);
        if (!isSink) return;

        // Check positional arguments for tainted variables
        for (PythonArgument arg : call.getArguments()) {
            PythonAstNode argVal = arg.getValue();
            String taintedVar = findTaintedVariableInExpr(argVal, taintedVars);
            if (taintedVar != null) {
                boolean sanitized = sanitizedVars.contains(taintedVar) || isSanitizedInCall(call, arg);
                List<String> chain = new ArrayList<>(taintedVars.get(taintedVar));
                chain.add("sink:" + fullCallee);
                traces.add(new TaintTrace(
                        chain.get(0),
                        fullCallee,
                        chain,
                        sanitized,
                        call.getLine(),
                        call.getRawText()
                ));
            }
        }
    }

    private boolean isWebRouteHandler(PythonFunctionDef func) {
        for (PythonDecorator dec : func.getDecorators()) {
            String name = dec.getName().toLowerCase(Locale.ROOT);
            if (name.contains("route") || name.contains("get") || name.contains("post")
                    || name.contains("put") || name.contains("delete") || name.contains("api")) {
                return true;
            }
        }
        return false;
    }

    private boolean isSourceParameter(String paramName) {
        String lower = paramName.toLowerCase(Locale.ROOT);
        return lower.contains("input") || lower.contains("user") || lower.contains("payload")
                || lower.contains("query") || lower.contains("param") || lower.contains("body")
                || lower.contains("path") || lower.contains("url") || lower.contains("data");
    }

    private String identifyDirectSource(PythonAstNode expr) {
        if (expr == null) return null;
        String raw = expr.getRawText();
        if (raw.contains("request.args") || raw.contains("request.form")
                || raw.contains("request.values") || raw.contains("request.json")
                || raw.contains("request.GET") || raw.contains("request.POST")
                || raw.contains("request.query_params") || raw.contains("request.body")) {
            return "source:http_request";
        }
        if (raw.contains("sys.argv") || raw.contains("os.environ")) {
            return "source:system_env";
        }
        return null;
    }

    private boolean isSanitizerCall(PythonAstNode expr) {
        if (expr == null) return false;
        String raw = expr.getRawText();
        return raw.contains("shlex.quote") || raw.contains("os.path.realpath")
                || raw.contains("os.path.commonpath") || raw.contains("yaml.safe_load")
                || raw.contains("ast.literal_eval") || raw.contains("escape")
                || raw.contains("secrets.token");
    }

    private String findTaintedVariableInExpr(PythonAstNode expr, Map<String, List<String>> taintedVars) {
        if (expr == null || taintedVars.isEmpty()) return null;

        if (expr instanceof PythonNameExpr name) {
            if (taintedVars.containsKey(name.getName())) {
                return name.getName();
            }
        }

        String raw = expr.getRawText();
        for (String varName : taintedVars.keySet()) {
            // Check word boundary
            if (raw.matches(".*\\b" + Pattern.quote(varName) + "\\b.*")) {
                return varName;
            }
        }

        for (PythonAstNode child : expr.getChildren()) {
            String found = findTaintedVariableInExpr(child, taintedVars);
            if (found != null) return found;
        }

        return null;
    }

    private boolean isSecuritySink(String fullCallee, String shortCallee) {
        if ("os.system".equals(fullCallee) || "os.popen".equals(fullCallee)
                || fullCallee.startsWith("subprocess.") || "eval".equals(fullCallee) || "exec".equals(fullCallee)) {
            return true;
        }
        if ("execute".equals(shortCallee) || "executemany".equals(shortCallee) || "raw".equals(shortCallee)
                || fullCallee.contains("cursor.execute") || fullCallee.contains("session.execute")) {
            return true;
        }
        if ("open".equals(fullCallee) || "io.open".equals(fullCallee) || "os.remove".equals(fullCallee)) {
            return true;
        }
        if (fullCallee.startsWith("requests.") || fullCallee.startsWith("httpx.") || fullCallee.startsWith("urllib.request.")) {
            return true;
        }
        if (fullCallee.startsWith("pickle.") || "_pickle.loads".equals(fullCallee)) {
            return true;
        }
        return false;
    }

    private boolean isSanitizedInCall(PythonCallExpr call, PythonArgument arg) {
        // Parameterized SQL query: cursor.execute("SELECT ... WHERE id = %s", (tainted,)) is sanitized!
        String shortCallee = call.getCalleeName();
        if ("execute".equals(shortCallee) || "executemany".equals(shortCallee)) {
            List<PythonAstNode> posArgs = call.getPositionalArguments();
            if (posArgs.size() > 1 && posArgs.get(0) instanceof PythonLiteralExpr) {
                return true; // parameterized query binding
            }
        }
        return false;
    }
}
