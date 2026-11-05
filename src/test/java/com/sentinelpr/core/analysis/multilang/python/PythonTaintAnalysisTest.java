package com.sentinelpr.core.analysis.multilang.python;

import com.sentinelpr.core.analysis.multilang.python.ast.PythonFunctionDef;
import com.sentinelpr.core.analysis.multilang.python.ast.PythonModule;
import com.sentinelpr.core.analysis.multilang.python.taint.PythonTaintTracker;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Phase 5: Python Intra-Procedural Taint Analysis Test Suite")
public class PythonTaintAnalysisTest {

    private PythonSourceParser parser;
    private PythonTaintTracker taintTracker;

    @BeforeEach
    void setUp() {
        this.parser = new PythonSourceParser();
        this.taintTracker = new PythonTaintTracker();
    }

    @Test
    @DisplayName("Trace multi-hop taint from request.args to database sink")
    void testMultiHopTaintToSink() {
        String pyCode = """
                @app.route("/user")
                def view_user():
                    raw_id = request.args.get("id")
                    clean_or_tainted = raw_id
                    sql = "SELECT * FROM users WHERE id = " + clean_or_tainted
                    cursor.execute(sql)
                """;

        PythonModule module = parser.parse(pyCode, Path.of("views.py"));
        PythonFunctionDef func = module.getFunctions().get(0);

        List<PythonTaintTracker.TaintTrace> traces = taintTracker.traceTaint(func);
        assertFalse(traces.isEmpty(), "Must track multi-hop taint to sink");

        PythonTaintTracker.TaintTrace trace = traces.get(0);
        assertEquals("source:http_request", trace.sourceDescription());
        assertTrue(trace.sinkName().contains("execute"));
        assertFalse(trace.isSanitized(), "Raw string concatenation is not sanitized");
        assertTrue(trace.propagationChain().contains("raw_id"));
        assertTrue(trace.propagationChain().contains("sql"));
    }

    @Test
    @DisplayName("Recognize shlex.quote sanitizer on command execution")
    void testCommandSanitizerRecognition() {
        String pyCode = """
                import shlex, os
                def run_user_cmd(user_input):
                    safe_arg = shlex.quote(user_input)
                    os.system("echo " + safe_arg)
                """;

        PythonModule module = parser.parse(pyCode, Path.of("cmd.py"));
        PythonFunctionDef func = module.getFunctions().get(0);

        List<PythonTaintTracker.TaintTrace> traces = taintTracker.traceTaint(func);
        // Either trace is marked sanitized or excluded from active vulnerability sinks
        assertTrue(traces.isEmpty() || traces.stream().allMatch(PythonTaintTracker.TaintTrace::isSanitized),
                "shlex.quote must sanitize the tainted variable");
    }

    @Test
    @DisplayName("Recognize parameterized query binding as safe sink usage")
    void testParameterizedSqlSanitizer() {
        String pyCode = """
                @app.route("/search")
                def search_items():
                    query_term = request.args.get("q")
                    cursor.execute("SELECT * FROM items WHERE name = %s", (query_term,))
                """;

        PythonModule module = parser.parse(pyCode, Path.of("search.py"));
        PythonFunctionDef func = module.getFunctions().get(0);

        List<PythonTaintTracker.TaintTrace> traces = taintTracker.traceTaint(func);
        assertTrue(traces.stream().anyMatch(PythonTaintTracker.TaintTrace::isSanitized),
                "Tuple binding in cursor.execute must be recognized as sanitized parameter binding");
    }

    @Test
    @DisplayName("Track path traversal from parameter to open() sink")
    void testPathTraversalTaint() {
        String pyCode = """
                def download_file(user_path):
                    target = "/data/" + user_path
                    f = open(target)
                    return f.read()
                """;

        PythonModule module = parser.parse(pyCode, Path.of("files.py"));
        PythonFunctionDef func = module.getFunctions().get(0);

        List<PythonTaintTracker.TaintTrace> traces = taintTracker.traceTaint(func);
        assertFalse(traces.isEmpty(), "Must track taint from user_path to open()");

        PythonTaintTracker.TaintTrace trace = traces.get(0);
        assertEquals("open", trace.sinkName());
        assertFalse(trace.isSanitized(), "Raw path concatenation is not sanitized");
        assertTrue(trace.propagationChain().contains("target"));
    }
}
