package com.sentinelpr.core.analysis.multilang.python.ast;

import java.util.Collections;
import java.util.List;

/**
 * Decorator applied to a Python function or class (e.g., @app.route('/login', methods=['POST'])).
 */
public class PythonDecorator extends PythonAstNode {

    private final String name;
    private final PythonCallExpr callExpr;

    public PythonDecorator(int line, int column, int endLine, int endColumn, String rawText, String name, PythonCallExpr callExpr) {
        super(line, column, endLine, endColumn, rawText);
        this.name = name != null ? name : "";
        this.callExpr = callExpr;
    }

    public String getName() {
        return name;
    }

    public PythonCallExpr getCallExpr() {
        return callExpr;
    }

    @Override
    public List<PythonAstNode> getChildren() {
        return callExpr != null ? List.of(callExpr) : Collections.emptyList();
    }

    @Override
    public void accept(PythonAstVisitor visitor) {
        if (callExpr != null) {
            callExpr.accept(visitor);
        }
    }
}
