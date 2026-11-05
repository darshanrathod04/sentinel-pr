package com.sentinelpr.core.analysis.multilang.python.ast;

import java.util.Collections;
import java.util.List;

/**
 * Return statement in Python.
 */
public class PythonReturnStmt extends PythonAstNode {

    private final PythonAstNode value;

    public PythonReturnStmt(int line, int column, int endLine, int endColumn, String rawText, PythonAstNode value) {
        super(line, column, endLine, endColumn, rawText);
        this.value = value;
    }

    public PythonAstNode getValue() {
        return value;
    }

    @Override
    public List<PythonAstNode> getChildren() {
        return value != null ? List.of(value) : Collections.emptyList();
    }

    @Override
    public void accept(PythonAstVisitor visitor) {
        visitor.visit(this);
    }
}
