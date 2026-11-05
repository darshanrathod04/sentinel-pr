package com.sentinelpr.core.analysis.multilang.python.ast;

/**
 * Identifier/variable name reference in Python.
 */
public class PythonNameExpr extends PythonAstNode {

    private final String name;

    public PythonNameExpr(int line, int column, int endLine, int endColumn, String rawText, String name) {
        super(line, column, endLine, endColumn, rawText);
        this.name = name != null ? name : "";
    }

    public String getName() {
        return name;
    }

    @Override
    public void accept(PythonAstVisitor visitor) {
        visitor.visit(this);
    }
}
