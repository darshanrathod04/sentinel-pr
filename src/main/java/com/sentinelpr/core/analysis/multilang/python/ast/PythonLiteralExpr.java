package com.sentinelpr.core.analysis.multilang.python.ast;

/**
 * Literal constant expression in Python (string, number, boolean, None).
 */
public class PythonLiteralExpr extends PythonAstNode {

    public enum Kind {
        STRING,
        FSTRING,
        NUMBER,
        BOOLEAN,
        NONE,
        OTHER
    }

    private final Kind kind;
    private final String value;

    public PythonLiteralExpr(int line, int column, int endLine, int endColumn, String rawText, Kind kind, String value) {
        super(line, column, endLine, endColumn, rawText);
        this.kind = kind;
        this.value = value != null ? value : "";
    }

    public Kind getKind() {
        return kind;
    }

    public String getValue() {
        return value;
    }

    @Override
    public void accept(PythonAstVisitor visitor) {
        visitor.visit(this);
    }
}
