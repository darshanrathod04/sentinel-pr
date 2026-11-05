package com.sentinelpr.core.analysis.multilang.python.ast;

import java.util.Collections;
import java.util.List;

/**
 * Base abstract syntax tree node for Python representations in SentinelPR.
 */
public abstract class PythonAstNode {

    private final int line;
    private final int column;
    private final int endLine;
    private final int endColumn;
    private final String rawText;

    protected PythonAstNode(int line, int column, int endLine, int endColumn, String rawText) {
        this.line = line;
        this.column = column;
        this.endLine = endLine >= line ? endLine : line;
        this.endColumn = endColumn;
        this.rawText = rawText != null ? rawText : "";
    }

    public int getLine() {
        return line;
    }

    public int getColumn() {
        return column;
    }

    public int getEndLine() {
        return endLine;
    }

    public int getEndColumn() {
        return endColumn;
    }

    public String getRawText() {
        return rawText;
    }

    public List<PythonAstNode> getChildren() {
        return Collections.emptyList();
    }

    public abstract void accept(PythonAstVisitor visitor);

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[line=" + line + ", col=" + column + ", raw='" + rawText + "']";
    }
}
