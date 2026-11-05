package com.sentinelpr.core.analysis.multilang.python.ast;

import java.util.Collections;
import java.util.List;

/**
 * Represents a positional or keyword argument in a Python function or method call.
 */
public class PythonArgument extends PythonAstNode {

    private final String keywordName;
    private final PythonAstNode value;

    public PythonArgument(int line, int column, int endLine, int endColumn, String rawText, String keywordName, PythonAstNode value) {
        super(line, column, endLine, endColumn, rawText);
        this.keywordName = keywordName;
        this.value = value;
    }

    public boolean isKeyword() {
        return keywordName != null && !keywordName.isBlank();
    }

    public String getKeywordName() {
        return keywordName;
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
