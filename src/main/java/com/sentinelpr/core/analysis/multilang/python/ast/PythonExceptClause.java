package com.sentinelpr.core.analysis.multilang.python.ast;

import java.util.Collections;
import java.util.List;

/**
 * Except clause in a Python try/except block (except (ValueError, KeyError) as e:).
 */
public class PythonExceptClause extends PythonAstNode {

    private final String exceptionType;
    private final String exceptionAlias;
    private final List<PythonAstNode> body;

    public PythonExceptClause(
            int line,
            int column,
            int endLine,
            int endColumn,
            String rawText,
            String exceptionType,
            String exceptionAlias,
            List<PythonAstNode> body
    ) {
        super(line, column, endLine, endColumn, rawText);
        this.exceptionType = exceptionType != null ? exceptionType : "";
        this.exceptionAlias = exceptionAlias != null ? exceptionAlias : "";
        this.body = body != null ? Collections.unmodifiableList(body) : Collections.emptyList();
    }

    public String getExceptionType() {
        return exceptionType;
    }

    public String getExceptionAlias() {
        return exceptionAlias;
    }

    public List<PythonAstNode> getBody() {
        return body;
    }

    @Override
    public List<PythonAstNode> getChildren() {
        return body;
    }

    @Override
    public void accept(PythonAstVisitor visitor) {
        visitor.visit(this);
    }
}
