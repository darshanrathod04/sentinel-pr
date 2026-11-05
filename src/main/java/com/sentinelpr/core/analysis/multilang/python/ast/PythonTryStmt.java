package com.sentinelpr.core.analysis.multilang.python.ast;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Try-except-finally statement in Python.
 */
public class PythonTryStmt extends PythonAstNode {

    private final List<PythonAstNode> tryBody;
    private final List<PythonExceptClause> exceptClauses;
    private final List<PythonAstNode> finallyBody;

    public PythonTryStmt(
            int line,
            int column,
            int endLine,
            int endColumn,
            String rawText,
            List<PythonAstNode> tryBody,
            List<PythonExceptClause> exceptClauses,
            List<PythonAstNode> finallyBody
    ) {
        super(line, column, endLine, endColumn, rawText);
        this.tryBody = tryBody != null ? Collections.unmodifiableList(tryBody) : Collections.emptyList();
        this.exceptClauses = exceptClauses != null ? Collections.unmodifiableList(exceptClauses) : Collections.emptyList();
        this.finallyBody = finallyBody != null ? Collections.unmodifiableList(finallyBody) : Collections.emptyList();
    }

    public List<PythonAstNode> getTryBody() {
        return tryBody;
    }

    public List<PythonExceptClause> getExceptClauses() {
        return exceptClauses;
    }

    public List<PythonAstNode> getFinallyBody() {
        return finallyBody;
    }

    @Override
    public List<PythonAstNode> getChildren() {
        List<PythonAstNode> children = new ArrayList<>(tryBody);
        children.addAll(exceptClauses);
        children.addAll(finallyBody);
        return Collections.unmodifiableList(children);
    }

    @Override
    public void accept(PythonAstVisitor visitor) {
        visitor.visit(this);
    }
}
