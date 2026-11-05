package com.sentinelpr.core.analysis.multilang.python.ast;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * If-elif-else conditional statement in Python.
 */
public class PythonIfStmt extends PythonAstNode {

    private final PythonAstNode condition;
    private final List<PythonAstNode> thenBranch;
    private final List<PythonAstNode> elseBranch;

    public PythonIfStmt(
            int line,
            int column,
            int endLine,
            int endColumn,
            String rawText,
            PythonAstNode condition,
            List<PythonAstNode> thenBranch,
            List<PythonAstNode> elseBranch
    ) {
        super(line, column, endLine, endColumn, rawText);
        this.condition = condition;
        this.thenBranch = thenBranch != null ? Collections.unmodifiableList(thenBranch) : Collections.emptyList();
        this.elseBranch = elseBranch != null ? Collections.unmodifiableList(elseBranch) : Collections.emptyList();
    }

    public PythonAstNode getCondition() {
        return condition;
    }

    public List<PythonAstNode> getThenBranch() {
        return thenBranch;
    }

    public List<PythonAstNode> getElseBranch() {
        return elseBranch;
    }

    @Override
    public List<PythonAstNode> getChildren() {
        List<PythonAstNode> children = new ArrayList<>();
        if (condition != null) children.add(condition);
        children.addAll(thenBranch);
        children.addAll(elseBranch);
        return Collections.unmodifiableList(children);
    }

    @Override
    public void accept(PythonAstVisitor visitor) {
        visitor.visit(this);
    }
}
