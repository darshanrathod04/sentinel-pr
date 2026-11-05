package com.sentinelpr.core.analysis.multilang.python.ast;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Binary expression in Python (e.g. left + right, left % right).
 */
public class PythonBinaryExpr extends PythonAstNode {

    private final PythonAstNode left;
    private final String operator;
    private final PythonAstNode right;

    public PythonBinaryExpr(int line, int column, int endLine, int endColumn, String rawText, PythonAstNode left, String operator, PythonAstNode right) {
        super(line, column, endLine, endColumn, rawText);
        this.left = left;
        this.operator = operator != null ? operator : "";
        this.right = right;
    }

    public PythonAstNode getLeft() {
        return left;
    }

    public String getOperator() {
        return operator;
    }

    public PythonAstNode getRight() {
        return right;
    }

    @Override
    public List<PythonAstNode> getChildren() {
        List<PythonAstNode> children = new ArrayList<>();
        if (left != null) children.add(left);
        if (right != null) children.add(right);
        return Collections.unmodifiableList(children);
    }

    @Override
    public void accept(PythonAstVisitor visitor) {
        visitor.visit(this);
    }
}
