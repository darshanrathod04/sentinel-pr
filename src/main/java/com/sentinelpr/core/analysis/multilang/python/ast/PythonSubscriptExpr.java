package com.sentinelpr.core.analysis.multilang.python.ast;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Subscript expression in Python (e.g., target[index]).
 */
public class PythonSubscriptExpr extends PythonAstNode {

    private final PythonAstNode target;
    private final PythonAstNode index;

    public PythonSubscriptExpr(int line, int column, int endLine, int endColumn, String rawText, PythonAstNode target, PythonAstNode index) {
        super(line, column, endLine, endColumn, rawText);
        this.target = target;
        this.index = index;
    }

    public PythonAstNode getTarget() {
        return target;
    }

    public PythonAstNode getIndex() {
        return index;
    }

    @Override
    public List<PythonAstNode> getChildren() {
        List<PythonAstNode> children = new ArrayList<>();
        if (target != null) children.add(target);
        if (index != null) children.add(index);
        return Collections.unmodifiableList(children);
    }

    @Override
    public void accept(PythonAstVisitor visitor) {
        visitor.visit(this);
    }
}
