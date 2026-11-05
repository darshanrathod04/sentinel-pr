package com.sentinelpr.core.analysis.multilang.python.ast;

import java.util.Collections;
import java.util.List;

/**
 * Attribute access expression in Python (e.g., target.attr, resp.text, obj.field).
 */
public class PythonAttributeExpr extends PythonAstNode {

    private final PythonAstNode target;
    private final String attributeName;

    public PythonAttributeExpr(int line, int column, int endLine, int endColumn, String rawText, PythonAstNode target, String attributeName) {
        super(line, column, endLine, endColumn, rawText);
        this.target = target;
        this.attributeName = attributeName != null ? attributeName : "";
    }

    public PythonAstNode getTarget() {
        return target;
    }

    public String getAttributeName() {
        return attributeName;
    }

    @Override
    public List<PythonAstNode> getChildren() {
        return target != null ? List.of(target) : Collections.emptyList();
    }

    @Override
    public void accept(PythonAstVisitor visitor) {
        if (target != null) {
            target.accept(visitor);
        }
    }
}
