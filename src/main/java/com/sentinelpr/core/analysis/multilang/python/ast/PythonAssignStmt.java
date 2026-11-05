package com.sentinelpr.core.analysis.multilang.python.ast;

import java.util.Collections;
import java.util.List;

/**
 * Assignment statement in Python (e.g., cmd = "ping " + host).
 */
public class PythonAssignStmt extends PythonAstNode {

    private final List<String> targets;
    private final PythonAstNode value;

    public PythonAssignStmt(int line, int column, int endLine, int endColumn, String rawText, List<String> targets, PythonAstNode value) {
        super(line, column, endLine, endColumn, rawText);
        this.targets = targets != null ? Collections.unmodifiableList(targets) : Collections.emptyList();
        this.value = value;
    }

    public List<String> getTargets() {
        return targets;
    }

    public String getPrimaryTarget() {
        return targets.isEmpty() ? "" : targets.get(0);
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
