package com.sentinelpr.core.analysis.multilang.python.ast;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Function or method definition in Python (def foo(a, b): / async def foo(a, b):).
 */
public class PythonFunctionDef extends PythonAstNode {

    private final String name;
    private final List<String> parameters;
    private final List<PythonDecorator> decorators;
    private final List<PythonAstNode> body;
    private final boolean isAsync;
    private final String docstring;

    public PythonFunctionDef(
            int line,
            int column,
            int endLine,
            int endColumn,
            String rawText,
            String name,
            List<String> parameters,
            List<PythonDecorator> decorators,
            List<PythonAstNode> body,
            boolean isAsync,
            String docstring
    ) {
        super(line, column, endLine, endColumn, rawText);
        this.name = name != null ? name : "";
        this.parameters = parameters != null ? Collections.unmodifiableList(parameters) : Collections.emptyList();
        this.decorators = decorators != null ? Collections.unmodifiableList(decorators) : Collections.emptyList();
        this.body = body != null ? Collections.unmodifiableList(body) : Collections.emptyList();
        this.isAsync = isAsync;
        this.docstring = docstring != null ? docstring : "";
    }

    public String getName() {
        return name;
    }

    public List<String> getParameters() {
        return parameters;
    }

    public List<PythonDecorator> getDecorators() {
        return decorators;
    }

    public List<PythonAstNode> getBody() {
        return body;
    }

    public boolean isAsync() {
        return isAsync;
    }

    public String getDocstring() {
        return docstring;
    }

    public List<PythonCallExpr> getCalls() {
        List<PythonCallExpr> calls = new ArrayList<>();
        collectCalls(body, calls);
        return Collections.unmodifiableList(calls);
    }

    private void collectCalls(List<PythonAstNode> nodes, List<PythonCallExpr> acc) {
        for (PythonAstNode node : nodes) {
            if (node instanceof PythonCallExpr call) {
                acc.add(call);
            }
            collectCalls(node.getChildren(), acc);
        }
    }

    public List<PythonAssignStmt> getAssignments() {
        List<PythonAssignStmt> assigns = new ArrayList<>();
        collectAssignments(body, assigns);
        return Collections.unmodifiableList(assigns);
    }

    private void collectAssignments(List<PythonAstNode> nodes, List<PythonAssignStmt> acc) {
        for (PythonAstNode node : nodes) {
            if (node instanceof PythonAssignStmt assign) {
                acc.add(assign);
            }
            collectAssignments(node.getChildren(), acc);
        }
    }

    public List<PythonReturnStmt> getReturns() {
        List<PythonReturnStmt> returns = new ArrayList<>();
        collectReturns(body, returns);
        return Collections.unmodifiableList(returns);
    }

    private void collectReturns(List<PythonAstNode> nodes, List<PythonReturnStmt> acc) {
        for (PythonAstNode node : nodes) {
            if (node instanceof PythonReturnStmt ret) {
                acc.add(ret);
            }
            collectReturns(node.getChildren(), acc);
        }
    }

    @Override
    public List<PythonAstNode> getChildren() {
        List<PythonAstNode> children = new ArrayList<>(decorators);
        children.addAll(body);
        return Collections.unmodifiableList(children);
    }

    @Override
    public void accept(PythonAstVisitor visitor) {
        visitor.visit(this);
    }
}
