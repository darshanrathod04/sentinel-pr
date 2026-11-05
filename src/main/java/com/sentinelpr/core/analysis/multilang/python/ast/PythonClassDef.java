package com.sentinelpr.core.analysis.multilang.python.ast;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Class definition in Python (class MyModel(models.Model):).
 */
public class PythonClassDef extends PythonAstNode {

    private final String name;
    private final List<String> bases;
    private final List<PythonDecorator> decorators;
    private final List<PythonFunctionDef> methods;
    private final List<PythonAssignStmt> classVariables;
    private final List<PythonAstNode> body;
    private final String docstring;

    public PythonClassDef(
            int line,
            int column,
            int endLine,
            int endColumn,
            String rawText,
            String name,
            List<String> bases,
            List<PythonDecorator> decorators,
            List<PythonFunctionDef> methods,
            List<PythonAssignStmt> classVariables,
            List<PythonAstNode> body,
            String docstring
    ) {
        super(line, column, endLine, endColumn, rawText);
        this.name = name != null ? name : "";
        this.bases = bases != null ? Collections.unmodifiableList(bases) : Collections.emptyList();
        this.decorators = decorators != null ? Collections.unmodifiableList(decorators) : Collections.emptyList();
        this.methods = methods != null ? Collections.unmodifiableList(methods) : Collections.emptyList();
        this.classVariables = classVariables != null ? Collections.unmodifiableList(classVariables) : Collections.emptyList();
        this.body = body != null ? Collections.unmodifiableList(body) : Collections.emptyList();
        this.docstring = docstring != null ? docstring : "";
    }

    public String getName() {
        return name;
    }

    public List<String> getBases() {
        return bases;
    }

    public List<PythonDecorator> getDecorators() {
        return decorators;
    }

    public List<PythonFunctionDef> getMethods() {
        return methods;
    }

    public List<PythonAssignStmt> getClassVariables() {
        return classVariables;
    }

    public List<PythonAstNode> getBody() {
        return body;
    }

    public String getDocstring() {
        return docstring;
    }

    @Override
    public List<PythonAstNode> getChildren() {
        List<PythonAstNode> children = new ArrayList<>(decorators);
        children.addAll(methods);
        children.addAll(classVariables);
        children.addAll(body);
        return Collections.unmodifiableList(children);
    }

    @Override
    public void accept(PythonAstVisitor visitor) {
        visitor.visit(this);
    }
}
