package com.sentinelpr.core.analysis.multilang.python.ast;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Root AST node representing an entire Python source module.
 */
public class PythonModule extends PythonAstNode {

    private final Path filePath;
    private final List<PythonImportStmt> imports;
    private final List<PythonClassDef> classes;
    private final List<PythonFunctionDef> functions;
    private final List<PythonAstNode> statements;

    public PythonModule(
            Path filePath,
            int lineCount,
            String rawSource,
            List<PythonImportStmt> imports,
            List<PythonClassDef> classes,
            List<PythonFunctionDef> functions,
            List<PythonAstNode> statements
    ) {
        super(1, 0, Math.max(1, lineCount), 0, rawSource);
        this.filePath = filePath;
        this.imports = imports != null ? Collections.unmodifiableList(imports) : Collections.emptyList();
        this.classes = classes != null ? Collections.unmodifiableList(classes) : Collections.emptyList();
        this.functions = functions != null ? Collections.unmodifiableList(functions) : Collections.emptyList();
        this.statements = statements != null ? Collections.unmodifiableList(statements) : Collections.emptyList();
    }

    public Path getFilePath() {
        return filePath;
    }

    public int getLineCount() {
        return getEndLine();
    }

    public List<PythonImportStmt> getImports() {
        return imports;
    }

    public List<PythonClassDef> getClasses() {
        return classes;
    }

    public List<PythonFunctionDef> getFunctions() {
        return functions;
    }

    public List<PythonAstNode> getStatements() {
        return statements;
    }

    public List<PythonCallExpr> findAllCalls() {
        List<PythonCallExpr> calls = new ArrayList<>();
        collectCalls(statements, calls);
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

    public List<PythonAssignStmt> findAllAssignments() {
        List<PythonAssignStmt> assigns = new ArrayList<>();
        collectAssignments(statements, assigns);
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

    @Override
    public List<PythonAstNode> getChildren() {
        List<PythonAstNode> children = new ArrayList<>();
        children.addAll(imports);
        children.addAll(classes);
        children.addAll(functions);
        children.addAll(statements);
        return Collections.unmodifiableList(children);
    }

    @Override
    public void accept(PythonAstVisitor visitor) {
        visitor.visit(this);
    }
}
