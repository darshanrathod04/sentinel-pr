package com.sentinelpr.core.analysis.multilang.python.ast;

/**
 * Visitor interface for traversing Python AST structures.
 */
public interface PythonAstVisitor {

    default void visit(PythonModule module) {
        for (PythonAstNode stmt : module.getStatements()) {
            stmt.accept(this);
        }
    }

    default void visit(PythonClassDef classDef) {
        for (PythonFunctionDef method : classDef.getMethods()) {
            method.accept(this);
        }
    }

    default void visit(PythonFunctionDef functionDef) {
        for (PythonAstNode stmt : functionDef.getBody()) {
            stmt.accept(this);
        }
    }

    default void visit(PythonCallExpr callExpr) {
        for (PythonAstNode arg : callExpr.getArguments()) {
            arg.accept(this);
        }
    }

    default void visit(PythonAssignStmt assignStmt) {
        if (assignStmt.getValue() != null) {
            assignStmt.getValue().accept(this);
        }
    }

    default void visit(PythonImportStmt importStmt) {}

    default void visit(PythonReturnStmt returnStmt) {
        if (returnStmt.getValue() != null) {
            returnStmt.getValue().accept(this);
        }
    }

    default void visit(PythonIfStmt ifStmt) {
        if (ifStmt.getCondition() != null) {
            ifStmt.getCondition().accept(this);
        }
        for (PythonAstNode s : ifStmt.getThenBranch()) {
            s.accept(this);
        }
        for (PythonAstNode s : ifStmt.getElseBranch()) {
            s.accept(this);
        }
    }

    default void visit(PythonTryStmt tryStmt) {
        for (PythonAstNode s : tryStmt.getTryBody()) {
            s.accept(this);
        }
        for (PythonExceptClause ec : tryStmt.getExceptClauses()) {
            ec.accept(this);
        }
        for (PythonAstNode s : tryStmt.getFinallyBody()) {
            s.accept(this);
        }
    }

    default void visit(PythonExceptClause exceptClause) {
        for (PythonAstNode s : exceptClause.getBody()) {
            s.accept(this);
        }
    }

    default void visit(PythonBinaryExpr binaryExpr) {
        if (binaryExpr.getLeft() != null) binaryExpr.getLeft().accept(this);
        if (binaryExpr.getRight() != null) binaryExpr.getRight().accept(this);
    }

    default void visit(PythonLiteralExpr literalExpr) {}

    default void visit(PythonNameExpr nameExpr) {}

    default void visit(PythonSubscriptExpr subscriptExpr) {
        if (subscriptExpr.getTarget() != null) subscriptExpr.getTarget().accept(this);
        if (subscriptExpr.getIndex() != null) subscriptExpr.getIndex().accept(this);
    }

    default void visit(PythonArgument argument) {
        if (argument.getValue() != null) argument.getValue().accept(this);
    }
}
