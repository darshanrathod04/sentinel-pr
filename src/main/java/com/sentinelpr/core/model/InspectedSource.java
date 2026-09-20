package com.sentinelpr.core.model;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.FieldDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.AnnotationExpr;
import com.github.javaparser.ast.expr.AssignExpr;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.github.javaparser.ast.expr.StringLiteralExpr;
import com.github.javaparser.ast.expr.UnaryExpr;
import com.github.javaparser.ast.stmt.CatchClause;
import com.github.javaparser.ast.stmt.TryStmt;

import java.nio.file.Path;
import java.util.Collections;
import java.util.List;

/**
 * Rich AST representation extracted from a Java source file by CodeInspectionService.
 */
public class InspectedSource {

    private final Path filePath;
    private final String rawSource;
    private final CompilationUnit compilationUnit;
    private final String packageName;
    private final String primaryClassName;
    private final List<String> imports;
    private final List<ClassOrInterfaceDeclaration> classDeclarations;
    private final List<MethodDeclaration> methods;
    private final List<FieldDeclaration> fields;
    private final List<CatchClause> catchClauses;
    private final List<TryStmt> tryStatements;
    private final List<VariableDeclarator> variableDeclarations;
    private final List<ObjectCreationExpr> objectCreations;
    private final List<UnaryExpr> unaryExpressions;
    private final List<AssignExpr> assignExpressions;
    private final List<MethodCallExpr> methodCalls;

    public InspectedSource(
            Path filePath,
            String rawSource,
            CompilationUnit compilationUnit,
            String packageName,
            String primaryClassName,
            List<String> imports,
            List<ClassOrInterfaceDeclaration> classDeclarations,
            List<MethodDeclaration> methods,
            List<FieldDeclaration> fields,
            List<CatchClause> catchClauses,
            List<TryStmt> tryStatements,
            List<VariableDeclarator> variableDeclarations,
            List<ObjectCreationExpr> objectCreations,
            List<UnaryExpr> unaryExpressions,
            List<AssignExpr> assignExpressions,
            List<MethodCallExpr> methodCalls
    ) {
        this.filePath = filePath;
        this.rawSource = rawSource != null ? rawSource : "";
        this.compilationUnit = compilationUnit;
        this.packageName = packageName != null ? packageName : "";
        this.primaryClassName = primaryClassName != null ? primaryClassName : "";
        this.imports = imports != null ? Collections.unmodifiableList(imports) : List.of();
        this.classDeclarations = classDeclarations != null ? Collections.unmodifiableList(classDeclarations) : List.of();
        this.methods = methods != null ? Collections.unmodifiableList(methods) : List.of();
        this.fields = fields != null ? Collections.unmodifiableList(fields) : List.of();
        this.catchClauses = catchClauses != null ? Collections.unmodifiableList(catchClauses) : List.of();
        this.tryStatements = tryStatements != null ? Collections.unmodifiableList(tryStatements) : List.of();
        this.variableDeclarations = variableDeclarations != null ? Collections.unmodifiableList(variableDeclarations) : List.of();
        this.objectCreations = objectCreations != null ? Collections.unmodifiableList(objectCreations) : List.of();
        this.unaryExpressions = unaryExpressions != null ? Collections.unmodifiableList(unaryExpressions) : List.of();
        this.assignExpressions = assignExpressions != null ? Collections.unmodifiableList(assignExpressions) : List.of();
        this.methodCalls = methodCalls != null ? Collections.unmodifiableList(methodCalls) : List.of();
    }

    public Path getFilePath() {
        return filePath;
    }

    public String getRawSource() {
        return rawSource;
    }

    public CompilationUnit getCompilationUnit() {
        return compilationUnit;
    }

    public String getPackageName() {
        return packageName;
    }

    public String getPrimaryClassName() {
        return primaryClassName;
    }

    public List<String> getImports() {
        return imports;
    }

    public List<ClassOrInterfaceDeclaration> getClassDeclarations() {
        return classDeclarations;
    }

    public List<MethodDeclaration> getMethods() {
        return methods;
    }

    public List<FieldDeclaration> getFields() {
        return fields;
    }

    public List<CatchClause> getCatchClauses() {
        return catchClauses;
    }

    public List<TryStmt> getTryStatements() {
        return tryStatements;
    }

    public List<VariableDeclarator> getVariableDeclarations() {
        return variableDeclarations;
    }

    public List<ObjectCreationExpr> getObjectCreations() {
        return objectCreations;
    }

    public List<UnaryExpr> getUnaryExpressions() {
        return unaryExpressions;
    }

    public List<AssignExpr> getAssignExpressions() {
        return assignExpressions;
    }

    public List<MethodCallExpr> getMethodCalls() {
        return methodCalls;
    }

    public List<StringLiteralExpr> getStringLiterals() {
        if (compilationUnit != null) {
            return compilationUnit.findAll(StringLiteralExpr.class);
        }
        return Collections.emptyList();
    }

    public List<AnnotationExpr> getAnnotations() {
        if (compilationUnit != null) {
            return compilationUnit.findAll(AnnotationExpr.class);
        }
        return Collections.emptyList();
    }
}
