package com.sentinelpr.client;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.FieldDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.AssignExpr;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.github.javaparser.ast.expr.UnaryExpr;
import com.github.javaparser.ast.stmt.CatchClause;
import com.github.javaparser.ast.stmt.TryStmt;
import com.sentinelpr.core.model.InspectedSource;
import com.shreeai.os.platform.kernels.project.parser.JavaAstParser;
import com.shreeai.os.platform.sdk.ProjectSDK;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Project intelligence facade combining Shree AI OS ProjectSDK with deep AST parsing.
 */
public class ProjectFacade {

    private final ProjectSDK projectSdk;
    private final JavaAstParser astParser;
    private final JavaParser javaParser;

    public ProjectFacade(ProjectSDK projectSdk) {
        this.projectSdk = Objects.requireNonNull(projectSdk, "projectSdk must not be null");
        this.astParser = new JavaAstParser();
        ParserConfiguration config = new ParserConfiguration();
        config.setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_21);
        this.javaParser = new JavaParser(config);
    }

    /**
     * Parses Java AST from a file path.
     */
    public InspectedSource parseAst(Path path) throws IOException {
        Objects.requireNonNull(path, "path must not be null");
        String content = Files.readString(path);
        return parseAst(content, path);
    }

    /**
     * Parses Java AST from source code string and path.
     */
    public InspectedSource parseAst(String source, Path path) {
        Objects.requireNonNull(source, "source must not be null");
        Optional<CompilationUnit> cuResult = javaParser.parse(source).getResult();
        if (cuResult.isEmpty()) {
            throw new IllegalArgumentException("Failed to parse Java source: syntactically invalid Java code");
        }

        CompilationUnit cu = cuResult.get();
        String packageName = cu.getPackageDeclaration()
                .map(p -> p.getNameAsString())
                .orElse("");

        List<String> imports = cu.getImports().stream()
                .map(i -> i.getNameAsString())
                .toList();

        List<ClassOrInterfaceDeclaration> classDecls = cu.findAll(ClassOrInterfaceDeclaration.class);
        String primaryClassName = classDecls.stream()
                .filter(ClassOrInterfaceDeclaration::isPublic)
                .map(ClassOrInterfaceDeclaration::getNameAsString)
                .findFirst()
                .orElse(classDecls.isEmpty() ? "UnknownClass" : classDecls.get(0).getNameAsString());

        List<MethodDeclaration> methods = cu.findAll(MethodDeclaration.class);
        List<FieldDeclaration> fields = cu.findAll(FieldDeclaration.class);
        List<CatchClause> catchClauses = cu.findAll(CatchClause.class);
        List<TryStmt> tryStatements = cu.findAll(TryStmt.class);
        List<VariableDeclarator> variableDeclarators = cu.findAll(VariableDeclarator.class);
        List<ObjectCreationExpr> objectCreations = cu.findAll(ObjectCreationExpr.class);
        List<UnaryExpr> unaryExpressions = cu.findAll(UnaryExpr.class);
        List<AssignExpr> assignExpressions = cu.findAll(AssignExpr.class);
        List<MethodCallExpr> methodCalls = cu.findAll(MethodCallExpr.class);

        return new InspectedSource(
                path,
                source,
                cu,
                packageName,
                primaryClassName,
                imports,
                classDecls,
                methods,
                fields,
                catchClauses,
                tryStatements,
                variableDeclarators,
                objectCreations,
                unaryExpressions,
                assignExpressions,
                methodCalls
        );
    }

    public ProjectSDK getSdk() {
        return projectSdk;
    }

    public JavaAstParser getAstParser() {
        return astParser;
    }
}
