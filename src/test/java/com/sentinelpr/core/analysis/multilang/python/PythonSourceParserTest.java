package com.sentinelpr.core.analysis.multilang.python;

import com.sentinelpr.core.analysis.multilang.python.ast.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Phase 5: PythonSourceParser AST & Source Location Model Test Suite")
public class PythonSourceParserTest {

    private PythonSourceParser parser;

    @BeforeEach
    void setUp() {
        this.parser = new PythonSourceParser();
    }

    @Test
    @DisplayName("Parse standard and aliased imports")
    void testParseImports() {
        String pyCode = """
                import os, sys
                import requests as req
                from flask import Flask, request, jsonify as j
                from django.db import connection
                """;

        PythonModule module = parser.parse(pyCode, Path.of("app.py"));
        assertNotNull(module);
        assertTrue(module.getLineCount() >= 4);

        List<PythonImportStmt> imports = module.getImports();
        assertTrue(imports.size() >= 6, "Expected at least 6 imported symbols");

        assertTrue(imports.stream().anyMatch(i -> "os".equals(i.getModuleName())));
        assertTrue(imports.stream().anyMatch(i -> "sys".equals(i.getModuleName())));
        assertTrue(imports.stream().anyMatch(i -> "requests".equals(i.getModuleName()) && "req".equals(i.getAlias())));
        assertTrue(imports.stream().anyMatch(i -> "flask".equals(i.getModuleName()) && "request".equals(i.getImportedSymbol())));
        assertTrue(imports.stream().anyMatch(i -> "flask".equals(i.getModuleName()) && "j".equals(i.getAlias())));
        assertTrue(imports.stream().anyMatch(i -> "django.db".equals(i.getModuleName()) && "connection".equals(i.getImportedSymbol())));
    }

    @Test
    @DisplayName("Parse classes with bases, docstrings, decorators, and methods")
    void testParseClasses() {
        String pyCode = """
                @dataclass
                class UserModel(BaseModel, AuditMixin):
                    \"\"\"User domain entity representation.\"\"\"
                    table_name = "users"
                    
                    def __init__(self, user_id: str, username: str = "guest"):
                        self.user_id = user_id
                        self.username = username
                    
                    @property
                    def display_name(self):
                        return self.username
                """;

        PythonModule module = parser.parse(pyCode, Path.of("models.py"));
        assertEquals(1, module.getClasses().size());

        PythonClassDef userClass = module.getClasses().get(0);
        assertEquals("UserModel", userClass.getName());
        assertEquals(List.of("BaseModel", "AuditMixin"), userClass.getBases());
        assertEquals(1, userClass.getDecorators().size());
        assertEquals("dataclass", userClass.getDecorators().get(0).getName());
        assertTrue(userClass.getDocstring().contains("User domain entity representation"));

        List<PythonFunctionDef> methods = userClass.getMethods();
        assertEquals(2, methods.size());

        PythonFunctionDef initMethod = methods.get(0);
        assertEquals("__init__", initMethod.getName());
        assertEquals(List.of("self", "user_id", "username"), initMethod.getParameters());

        PythonFunctionDef propMethod = methods.get(1);
        assertEquals("display_name", propMethod.getName());
        assertEquals(1, propMethod.getDecorators().size());
        assertEquals("property", propMethod.getDecorators().get(0).getName());
    }

    @Test
    @DisplayName("Parse top-level functions and async definitions with decorators and params")
    void testParseFunctions() {
        String pyCode = """
                @app.route("/api/v1/users", methods=["GET"])
                def get_users():
                    \"\"\"Fetch all active users.\"\"\"
                    query = "SELECT * FROM users"
                    return query

                @router.post("/items")
                async def create_item(item_id: int, payload: dict):
                    status = 201
                    return status
                """;

        PythonModule module = parser.parse(pyCode, Path.of("routes.py"));
        List<PythonFunctionDef> functions = module.getFunctions();
        assertEquals(2, functions.size());

        PythonFunctionDef getUsers = functions.get(0);
        assertEquals("get_users", getUsers.getName());
        assertFalse(getUsers.isAsync());
        assertEquals(1, getUsers.getDecorators().size());
        assertEquals("app.route", getUsers.getDecorators().get(0).getName());
        assertNotNull(getUsers.getDecorators().get(0).getCallExpr());
        assertEquals("app.route", getUsers.getDecorators().get(0).getCallExpr().getFullCalleeName());

        PythonFunctionDef createItem = functions.get(1);
        assertEquals("create_item", createItem.getName());
        assertTrue(createItem.isAsync());
        assertEquals(List.of("item_id", "payload"), createItem.getParameters());
        assertEquals("router.post", createItem.getDecorators().get(0).getName());
    }

    @Test
    @DisplayName("Parse call expressions and keyword arguments")
    void testParseCallsAndKeywordArgs() {
        String pyCode = """
                def query_database(user_id):
                    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
                    subprocess.run(["ping", "-c", "1", "8.8.8.8"], shell=False, timeout=30)
                """;

        PythonModule module = parser.parse(pyCode, Path.of("db.py"));
        List<PythonCallExpr> calls = module.findAllCalls();
        assertEquals(2, calls.size());

        PythonCallExpr cursorCall = calls.get(0);
        assertEquals("execute", cursorCall.getCalleeName());
        assertEquals("cursor.execute", cursorCall.getFullCalleeName());
        assertEquals(2, cursorCall.getArguments().size());

        PythonCallExpr subpCall = calls.get(1);
        assertEquals("run", subpCall.getCalleeName());
        assertEquals("subprocess.run", subpCall.getFullCalleeName());
        assertNotNull(subpCall.getKeywordArgument("shell"));
        assertEquals("False", subpCall.getKeywordArgument("shell").getRawText());
        assertNotNull(subpCall.getKeywordArgument("timeout"));
        assertEquals("30", subpCall.getKeywordArgument("timeout").getRawText());
    }

    @Test
    @DisplayName("Parse assignment statements and variable references")
    void testParseAssignments() {
        String pyCode = """
                def build_cmd(ip_addr):
                    cmd = "ping -c 1 " + ip_addr
                    query = f"SELECT * FROM items WHERE ip = '{ip_addr}'"
                    return cmd
                """;

        PythonModule module = parser.parse(pyCode, Path.of("network.py"));
        List<PythonAssignStmt> assigns = module.findAllAssignments();
        assertEquals(2, assigns.size());

        PythonAssignStmt firstAssign = assigns.get(0);
        assertEquals("cmd", firstAssign.getPrimaryTarget());
        assertTrue(firstAssign.getValue() instanceof PythonBinaryExpr);
        PythonBinaryExpr bin = (PythonBinaryExpr) firstAssign.getValue();
        assertEquals("+", bin.getOperator());

        PythonAssignStmt secondAssign = assigns.get(1);
        assertEquals("query", secondAssign.getPrimaryTarget());
        assertTrue(secondAssign.getValue() instanceof PythonLiteralExpr);
        assertEquals(PythonLiteralExpr.Kind.FSTRING, ((PythonLiteralExpr) secondAssign.getValue()).getKind());
    }

    @Test
    @DisplayName("Parse try/except/finally blocks with exception typing and aliases")
    void testParseTryExcept() {
        String pyCode = """
                def safe_action():
                    try:
                        perform_op()
                    except (ValueError, KeyError) as e:
                        log_error(e)
                    finally:
                        cleanup()
                """;

        PythonModule module = parser.parse(pyCode, Path.of("safety.py"));
        PythonFunctionDef func = module.getFunctions().get(0);
        assertEquals(1, func.getBody().size());
        assertTrue(func.getBody().get(0) instanceof PythonTryStmt);

        PythonTryStmt tryStmt = (PythonTryStmt) func.getBody().get(0);
        assertEquals(1, tryStmt.getTryBody().size());
        assertEquals(1, tryStmt.getExceptClauses().size());

        PythonExceptClause exceptClause = tryStmt.getExceptClauses().get(0);
        assertTrue(exceptClause.getExceptionType().contains("ValueError"));
        assertEquals("e", exceptClause.getExceptionAlias());
        assertEquals(1, exceptClause.getBody().size());

        assertEquals(1, tryStmt.getFinallyBody().size());
    }

    @Test
    @DisplayName("Verify AST Visitor traverses all nodes in Python module")
    void testAstVisitor() {
        String pyCode = """
                import math

                class MathUtil:
                    def square(self, x):
                        result = x * x
                        return result
                """;

        PythonModule module = parser.parse(pyCode, Path.of("calc.py"));
        List<String> visited = new ArrayList<>();

        module.accept(new PythonAstVisitor() {
            @Override
            public void visit(PythonImportStmt importStmt) {
                visited.add("import:" + importStmt.getModuleName());
            }

            @Override
            public void visit(PythonClassDef classDef) {
                visited.add("class:" + classDef.getName());
                PythonAstVisitor.super.visit(classDef);
            }

            @Override
            public void visit(PythonFunctionDef functionDef) {
                visited.add("func:" + functionDef.getName());
                PythonAstVisitor.super.visit(functionDef);
            }

            @Override
            public void visit(PythonAssignStmt assignStmt) {
                visited.add("assign:" + assignStmt.getPrimaryTarget());
                PythonAstVisitor.super.visit(assignStmt);
            }
        });

        assertTrue(visited.contains("import:math"));
        assertTrue(visited.contains("class:MathUtil"));
        assertTrue(visited.contains("func:square"));
        assertTrue(visited.contains("assign:result"));
    }
}
