package com.sentinelpr.core.analysis.multilang.python;

import com.sentinelpr.core.analysis.multilang.python.ast.*;
import com.sentinelpr.core.model.InspectedSource;
import com.sentinelpr.core.model.SourceLanguage;
import com.sentinelpr.core.service.CodeInspectionService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * <b>PythonParserAuditTest</b>
 *
 * <p>Phase 5.1: Adversarial parser audit verifying resilience, isolation, and exact grammar support
 * across malformed files, modern Python syntax, Unicode encoding, and edge cases.</p>
 */
@DisplayName("Phase 5.1: Python Parser Adversarial & Limitation Audit")
public class PythonParserAuditTest {

    private PythonSourceParser parser;
    private CodeInspectionService inspectionService;

    @BeforeEach
    void setUp() {
        this.parser = new PythonSourceParser();
        this.inspectionService = new CodeInspectionService();
    }

    @Test
    @DisplayName("Grammar: Async functions, type annotations, and multiple decorators")
    void testAsyncAndDecoratedFunctions() {
        String code = """
                @app.route("/api/v1/data", methods=["GET", "POST"])
                @auth_required(role="admin")
                async def fetch_records(request: Request, limit: int = 100) -> List[Dict[str, Any]]:
                    '''Docstring explaining async fetch.'''
                    results = await db.query()
                    return results
                """;

        PythonModule module = parser.parse(code, Path.of("routes.py"));
        assertNotNull(module);
        assertEquals(1, module.getFunctions().size());

        PythonFunctionDef func = module.getFunctions().get(0);
        assertEquals("fetch_records", func.getName());
        assertTrue(func.isAsync(), "Must recognize async function definition");
        assertEquals(2, func.getDecorators().size(), "Must capture all decorators");
        assertEquals("app.route", func.getDecorators().get(0).getName());
        assertEquals("auth_required", func.getDecorators().get(1).getName());
        assertTrue(func.getDocstring().contains("Docstring explaining async fetch."));
        assertTrue(func.getParameters().contains("request"));
        assertTrue(func.getParameters().contains("limit"));
    }

    @Test
    @DisplayName("Grammar: Classes with multiple inheritance and nested methods")
    void testClassesWithMultipleInheritance() {
        String code = """
                class BaseController:
                    pass

                class AuditMixin:
                    def log_action(self, action: str):
                        pass

                class AdminController(BaseController, AuditMixin):
                    '''Admin controller handling sensitive operations.'''
                    def execute_action(self, cmd: str):
                        self.log_action(cmd)
                """;

        PythonModule module = parser.parse(code, Path.of("controllers.py"));
        assertNotNull(module);
        assertEquals(3, module.getClasses().size());

        PythonClassDef adminClass = module.getClasses().stream()
                .filter(c -> "AdminController".equals(c.getName()))
                .findFirst()
                .orElse(null);

        assertNotNull(adminClass);
        assertEquals(2, adminClass.getBases().size());
        assertTrue(adminClass.getBases().contains("BaseController"));
        assertTrue(adminClass.getBases().contains("AuditMixin"));
        assertTrue(adminClass.getDocstring().contains("Admin controller handling sensitive operations."));
        assertEquals(1, adminClass.getMethods().size());
        assertEquals("execute_action", adminClass.getMethods().get(0).getName());
    }

    @Test
    @DisplayName("Grammar: Unicode characters, emojis, and multiline string literals")
    void testUnicodeAndMultilineLiterals() {
        String code = """
                # -*- coding: utf-8 -*-
                SECURITY_HEADER = "🛡️ SentinelPR \u00a9 2026"
                MULTILINE_BANNER = '''
                    ╔═══════════════════════════════════════╗
                    ║   HIGH SECURITY MULTILINE STRING      ║
                    ╚═══════════════════════════════════════╝
                '''
                def greet(user_名):
                    msg = f"こんにちは, {user_名}! 🚀"
                    return msg
                """;

        PythonModule module = parser.parse(code, Path.of("unicode_test.py"));
        assertNotNull(module);
        assertFalse(module.getFunctions().isEmpty());
        assertEquals("greet", module.getFunctions().get(0).getName());
    }

    @Test
    @DisplayName("Adversarial: Malformed unclosed delimiters, quotes, and indentation")
    void testAdversarialMalformedFilesDoNotCrashParser() {
        String malformed1 = "def broken(\n  a = [1, 2, (3, 4\n\n\n# Missing closing brackets";
        PythonModule m1 = parser.parse(malformed1, Path.of("broken1.py"));
        assertNotNull(m1, "Must handle unclosed delimiter without crashing");

        String malformed2 = "x = \"unclosed string literal\ny = 42\n";
        PythonModule m2 = parser.parse(malformed2, Path.of("broken2.py"));
        assertNotNull(m2, "Must handle unclosed string without crashing");

        String malformed3 = "    def bad_indent():\npass\n      return";
        PythonModule m3 = parser.parse(malformed3, Path.of("broken3.py"));
        assertNotNull(m3, "Must handle inconsistent indentation without crashing");
    }

    @Test
    @DisplayName("Isolation: Parsing failure on one malformed file does not abort directory scan")
    void testDirectoryScanIsolationOnMalformedFile(@TempDir Path tempDir) throws IOException {
        Path validPy = tempDir.resolve("valid.py");
        Files.writeString(validPy, "import os\ndef run(c):\n    os.system(c)\n");

        Path invalidPy = tempDir.resolve("corrupted.py");
        Files.writeString(invalidPy, "def <<<< INVALID PYTHON SYNTAX ???? {{{{");

        List<InspectedSource> sources = inspectionService.inspectDirectory(tempDir);
        assertNotNull(sources);
        assertTrue(sources.stream().anyMatch(s -> s.getFilePath().toString().endsWith("valid.py")),
                "Valid Python file must be successfully inspected despite corrupted sibling");
    }
}
