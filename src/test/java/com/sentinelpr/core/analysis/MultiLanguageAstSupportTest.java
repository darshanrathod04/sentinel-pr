package com.sentinelpr.core.analysis;

import com.sentinelpr.core.model.InspectedSource;
import com.sentinelpr.core.model.SecurityFinding;
import com.sentinelpr.core.model.SecurityRule;
import com.sentinelpr.core.model.SourceLanguage;
import com.sentinelpr.core.service.CodeInspectionService;
import com.sentinelpr.core.service.RuleEvaluationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class MultiLanguageAstSupportTest {

    private CodeInspectionService inspectionService;
    private RuleEvaluationService evaluationService;

    @BeforeEach
    void setUp() {
        this.inspectionService = new CodeInspectionService();
        this.evaluationService = new RuleEvaluationService();
    }

    @Test
    @DisplayName("Language Detection from Path and File Extension")
    void testLanguageDetection() {
        assertEquals(SourceLanguage.JAVA, SourceLanguage.fromPath(Path.of("UserService.java")));
        assertEquals(SourceLanguage.KOTLIN, SourceLanguage.fromPath(Path.of("OrderService.kt")));
        assertEquals(SourceLanguage.KOTLIN, SourceLanguage.fromPath(Path.of("build.gradle.kts")));
        assertEquals(SourceLanguage.PYTHON, SourceLanguage.fromPath(Path.of("app.py")));
        assertEquals(SourceLanguage.PYTHON, SourceLanguage.fromPath(Path.of("worker.pyw")));
        assertEquals(SourceLanguage.PYTHON, SourceLanguage.fromPath(Path.of("types.pyi")));
        assertEquals(SourceLanguage.JAVASCRIPT, SourceLanguage.fromPath(Path.of("server.js")));
        assertEquals(SourceLanguage.JAVASCRIPT, SourceLanguage.fromPath(Path.of("index.mjs")));
        assertEquals(SourceLanguage.TYPESCRIPT, SourceLanguage.fromPath(Path.of("client.ts")));
        assertEquals(SourceLanguage.TYPESCRIPT, SourceLanguage.fromPath(Path.of("App.tsx")));
        assertTrue(SourceLanguage.isSupported(Path.of("test.py")));
        assertTrue(SourceLanguage.isSupported(Path.of("types.pyi")));
        assertTrue(SourceLanguage.isSupported(Path.of("test.kt")));
        assertTrue(SourceLanguage.isSupported(Path.of("test.ts")));
        assertFalse(SourceLanguage.isSupported(Path.of("README.md")));
        assertFalse(SourceLanguage.isSupported(Path.of("pom.xml")));
    }

    @Test
    @DisplayName("Kotlin: Command Injection via Runtime.exec()")
    void testKotlinSubprocessCommandInjection() {
        String kotlinCode = """
            package com.example.service
            import java.lang.Runtime
            
            class DeployService {
                fun executeDeploy(branch: String) {
                    val cmd = "git checkout " + branch
                    Runtime.getRuntime().exec(cmd)
                }
            }
            """;
        InspectedSource source = inspectionService.inspectSourceCode(kotlinCode, "DeployService.kt");
        assertEquals(SourceLanguage.KOTLIN, source.getLanguage());

        List<SecurityFinding> findings = evaluationService.evaluate(source);
        assertTrue(findings.stream().anyMatch(f -> f.getRule() == SecurityRule.UNISOLATED_SUBPROCESS),
                "Must detect un-isolated subprocess execution in Kotlin");
    }

    @Test
    @DisplayName("Kotlin: SQL Injection via rawQuery with string interpolation")
    void testKotlinSqlInjection() {
        String kotlinCode = """
            package com.example.repo
            import android.database.sqlite.SQLiteDatabase
            
            class UserRepo(private val db: SQLiteDatabase) {
                fun findUser(username: String) {
                    val sql = "SELECT * FROM users WHERE name = '$username'"
                    db.rawQuery(sql, null)
                }
            }
            """;
        InspectedSource source = inspectionService.inspectSourceCode(kotlinCode, "UserRepo.kt");
        List<SecurityFinding> findings = evaluationService.evaluate(source);
        assertTrue(findings.stream().anyMatch(f -> f.getRule() == SecurityRule.SQL_INJECTION),
                "Must detect SQL injection in Kotlin");
    }

    @Test
    @DisplayName("Kotlin: Path Traversal, Weak Crypto, and Insecure Random")
    void testKotlinPathTraversalAndWeakCrypto() {
        String kotlinCode = """
            package com.example.util
            import java.io.File
            import java.security.MessageDigest
            import java.util.Random
            
            class StorageUtil {
                fun getFile(fileName: String): File {
                    return File("/tmp/data/" + fileName)
                }
                fun hashPassword(pwd: String): ByteArray {
                    return MessageDigest.getInstance("MD5").digest(pwd.toByteArray())
                }
                fun generateToken(): Int {
                    return Random().nextInt(100000)
                }
            }
            """;
        InspectedSource source = inspectionService.inspectSourceCode(kotlinCode, "StorageUtil.kt");
        List<SecurityFinding> findings = evaluationService.evaluate(source);

        assertTrue(findings.stream().anyMatch(f -> f.getRule() == SecurityRule.PATH_TRAVERSAL),
                "Must detect Path Traversal in Kotlin");
        assertTrue(findings.stream().anyMatch(f -> f.getRule() == SecurityRule.WEAK_CRYPTO),
                "Must detect Weak Crypto (MD5) in Kotlin");
        assertTrue(findings.stream().anyMatch(f -> f.getRule() == SecurityRule.INSECURE_RANDOM),
                "Must detect Insecure Random in Kotlin");
    }

    @Test
    @DisplayName("Python: Shell Execution and Arbitrary Code Execution (os.system, eval)")
    void testPythonSubprocessCommandInjection() {
        String pythonCode = """
            import os
            import subprocess
            
            def run_job(command_input):
                os.system("bash -c " + command_input)
                eval("2 + " + command_input)
            """;
        InspectedSource source = inspectionService.inspectSourceCode(pythonCode, "job_runner.py");
        assertEquals(SourceLanguage.PYTHON, source.getLanguage());

        List<SecurityFinding> findings = evaluationService.evaluate(source);
        long execFindings = findings.stream().filter(f -> f.getRule() == SecurityRule.UNISOLATED_SUBPROCESS).count();
        assertTrue(execFindings >= 2, "Must detect both os.system and eval in Python");
    }

    @Test
    @DisplayName("Python: SQL Injection via f-strings in cursor.execute")
    void testPythonSqlInjection() {
        String pythonCode = """
            import sqlite3
            
            def get_account(cursor, user_id):
                query = f"SELECT * FROM accounts WHERE id = {user_id}"
                cursor.execute(query)
            """;
        InspectedSource source = inspectionService.inspectSourceCode(pythonCode, "db_access.py");
        List<SecurityFinding> findings = evaluationService.evaluate(source);

        assertTrue(findings.stream().anyMatch(f -> f.getRule() == SecurityRule.SQL_INJECTION),
                "Must detect SQL injection in Python cursor.execute");
    }

    @Test
    @DisplayName("Python: Insecure Deserialization via pickle.loads")
    void testPythonInsecureDeserializationPickle() {
        String pythonCode = """
            import pickle
            
            def process_payload(raw_data):
                return pickle.loads(raw_data)
            """;
        InspectedSource source = inspectionService.inspectSourceCode(pythonCode, "deserializer.py");
        List<SecurityFinding> findings = evaluationService.evaluate(source);

        assertTrue(findings.stream().anyMatch(f -> f.getRule() == SecurityRule.INSECURE_DESERIALIZATION),
                "Must detect insecure pickle deserialization in Python");
    }

    @Test
    @DisplayName("Python: Path Traversal and SSRF")
    void testPythonPathTraversalAndSsrf() {
        String pythonCode = """
            import requests
            
            def download_report(user_path, target_url):
                with open("/var/reports/" + user_path, "r") as f:
                    content = f.read()
                requests.get(target_url)
                return content
            """;
        InspectedSource source = inspectionService.inspectSourceCode(pythonCode, "report_service.py");
        List<SecurityFinding> findings = evaluationService.evaluate(source);

        assertTrue(findings.stream().anyMatch(f -> f.getRule() == SecurityRule.PATH_TRAVERSAL),
                "Must detect Path Traversal in Python open()");
        assertTrue(findings.stream().anyMatch(f -> f.getRule() == SecurityRule.SSRF),
                "Must detect SSRF in Python requests.get()");
    }

    @Test
    @DisplayName("JavaScript/TypeScript: Command Injection via child_process.exec")
    void testJavaScriptCommandInjectionChildProcess() {
        String jsCode = """
            const cp = require('child_process');
            
            function backup(directory) {
                cp.exec("tar -czf backup.tar.gz " + directory);
            }
            """;
        InspectedSource source = inspectionService.inspectSourceCode(jsCode, "backup.js");
        assertEquals(SourceLanguage.JAVASCRIPT, source.getLanguage());

        List<SecurityFinding> findings = evaluationService.evaluate(source);
        assertTrue(findings.stream().anyMatch(f -> f.getRule() == SecurityRule.UNISOLATED_SUBPROCESS),
                "Must detect Command Injection in Node.js child_process.exec");
    }

    @Test
    @DisplayName("TypeScript: SQL Injection via template literal")
    void testTypeScriptSqlInjection() {
        String tsCode = """
            import { Client } from 'pg';
            
            export class UserService {
                async search(client: Client, searchParam: string) {
                    return client.query(`SELECT * FROM users WHERE name = '${searchParam}'`);
                }
            }
            """;
        InspectedSource source = inspectionService.inspectSourceCode(tsCode, "UserService.ts");
        assertEquals(SourceLanguage.TYPESCRIPT, source.getLanguage());

        List<SecurityFinding> findings = evaluationService.evaluate(source);
        assertTrue(findings.stream().anyMatch(f -> f.getRule() == SecurityRule.SQL_INJECTION),
                "Must detect SQL Injection in TypeScript pg client query");
    }

    @Test
    @DisplayName("JavaScript: JWT None Algorithm Allowed (SEC-013)")
    void testJavaScriptJwtNoneAlgorithm() {
        String jsCode = """
            const jwt = require('jsonwebtoken');
            
            function verifyAuth(token, secretKey) {
                return jwt.verify(token, secretKey, { algorithms: ['none'] });
            }
            """;
        InspectedSource source = inspectionService.inspectSourceCode(jsCode, "auth.js");
        List<SecurityFinding> findings = evaluationService.evaluate(source);

        assertTrue(findings.stream().anyMatch(f -> f.getRule() == SecurityRule.JWT_NONE_ALGORITHM),
                "Must detect JWT 'none' algorithm allowed in Node.js");
    }

    @Test
    @DisplayName("JavaScript: DOM XSS and Path Traversal")
    void testJavaScriptXssAndPathTraversal() {
        String jsCode = """
            const fs = require('fs');
            
            function render(userInput, filePath) {
                document.getElementById('content').innerHTML = userInput;
                return fs.readFileSync("/data/" + filePath);
            }
            """;
        InspectedSource source = inspectionService.inspectSourceCode(jsCode, "renderer.js");
        List<SecurityFinding> findings = evaluationService.evaluate(source);

        assertTrue(findings.stream().anyMatch(f -> f.getRule() == SecurityRule.XSS),
                "Must detect DOM XSS in JavaScript");
        assertTrue(findings.stream().anyMatch(f -> f.getRule() == SecurityRule.PATH_TRAVERSAL),
                "Must detect Path Traversal in Node.js fs.readFileSync");
    }

    @Test
    @DisplayName("Multi-Language Hardcoded Secret Scanning (Python & TypeScript)")
    void testMultiLanguageSecretScanning() {
        String pythonSecrets = """
            # Cloud Configuration
            AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
            GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
            """;
        InspectedSource pySource = inspectionService.inspectSourceCode(pythonSecrets, "config.py");
        List<SecurityFinding> pyFindings = evaluationService.evaluate(pySource);
        assertTrue(pyFindings.stream().anyMatch(f -> f.getRule() == SecurityRule.HARDCODED_SECRET),
                "Must detect hardcoded secrets in Python source");

        String tsSecrets = """
            export const config = {
                awsKey: "AKIAIOSFODNN7EXAMPLE",
                privateKey: "-----BEGIN RSA PRIVATE KEY-----"
            };
            """;
        InspectedSource tsSource = inspectionService.inspectSourceCode(tsSecrets, "config.ts");
        List<SecurityFinding> tsFindings = evaluationService.evaluate(tsSource);
        assertTrue(tsFindings.stream().anyMatch(f -> f.getRule() == SecurityRule.HARDCODED_SECRET),
                "Must detect hardcoded secrets in TypeScript source");
    }

    @Test
    @DisplayName("CodeInspectionService: Recursive Multi-Language Directory Scanning")
    void testInspectDirectoryMultiLanguage(@TempDir Path tempDir) throws IOException {
        Files.writeString(tempDir.resolve("Service.java"), "public class Service {}");
        Files.writeString(tempDir.resolve("Handler.kt"), "class Handler");
        Files.writeString(tempDir.resolve("script.py"), "print('hello')");
        Files.writeString(tempDir.resolve("index.js"), "console.log('js');");
        Files.writeString(tempDir.resolve("types.ts"), "export type ID = string;");
        Files.writeString(tempDir.resolve("ignored.txt"), "This should be ignored.");

        List<InspectedSource> sources = inspectionService.inspectDirectory(tempDir);
        assertEquals(5, sources.size(), "Must discover and inspect exactly 5 multi-language files");

        assertTrue(sources.stream().anyMatch(s -> s.getLanguage() == SourceLanguage.JAVA));
        assertTrue(sources.stream().anyMatch(s -> s.getLanguage() == SourceLanguage.KOTLIN));
        assertTrue(sources.stream().anyMatch(s -> s.getLanguage() == SourceLanguage.PYTHON));
        assertTrue(sources.stream().anyMatch(s -> s.getLanguage() == SourceLanguage.JAVASCRIPT));
        assertTrue(sources.stream().anyMatch(s -> s.getLanguage() == SourceLanguage.TYPESCRIPT));
    }
}
