package com.sentinelpr;

import com.sentinelpr.api.SentinelReviewController;
import com.sentinelpr.core.model.ReviewReport;
import com.sentinelpr.core.model.SecurityRule;
import com.sentinelpr.core.model.UnifiedDiffPatch;
import com.sentinelpr.core.service.CodeInspectionService;
import com.sentinelpr.core.service.PatchComposer;
import com.sentinelpr.core.service.ReviewSessionMemory;
import com.sentinelpr.core.service.RuleEvaluationService;
import com.sentinelpr.core.service.SentinelAuditOrchestrator;
import com.sentinelpr.client.SentinelClient;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.WebApplicationType;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * <b>SentinelPrStartupAndExecutionTest</b>
 *
 * <p>Validates Release Blocker Remediation across startup modes:</p>
 * <ul>
 *   <li>Direct application entry point execution in CLI mode (without unnecessary web context initialization)</li>
 *   <li>CLI help, usage, and error handling contracts</li>
 *   <li>Java and Python sample scanning through application entry point</li>
 *   <li>Real Spring Boot Web Application startup with clean {@link SentinelReviewController} dependency injection</li>
 * </ul>
 */
@DisplayName("Release Blocker Remediation: Startup Architecture & Execution Tests")
public class SentinelPrStartupAndExecutionTest {

    @Test
    @DisplayName("CLI Startup: No arguments prints usage and returns exit code 3")
    void testDirectApplicationStartup_NoArgsReturnsUsageExitCode3() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        PrintStream origOut = System.out;
        try {
            System.setOut(new PrintStream(out));
            int exitCode = SentinelPrApplication.run(new String[0]);
            assertEquals(3, exitCode, "No arguments must return exit code 3");
            String output = out.toString();
            assertTrue(output.contains("Usage: java -jar sentinel-pr.jar"), "Must print CLI usage header");
            assertTrue(output.contains("--server"), "Must document --server option in usage");
        } finally {
            System.setOut(origOut);
        }
    }

    @Test
    @DisplayName("CLI Startup: Explicit --help flag prints usage and returns exit code 0")
    void testDirectApplicationStartup_HelpFlagReturns0() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        PrintStream origOut = System.out;
        try {
            System.setOut(new PrintStream(out));
            int exitCode = SentinelPrApplication.run(new String[]{"--help"});
            assertEquals(0, exitCode, "--help must return exit code 0");
            assertTrue(out.toString().contains("Usage: java -jar sentinel-pr.jar"), "Must print CLI usage");
        } finally {
            System.setOut(origOut);
        }
    }

    @Test
    @DisplayName("CLI Startup: Non-existent target path returns controlled exit code 3")
    void testDirectApplicationStartup_InvalidTargetReturns3(@TempDir Path tempDir) {
        Path nonExistent = tempDir.resolve("MissingFile.java");
        int exitCode = SentinelPrApplication.run(new String[]{nonExistent.toString()});
        assertEquals(3, exitCode, "Missing target path must return exit code 3");
    }

    @Test
    @DisplayName("CLI Startup: Representative Java sample scan executes cleanly and outputs verified patch")
    void testDirectApplicationStartup_JavaSampleScanSuccess(@TempDir Path tempDir) throws IOException {
        Path javaFile = tempDir.resolve("VulnerableSample.java");
        Files.writeString(javaFile, """
                package com.example;
                public class VulnerableSample {
                    public void runCommand(String cmd) throws Exception {
                        Runtime.getRuntime().exec(cmd);
                    }
                }
                """);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        PrintStream origOut = System.out;
        try {
            System.setOut(new PrintStream(out));
            int exitCode = SentinelPrApplication.run(new String[]{javaFile.toString()});
            assertEquals(0, exitCode, "Successful scan on vulnerable sample must return exit code 0");
            String output = out.toString();
            assertTrue(output.contains("UNISOLATED_SUBPROCESS"), "Must detect UNISOLATED_SUBPROCESS finding");
            assertTrue(output.contains("Synthesized Verified Patches"), "Must synthesize verified patch diff");
        } finally {
            System.setOut(origOut);
        }
    }

    @Test
    @DisplayName("CLI Startup: Representative Python sample scan detects finding and enforces manual remediation")
    void testDirectApplicationStartup_PythonSampleScanManualRemediation(@TempDir Path tempDir) throws IOException {
        Path pyFile = tempDir.resolve("sample_app.py");
        Files.writeString(pyFile, """
                import os
                def exec_service(request):
                    cmd = request.args.get("command")
                    os.system(cmd)
                """);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        PrintStream origOut = System.out;
        try {
            System.setOut(new PrintStream(out));
            int exitCode = SentinelPrApplication.run(new String[]{pyFile.toString()});
            assertEquals(0, exitCode, "Python scan must complete with exit code 0");
            String output = out.toString();
            assertTrue(output.contains("PYTHON_COMMAND_INJECTION") || output.contains("os.system"),
                    "Must identify command execution in Python sample");
        } finally {
            System.setOut(origOut);
        }

        // Verify engine remediation boundary directly
        CodeInspectionService inspectionService = new CodeInspectionService();
        RuleEvaluationService evaluationService = new RuleEvaluationService();
        PatchComposer patchComposer = new PatchComposer(SentinelClient.getInstance());

        com.sentinelpr.core.model.InspectedSource source = inspectionService.inspectFile(pyFile);
        java.util.List<com.sentinelpr.core.model.SecurityFinding> findings = evaluationService.evaluate(source);
        assertFalse(findings.isEmpty(), "Must identify command execution finding in Python sample");
        assertEquals(SecurityRule.UNISOLATED_SUBPROCESS, findings.get(0).getRule());

        UnifiedDiffPatch patch = patchComposer.compose(source, findings);
        assertEquals(UnifiedDiffPatch.Status.MANUAL_REMEDIATION_REQUIRED, patch.getStatus());
        assertTrue(patch.getUnifiedDiff().isEmpty(), "Python patch must contain empty unified diff");
    }

    @Test
    @DisplayName("Server Mode: SentinelPrApplication.isServerMode correctly recognizes server flags")
    void testServerModeDetection() {
        assertFalse(SentinelPrApplication.isServerMode(new String[0]));
        assertFalse(SentinelPrApplication.isServerMode(new String[]{"src/main/java"}));
        assertFalse(SentinelPrApplication.isServerMode(new String[]{"--diff", "diff.patch"}));
        assertFalse(SentinelPrApplication.isServerMode(new String[]{"--help"}));

        assertTrue(SentinelPrApplication.isServerMode(new String[]{"--server"}));
        assertTrue(SentinelPrApplication.isServerMode(new String[]{"--server.port=9090"}));
        assertTrue(SentinelPrApplication.isServerMode(new String[]{"--web"}));
        assertTrue(SentinelPrApplication.isServerMode(new String[]{"-server"}));
    }

    @Test
    @DisplayName("Web Application Startup: Spring Boot servlet context initializes with cleanly injected SentinelReviewController")
    void testWebApplicationStartup_ContextLoadsAndControllerInjected() {
        SpringApplication app = new SpringApplication(SentinelPrApplication.class);
        app.setWebApplicationType(WebApplicationType.SERVLET);
        app.setDefaultProperties(Map.of(
                "server.port", "0",
                "spring.main.banner-mode", "off"
        ));
        ConfigurableApplicationContext context = app.run("--server");
        try {
            assertNotNull(context, "Spring application context must load successfully");
            SentinelReviewController controller = context.getBean(SentinelReviewController.class);
            assertNotNull(controller, "SentinelReviewController must be autowired in context");

            ResponseEntity<Map<String, Object>> health = controller.health();
            assertNotNull(health);
            assertEquals(HttpStatus.OK, health.getStatusCode());
            assertEquals("UP", health.getBody().get("status"));
        } finally {
            context.close();
        }
    }
}
