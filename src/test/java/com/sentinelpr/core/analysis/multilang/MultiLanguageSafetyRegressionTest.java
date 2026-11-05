package com.sentinelpr.core.analysis.multilang;

import com.sentinelpr.client.DeveloperFacade;
import com.sentinelpr.core.model.InspectedSource;
import com.sentinelpr.core.model.SecurityFinding;
import com.sentinelpr.core.model.SecurityRule;
import com.sentinelpr.core.model.Severity;
import com.sentinelpr.core.model.SourceLanguage;
import com.sentinelpr.core.model.UnifiedDiffPatch;
import com.sentinelpr.core.remediation.PatchValidationStatus;
import com.sentinelpr.core.service.CodeInspectionService;
import com.sentinelpr.core.service.PatchComposer;
import com.sentinelpr.core.service.PatchVerificationResult;
import com.sentinelpr.core.service.PatchVerifier;
import com.sentinelpr.core.service.RuleEvaluationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Phase 4B.1.1: Multi-Language Safety Corrections Regression Test Suite")
public class MultiLanguageSafetyRegressionTest {

    private CodeInspectionService inspectionService;
    private RuleEvaluationService evaluationService;
    private PatchComposer patchComposer;
    private PatchVerifier patchVerifier;

    @BeforeEach
    void setUp() {
        this.inspectionService = new CodeInspectionService();
        this.evaluationService = new RuleEvaluationService();
        this.patchVerifier = new PatchVerifier(inspectionService, evaluationService);
        this.patchComposer = new PatchComposer(com.sentinelpr.client.SentinelClient.getInstance());
    }

    // ─── Fix 1: Non-Java Patch Safety ─────────────────────────────────────────

    @Test
    @DisplayName("Fix 1: Kotlin findings require manual remediation and must not invoke JavaParser")
    void testNonJavaPatchSafety_Kotlin() {
        String code = """
                package com.example
                class KotlinRunner {
                    fun run(cmd: String) {
                        Runtime.getRuntime().exec(cmd)
                    }
                }
                """;
        InspectedSource source = inspectionService.inspectSourceCode(code, "KotlinRunner.kt");
        assertEquals(SourceLanguage.KOTLIN, source.getLanguage());

        List<SecurityFinding> findings = evaluationService.evaluate(source);
        assertFalse(findings.isEmpty(), "Must detect finding in Kotlin source");

        // 1. Compose patch
        UnifiedDiffPatch patch = patchComposer.compose(source, findings);
        assertNotNull(patch);
        assertEquals(UnifiedDiffPatch.Status.MANUAL_REMEDIATION_REQUIRED, patch.getStatus());
        assertEquals(PatchValidationStatus.MANUAL_REMEDIATION_REQUIRED, patch.getValidationStatus());
        assertFalse(patch.isVerified());
        assertFalse(patch.isRegressionVerified());
        assertEquals("", patch.getUnifiedDiff(), "Must not generate unified diff for non-Java source");
        assertTrue(patch.getVerificationMessage().contains("Manual remediation required"));

        // 2. Direct PatchVerifier on .kt
        PatchVerificationResult verResult = patchVerifier.verify(code, "KotlinRunner.kt");
        assertFalse(verResult.isSyntaxValid());
        assertFalse(verResult.isRegressionVerified());
        assertEquals(PatchValidationStatus.MANUAL_REMEDIATION_REQUIRED, verResult.getValidationStatus());
    }

    @Test
    @DisplayName("Fix 1: Python findings require manual remediation and must not invoke JavaParser")
    void testNonJavaPatchSafety_Python() {
        String code = """
                import os
                def execute(user_cmd):
                    os.system(user_cmd)
                """;
        InspectedSource source = inspectionService.inspectSourceCode(code, "runner.py");
        assertEquals(SourceLanguage.PYTHON, source.getLanguage());

        List<SecurityFinding> findings = evaluationService.evaluate(source);
        assertFalse(findings.isEmpty(), "Must detect finding in Python source");

        UnifiedDiffPatch patch = patchComposer.compose(source, findings);
        assertNotNull(patch);
        assertEquals(UnifiedDiffPatch.Status.MANUAL_REMEDIATION_REQUIRED, patch.getStatus());
        assertEquals(PatchValidationStatus.MANUAL_REMEDIATION_REQUIRED, patch.getValidationStatus());
        assertFalse(patch.isVerified());
        assertEquals("", patch.getUnifiedDiff());

        PatchVerificationResult verResult = patchVerifier.verify(code, "runner.py");
        assertEquals(PatchValidationStatus.MANUAL_REMEDIATION_REQUIRED, verResult.getValidationStatus());
    }

    @Test
    @DisplayName("Fix 1: JavaScript/TypeScript findings require manual remediation and must not invoke JavaParser")
    void testNonJavaPatchSafety_JavaScriptAndTypeScript() {
        String jsCode = "const cp = require('child_process'); function run(c) { cp.exec(c); }";
        InspectedSource jsSource = inspectionService.inspectSourceCode(jsCode, "exec.js");
        List<SecurityFinding> jsFindings = evaluationService.evaluate(jsSource);
        assertFalse(jsFindings.isEmpty());

        UnifiedDiffPatch jsPatch = patchComposer.compose(jsSource, jsFindings);
        assertEquals(UnifiedDiffPatch.Status.MANUAL_REMEDIATION_REQUIRED, jsPatch.getStatus());
        assertEquals(PatchValidationStatus.MANUAL_REMEDIATION_REQUIRED, jsPatch.getValidationStatus());
        assertEquals("", jsPatch.getUnifiedDiff());

        String tsCode = "import cp from 'child_process'; export function run(c: string) { cp.exec(c); }";
        InspectedSource tsSource = inspectionService.inspectSourceCode(tsCode, "exec.ts");
        List<SecurityFinding> tsFindings = evaluationService.evaluate(tsSource);
        assertFalse(tsFindings.isEmpty());

        UnifiedDiffPatch tsPatch = patchComposer.compose(tsSource, tsFindings);
        assertEquals(UnifiedDiffPatch.Status.MANUAL_REMEDIATION_REQUIRED, tsPatch.getStatus());
        assertEquals(PatchValidationStatus.MANUAL_REMEDIATION_REQUIRED, tsPatch.getValidationStatus());
    }

    @Test
    @DisplayName("Fix 1: Java patch synthesis and verification remain completely unaffected")
    void testJavaPatchSynthesisUnaffected() {
        String javaCode = """
                package com.example;
                public class AccountService {
                    private volatile int counter = 0;
                    public void increment() {
                        counter++;
                    }
                }
                """;
        InspectedSource source = inspectionService.inspectSourceCode(javaCode, "AccountService.java");
        assertEquals(SourceLanguage.JAVA, source.getLanguage());

        List<SecurityFinding> findings = evaluationService.evaluate(source);
        assertFalse(findings.isEmpty(), "Must detect volatile compound op finding");

        UnifiedDiffPatch patch = patchComposer.compose(source, findings);
        assertNotNull(patch);
        assertEquals(UnifiedDiffPatch.Status.SUCCESS, patch.getStatus());
        assertEquals(PatchValidationStatus.VALID_PATCH, patch.getValidationStatus());
        assertTrue(patch.isVerified());
        assertFalse(patch.getUnifiedDiff().isBlank(), "Unified diff must be generated for Java");
    }

    // ─── Fix 2: Python File-Wide Suppression Corrections ─────────────────────

    @Test
    @DisplayName("Fix 2: Unrelated safe function must NOT suppress path traversal in vulnerable function")
    void testPythonPathTraversal_UnrelatedFunctionDoesNotSuppress() {
        String pythonCode = """
                import os

                def safe_download(user_file):
                    full_path = os.path.realpath(os.path.join("/var/data", user_file))
                    if not full_path.startswith("/var/data"):
                        raise ValueError("Access denied")
                    with open(full_path, "r") as f:
                        return f.read()

                def vulnerable_download(user_file):
                    with open("/var/data/" + user_file, "r") as f:
                        return f.read()
                """;
        InspectedSource source = inspectionService.inspectSourceCode(pythonCode, "file_service.py");
        List<SecurityFinding> findings = evaluationService.evaluate(source);

        List<SecurityFinding> ptFindings = findings.stream()
                .filter(f -> f.getRule() == SecurityRule.PATH_TRAVERSAL)
                .toList();

        assertEquals(1, ptFindings.size(), "Must detect exactly 1 path traversal in vulnerable_download");
        assertEquals("vulnerable_download", ptFindings.get(0).getMethodName(),
                "Finding must point to vulnerable_download, not safe_download");
    }

    @Test
    @DisplayName("Fix 2: Comments containing 'allowlist' must NOT suppress SSRF in vulnerable function")
    void testPythonSsrf_CommentDoesNotSuppress() {
        String pythonCode = """
                import requests

                # TODO: Implement allowlist validation for untrusted URLs
                # allowlist = ["api.trusted.com"]
                def fetch_webhook(target_url):
                    return requests.get(target_url).text
                """;
        InspectedSource source = inspectionService.inspectSourceCode(pythonCode, "webhook.py");
        List<SecurityFinding> findings = evaluationService.evaluate(source);

        assertTrue(findings.stream().anyMatch(f -> f.getRule() == SecurityRule.SSRF),
                "Comment containing 'allowlist' must NOT suppress SSRF finding in fetch_webhook");
    }

    @Test
    @DisplayName("Fix 2: Allowlist in one function must NOT suppress SSRF in another function")
    void testPythonSsrf_UnrelatedFunctionDoesNotSuppress() {
        String pythonCode = """
                import requests

                def safe_fetch(url):
                    allowlist = ["https://trusted.domain.com"]
                    if url in allowlist:
                        return requests.get(url).text
                    raise ValueError("Not allowed")

                def unguarded_fetch(user_url):
                    return requests.get(user_url).text
                """;
        InspectedSource source = inspectionService.inspectSourceCode(pythonCode, "client.py");
        List<SecurityFinding> findings = evaluationService.evaluate(source);

        List<SecurityFinding> ssrfFindings = findings.stream()
                .filter(f -> f.getRule() == SecurityRule.SSRF)
                .toList();

        assertEquals(1, ssrfFindings.size(), "Must detect exactly 1 SSRF finding in unguarded_fetch");
        assertEquals("unguarded_fetch", ssrfFindings.get(0).getMethodName());
    }

    @Test
    @DisplayName("Fix 2: Insecure random is scoped properly to token/security contexts without false positives on dice rolls")
    void testPythonInsecureRandom_ScopedCorrectly() {
        String pythonCode = """
                import random

                def roll_dice():
                    return random.randint(1, 6)

                def generate_auth_token():
                    token = random.random()
                    return str(token)
                """;
        InspectedSource source = inspectionService.inspectSourceCode(pythonCode, "game_and_auth.py");
        List<SecurityFinding> findings = evaluationService.evaluate(source);

        List<SecurityFinding> randFindings = findings.stream()
                .filter(f -> f.getRule() == SecurityRule.INSECURE_RANDOM)
                .toList();

        assertEquals(1, randFindings.size(), "Only generate_auth_token must be flagged, not roll_dice");
        assertEquals("generate_auth_token", randFindings.get(0).getMethodName());
    }

    @Test
    @DisplayName("Milestone 3 Negative: React Query refetch() and UI button callbacks do not trigger false positive SSRF")
    void testNodeJsSsrf_ClientSideRefetchDoesNotMatch() {
        String tsxCode = """
                "use client";
                import React, { useCallback } from 'react';

                export function AlertsDrawer({ refetch }) {
                    return (
                        <div>
                            <button onClick={() => refetch()}>Refresh Data</button>
                            <button onClick={() => query.refetch()}>Query Refetch</button>
                        </div>
                    );
                }
                """;
        InspectedSource source = inspectionService.inspectSourceCode(tsxCode, "frontend/src/components/alerts/AlertsDrawer.tsx");
        List<SecurityFinding> findings = evaluationService.evaluate(source);

        assertTrue(findings.stream().noneMatch(f -> f.getRule() == SecurityRule.SSRF),
                "Client-side React refetch() callbacks must never produce SSRF findings");
    }

    @Test
    @DisplayName("Milestone 3 Negative: Hardcoded static URLs in fetch/axios do not trigger SSRF")
    void testNodeJsSsrf_HardcodedUrlDoesNotTrigger() {
        String jsCode = """
                export async function pollData() {
                    const response = await apiClient.post("/connectors/poll");
                    const status = await fetch("https://status.example.com/health");
                    return response.data;
                }
                """;
        InspectedSource source = inspectionService.inspectSourceCode(jsCode, "apiService.js");
        List<SecurityFinding> findings = evaluationService.evaluate(source);

        assertTrue(findings.stream().noneMatch(f -> f.getRule() == SecurityRule.SSRF),
                "Hardcoded URLs like '/connectors/poll' or 'https://...' must not produce SSRF findings");
    }

    @Test
    @DisplayName("Milestone 3 Positive: Server-side Node.js fetch with dynamic destination is detected as SSRF")
    void testNodeJsSsrf_ServerSideDynamicDestination_Detected() {
        String serverCode = """
                const express = require('express');
                const app = express();

                app.get('/proxy', async (req, res) => {
                    const target = req.query.url;
                    const response = await fetch(target);
                    const body = await response.text();
                    res.send(body);
                });
                """;
        InspectedSource source = inspectionService.inspectSourceCode(serverCode, "server/proxyRouter.js");
        List<SecurityFinding> findings = evaluationService.evaluate(source);

        List<SecurityFinding> ssrf = findings.stream()
                .filter(f -> f.getRule() == SecurityRule.SSRF)
                .toList();

        assertEquals(1, ssrf.size(), "Dynamic fetch(target) in server code must trigger SEC-012-SSRF");
        assertEquals(SecurityRule.SSRF, ssrf.get(0).getRule());
        assertEquals(Severity.CRITICAL, ssrf.get(0).getSeverity());
    }
}
