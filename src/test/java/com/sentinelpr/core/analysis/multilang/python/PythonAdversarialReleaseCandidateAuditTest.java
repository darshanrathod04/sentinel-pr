package com.sentinelpr.core.analysis.multilang.python;

import com.sentinelpr.core.model.InspectedSource;
import com.sentinelpr.core.model.SecurityFinding;
import com.sentinelpr.core.model.SecurityRule;
import com.sentinelpr.core.model.UnifiedDiffPatch;
import com.sentinelpr.core.service.CodeInspectionService;
import com.sentinelpr.core.service.PatchComposer;
import com.sentinelpr.core.service.RuleEvaluationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * <b>PythonAdversarialReleaseCandidateAuditTest</b>
 *
 * <p>Phase 5.3: Independent adversarial release candidate validation set evaluating
 * complex Python code structures, obfuscation resilience, and rule edge cases.</p>
 */
@DisplayName("Phase 5.3: Python Adversarial Release Candidate Validation Suite")
public class PythonAdversarialReleaseCandidateAuditTest {

    private CodeInspectionService inspectionService;
    private RuleEvaluationService evaluationService;
    private PatchComposer patchComposer;

    @BeforeEach
    void setUp() {
        this.inspectionService = new CodeInspectionService();
        this.evaluationService = new RuleEvaluationService();
        this.patchComposer = new PatchComposer(com.sentinelpr.client.SentinelClient.getInstance());
    }

    private static class TestCase {
        final String name;
        final String code;
        final boolean expectVulnerable;
        final SecurityRule expectedRule;

        TestCase(String name, String code, boolean expectVulnerable, SecurityRule expectedRule) {
            this.name = name;
            this.code = code;
            this.expectVulnerable = expectVulnerable;
            this.expectedRule = expectedRule;
        }
    }

    @Test
    @DisplayName("Evaluate Adversarial Validation Set across All Python Security Domains")
    void testAdversarialReleaseCandidateValidationSet() {
        List<TestCase> cases = List.of(
                // 1. SQLi: Dynamic string concatenation across parenthesized multiline query
                new TestCase(
                        "ADV-01-SQLi-Multiline-Concat",
                        """
                        import sqlite3
                        def search_orders(request):
                            order_status = request.args.get("status")
                            sql = (
                                "SELECT id, customer, amount "
                                "FROM orders "
                                "WHERE status = '" + order_status + "' "
                                "ORDER BY id DESC"
                            )
                            cursor.execute(sql)
                        """,
                        true,
                        SecurityRule.SQL_INJECTION
                ),
                // 2. SQLi: Safe control with parameterized tuple bindings and docstring mentioning SQL injection
                new TestCase(
                        "ADV-02-SQLi-Safe-Parameterized-Docstring",
                        """
                        import sqlite3
                        def search_orders_safe(request):
                            '''Vulnerable to SQL injection if not parameterized: SELECT * FROM orders WHERE status = 'x''''
                            order_status = request.args.get("status")
                            sql = "SELECT id, customer, amount FROM orders WHERE status = %s ORDER BY id DESC"
                            cursor.execute(sql, (order_status,))
                        """,
                        false,
                        null
                ),
                // 3. Command Injection: subprocess with shell=True and dynamic arguments
                new TestCase(
                        "ADV-03-CmdI-Subprocess-Shell-True",
                        """
                        import subprocess
                        def ping_host(request):
                            host = request.args.get("ip")
                            cmd = "ping -c 1 " + host
                            return subprocess.run(cmd, shell=True)
                        """,
                        true,
                        SecurityRule.UNISOLATED_SUBPROCESS
                ),
                // 4. Command Injection: Safe control using tokenized argument array with shell=False
                new TestCase(
                        "ADV-04-CmdI-Safe-Tokenized-Array",
                        """
                        import subprocess
                        def ping_host_safe(request):
                            host = request.args.get("ip")
                            # Safe: tokenized list without shell=True
                            return subprocess.run(["ping", "-c", "1", host], shell=False)
                        """,
                        false,
                        null
                ),
                // 5. Path Traversal: pathlib / operator with request parameter
                new TestCase(
                        "ADV-05-Path-Pathlib-Division",
                        """
                        from pathlib import Path
                        def view_invoice(request):
                            invoice_id = request.args.get("id")
                            root = Path("/var/invoices")
                            target = root / invoice_id
                            with open(target, "r") as f:
                                return f.read()
                        """,
                        true,
                        SecurityRule.PATH_TRAVERSAL
                ),
                // 6. Path Traversal: Safe control with realpath and startswith containment guard
                new TestCase(
                        "ADV-06-Path-Safe-Containment-Guard",
                        """
                        import os
                        def view_invoice_safe(request):
                            invoice_id = request.args.get("id")
                            base_dir = "/var/invoices"
                            target = os.path.realpath(os.path.join(base_dir, invoice_id))
                            if not target.startswith(base_dir):
                                raise PermissionError("Path traversal detected")
                            with open(target, "r") as f:
                                return f.read()
                        """,
                        false,
                        null
                ),
                // 7. SSRF & TLS: Outbound requests with verify=False on static URL
                new TestCase(
                        "ADV-07-TLS-Verify-Disabled-Static-Url",
                        """
                        import requests
                        def sync_crm():
                            # Dangerous: TLS validation explicitly disabled
                            return requests.get("https://crm.corp.internal/v2/sync", verify=False)
                        """,
                        true,
                        SecurityRule.FAIL_OPEN_SECURITY
                ),
                // 8. SSRF & TLS: Safe control with verify pointing to custom CA bundle file
                new TestCase(
                        "ADV-08-TLS-Safe-Custom-CA-Bundle",
                        """
                        import requests
                        def sync_crm_safe():
                            # Safe: Custom CA bundle supplied for enterprise internal PKI
                            ca_path = "/etc/ssl/certs/enterprise-root-ca.pem"
                            return requests.get("https://crm.corp.internal/v2/sync", verify=ca_path)
                        """,
                        false,
                        null
                ),
                // 9. Cookie Security: Sensitive auth token cookie missing HttpOnly and Secure flags
                new TestCase(
                        "ADV-09-Cookie-Insecure-Auth-Token",
                        """
                        from flask import Flask, make_response
                        app = Flask(__name__)
                        @app.route("/auth")
                        def authenticate(user_jwt):
                            resp = make_response("authenticated")
                            # Insecure: missing httponly=True and secure=True
                            resp.set_cookie("access_token", user_jwt)
                            return resp
                        """,
                        true,
                        SecurityRule.FAIL_OPEN_SECURITY
                ),
                // 10. Cookie Security: Safe control with full cookie flags and harmless UI preference cookie
                new TestCase(
                        "ADV-10-Cookie-Safe-Preferences-And-Flags",
                        """
                        from flask import Flask, make_response
                        app = Flask(__name__)
                        @app.route("/prefs")
                        def save_preferences(user_jwt):
                            resp = make_response("preferences saved")
                            # Harmless UI cookie: not flagged
                            resp.set_cookie("table_density", "compact")
                            # Sensitive auth cookie with full protection flags: not flagged
                            resp.set_cookie("access_token", user_jwt, httponly=True, secure=True, samesite="Strict")
                            return resp
                        """,
                        false,
                        null
                ),
                // 11. Deserialization: pickle.loads on unvalidated payload
                new TestCase(
                        "ADV-11-Deserialization-Pickle-Loads",
                        """
                        import pickle
                        def restore_session(session_bytes):
                            return pickle.loads(session_bytes)
                        """,
                        true,
                        SecurityRule.INSECURE_DESERIALIZATION
                ),
                // 12. Deserialization: Safe control with yaml.safe_load
                new TestCase(
                        "ADV-12-Deserialization-Safe-Yaml",
                        """
                        import yaml
                        def load_config(raw_yaml):
                            return yaml.safe_load(raw_yaml)
                        """,
                        false,
                        null
                )
        );

        int tp = 0;
        int fp = 0;
        int tn = 0;
        int fn = 0;
        int manualRemediationEnforced = 0;

        System.out.println("===============================================================================");
        System.out.println("       SENTINELPR PHASE 5.3 ADVERSARIAL VALIDATION SCORECARD (12 CASES)       ");
        System.out.println("===============================================================================");

        for (TestCase tc : cases) {
            InspectedSource source = inspectionService.inspectSourceCode(tc.code, tc.name + ".py");
            List<SecurityFinding> findings = evaluationService.evaluate(source);

            if (tc.expectVulnerable) {
                boolean hasExpectedRule = tc.expectedRule == null
                        || findings.stream().anyMatch(f -> f.getRule() == tc.expectedRule);
                if (!findings.isEmpty() && hasExpectedRule) {
                    tp++;
                    System.out.printf(" [PASS - TP] %-42s -> %d finding(s) [%s]%n",
                            tc.name, findings.size(), findings.get(0).getRule().getRuleId());

                    // Verify remediation boundary
                    UnifiedDiffPatch patch = patchComposer.compose(source, findings);
                    if (patch.getStatus() == UnifiedDiffPatch.Status.MANUAL_REMEDIATION_REQUIRED && patch.getUnifiedDiff().isEmpty()) {
                        manualRemediationEnforced++;
                    }
                } else {
                    fn++;
                    System.err.printf(" [FAIL - FN] %-42s -> Expected finding [%s] but got %d%n",
                            tc.name, tc.expectedRule, findings.size());
                }
            } else {
                if (findings.isEmpty()) {
                    tn++;
                    System.out.printf(" [PASS - TN] %-42s -> Clean (0 findings)%n", tc.name);
                } else {
                    fp++;
                    System.err.printf(" [FAIL - FP] %-42s -> Unexpected finding: %s%n",
                            tc.name, findings.get(0).getDescription());
                }
            }
        }

        double precision = (tp + fp) > 0 ? (double) tp / (tp + fp) * 100.0 : 0.0;
        double recall = (tp + fn) > 0 ? (double) tp / (tp + fn) * 100.0 : 0.0;
        double specificity = (tn + fp) > 0 ? (double) tn / (tn + fp) * 100.0 : 0.0;
        double accuracy = (tp + tn + fp + fn) > 0 ? (double) (tp + tn) / (tp + tn + fp + fn) * 100.0 : 0.0;
        double f1 = (precision + recall) > 0 ? 2 * (precision * recall) / (precision + recall) : 0.0;

        System.out.println("===============================================================================");
        System.out.printf("Adversarial Matrix: TP=%d, FP=%d, TN=%d, FN=%d%n", tp, fp, tn, fn);
        System.out.printf("Precision: %.2f%% | Recall: %.2f%% | Specificity: %.2f%% | Accuracy: %.2f%%%n",
                precision, recall, specificity, accuracy);
        System.out.printf("F1-Score: %.2f%% | Manual Remediation Boundary: %d / %d (100.00%%)%n",
                f1, manualRemediationEnforced, tp);
        System.out.println("===============================================================================");

        assertEquals(6, tp, "All 6 vulnerable adversarial test cases must be detected (TP=6)");
        assertEquals(0, fp, "Zero false alarms permitted on adversarial safe controls (FP=0)");
        assertEquals(6, tn, "All 6 safe adversarial control cases must pass cleanly (TN=6)");
        assertEquals(0, fn, "Zero false negatives permitted in adversarial validation set (FN=0)");
        assertEquals(100.0, precision, 0.001, "Precision must be 100.00%");
        assertEquals(100.0, recall, 0.001, "Recall must be 100.00%");
        assertEquals(100.0, specificity, 0.001, "Specificity must be 100.00%");
        assertEquals(100.0, f1, 0.01, "F1-Score must be 100.00%");
        assertEquals(6, manualRemediationEnforced, "100% of detected findings must enforce MANUAL_REMEDIATION_REQUIRED");
    }
}
