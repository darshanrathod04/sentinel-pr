package com.sentinelpr.core.analysis.multilang.python;

import com.sentinelpr.core.analysis.multilang.python.ast.PythonModule;
import com.sentinelpr.core.analysis.multilang.python.rules.PythonSecurityRuleEngine;
import com.sentinelpr.core.model.InspectedSource;
import com.sentinelpr.core.model.SecurityFinding;
import com.sentinelpr.core.model.SecurityRule;
import com.sentinelpr.core.service.CodeInspectionService;
import com.sentinelpr.core.service.RuleEvaluationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Phase 5: Python Core AST-Based Security Rules Test Suite")
public class PythonSecurityRulesTest {

    private PythonSourceParser parser;
    private PythonSecurityRuleEngine ruleEngine;
    private CodeInspectionService inspectionService;
    private RuleEvaluationService evaluationService;

    @BeforeEach
    void setUp() {
        this.parser = new PythonSourceParser();
        this.ruleEngine = new PythonSecurityRuleEngine();
        this.inspectionService = new CodeInspectionService();
        this.evaluationService = new RuleEvaluationService();
    }

    @Test
    @DisplayName("SQLi: Detect dynamic queries; allow parameterized queries")
    void testSqlInjection() {
        String vulnCode = """
                def get_user(user_id):
                    sql = f"SELECT * FROM users WHERE id = '{user_id}'"
                    cursor.execute(sql)
                """;
        InspectedSource vulnSource = inspectionService.inspectSourceCode(vulnCode, "repo.py");
        List<SecurityFinding> vulnFindings = evaluationService.evaluate(vulnSource);
        assertTrue(vulnFindings.stream().anyMatch(f -> f.getRule() == SecurityRule.SQL_INJECTION),
                "Must flag dynamic f-string SQL query execution");

        String safeCode = """
                def get_user_safe(user_id):
                    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
                """;
        InspectedSource safeSource = inspectionService.inspectSourceCode(safeCode, "repo_safe.py");
        List<SecurityFinding> safeFindings = evaluationService.evaluate(safeSource);
        assertFalse(safeFindings.stream().anyMatch(f -> f.getRule() == SecurityRule.SQL_INJECTION),
                "Parameterized SQL query must not be flagged");
    }

    @Test
    @DisplayName("Command Injection: Detect os.system and shell=True; allow tokenized subprocess")
    void testCommandInjection() {
        String vulnCode = """
                import os, subprocess
                def run_backup(path):
                    os.system("tar -czf backup.tar.gz " + path)
                    subprocess.run(f"zip -r {path}", shell=True)
                """;
        InspectedSource vulnSource = inspectionService.inspectSourceCode(vulnCode, "backup.py");
        List<SecurityFinding> vulnFindings = evaluationService.evaluate(vulnSource);
        long cmdFindings = vulnFindings.stream().filter(f -> f.getRule() == SecurityRule.UNISOLATED_SUBPROCESS).count();
        assertTrue(cmdFindings >= 2, "Must flag both os.system and shell=True");

        String safeCode = """
                import subprocess
                def run_backup_safe(path):
                    subprocess.run(["tar", "-czf", "backup.tar.gz", path], shell=False)
                """;
        InspectedSource safeSource = inspectionService.inspectSourceCode(safeCode, "backup_safe.py");
        List<SecurityFinding> safeFindings = evaluationService.evaluate(safeSource);
        assertFalse(safeFindings.stream().anyMatch(f -> f.getRule() == SecurityRule.UNISOLATED_SUBPROCESS),
                "Tokenized subprocess call with shell=False must not be flagged");
    }

    @Test
    @DisplayName("Code Eval: Detect eval() and exec(); allow ast.literal_eval()")
    void testCodeEvaluation() {
        String vulnCode = """
                def run_calculation(user_formula):
                    return eval(user_formula)
                """;
        InspectedSource vulnSource = inspectionService.inspectSourceCode(vulnCode, "calc.py");
        List<SecurityFinding> vulnFindings = evaluationService.evaluate(vulnSource);
        assertTrue(vulnFindings.stream().anyMatch(f -> f.getRule() == SecurityRule.UNISOLATED_SUBPROCESS),
                "eval() must be flagged");

        String safeCode = """
                import ast
                def parse_config(raw_dict):
                    return ast.literal_eval(raw_dict)
                """;
        InspectedSource safeSource = inspectionService.inspectSourceCode(safeCode, "calc_safe.py");
        List<SecurityFinding> safeFindings = evaluationService.evaluate(safeSource);
        assertFalse(safeFindings.stream().anyMatch(f -> f.getRule() == SecurityRule.UNISOLATED_SUBPROCESS),
                "ast.literal_eval must not be flagged");
    }

    @Test
    @DisplayName("Insecure Deserialization: Detect pickle and unsafe PyYAML; allow safe_load")
    void testInsecureDeserialization() {
        String vulnCode = """
                import pickle, yaml
                def load_payload(raw_data):
                    obj = pickle.loads(raw_data)
                    cfg = yaml.load(raw_data)
                    return obj, cfg
                """;
        InspectedSource vulnSource = inspectionService.inspectSourceCode(vulnCode, "loader.py");
        List<SecurityFinding> vulnFindings = evaluationService.evaluate(vulnSource);
        long deserFindings = vulnFindings.stream().filter(f -> f.getRule() == SecurityRule.INSECURE_DESERIALIZATION).count();
        assertTrue(deserFindings >= 2, "Must flag pickle.loads and yaml.load");

        String safeCode = """
                import yaml, json
                def load_safe(raw_data):
                    data1 = yaml.safe_load(raw_data)
                    data2 = json.loads(raw_data)
                    return data1, data2
                """;
        InspectedSource safeSource = inspectionService.inspectSourceCode(safeCode, "loader_safe.py");
        List<SecurityFinding> safeFindings = evaluationService.evaluate(safeSource);
        assertFalse(safeFindings.stream().anyMatch(f -> f.getRule() == SecurityRule.INSECURE_DESERIALIZATION),
                "yaml.safe_load and json.loads must not be flagged");
    }

    @Test
    @DisplayName("Path Traversal: Detect unverified dynamic paths; allow sanitized containment")
    void testPathTraversal() {
        String vulnCode = """
                def read_profile(filename):
                    with open("/var/data/" + filename, "r") as f:
                        return f.read()
                """;
        InspectedSource vulnSource = inspectionService.inspectSourceCode(vulnCode, "files.py");
        List<SecurityFinding> vulnFindings = evaluationService.evaluate(vulnSource);
        assertTrue(vulnFindings.stream().anyMatch(f -> f.getRule() == SecurityRule.PATH_TRAVERSAL),
                "Unvalidated dynamic open() must be flagged");

        String safeCode = """
                import os
                def read_profile_safe(filename):
                    base_dir = "/var/data"
                    target = os.path.realpath(os.path.join(base_dir, filename))
                    if not target.startswith(base_dir):
                        raise ValueError("Access denied")
                    with open(target, "r") as f:
                        return f.read()
                """;
        InspectedSource safeSource = inspectionService.inspectSourceCode(safeCode, "files_safe.py");
        List<SecurityFinding> safeFindings = evaluationService.evaluate(safeSource);
        assertFalse(safeFindings.stream().anyMatch(f -> f.getRule() == SecurityRule.PATH_TRAVERSAL),
                "Path with os.path.realpath and startswith containment must not be flagged");
    }

    @Test
    @DisplayName("SSRF: Detect unvalidated dynamic URLs; allow static URLs and allowlists")
    void testSsrf() {
        String vulnCode = """
                import requests
                def fetch_hook(webhook_url):
                    return requests.get(webhook_url)
                """;
        InspectedSource vulnSource = inspectionService.inspectSourceCode(vulnCode, "hook.py");
        List<SecurityFinding> vulnFindings = evaluationService.evaluate(vulnSource);
        assertTrue(vulnFindings.stream().anyMatch(f -> f.getRule() == SecurityRule.SSRF),
                "Unvalidated outbound dynamic HTTP request must be flagged");

        String safeCode = """
                import requests
                ALLOWED_HOSTS = ["api.internal.com", "hooks.slack.com"]
                def fetch_hook_safe(webhook_url):
                    if webhook_url in ALLOWED_HOSTS:
                        return requests.get(webhook_url)
                    return requests.get("https://api.github.com/status")
                """;
        InspectedSource safeSource = inspectionService.inspectSourceCode(safeCode, "hook_safe.py");
        List<SecurityFinding> safeFindings = evaluationService.evaluate(safeSource);
        assertFalse(safeFindings.stream().anyMatch(f -> f.getRule() == SecurityRule.SSRF),
                "URL with allowlist check and static URLs must not be flagged");
    }

    @Test
    @DisplayName("Weak Crypto & Insecure Random: Detect md5/sha1 and secret tokens generated via random")
    void testCryptoAndRandom() {
        String vulnCode = """
                import hashlib, random
                def generate_auth_token():
                    token = random.randint(100000, 999999)
                    pwd_hash = hashlib.md5(str(token).encode()).hexdigest()
                    return token, pwd_hash
                """;
        InspectedSource vulnSource = inspectionService.inspectSourceCode(vulnCode, "crypto.py");
        List<SecurityFinding> vulnFindings = evaluationService.evaluate(vulnSource);
        assertTrue(vulnFindings.stream().anyMatch(f -> f.getRule() == SecurityRule.WEAK_CRYPTO),
                "hashlib.md5 must be flagged");
        assertTrue(vulnFindings.stream().anyMatch(f -> f.getRule() == SecurityRule.INSECURE_RANDOM),
                "random.randint for token generation must be flagged");

        String safeCode = """
                import hashlib, secrets, random
                def roll_dice():
                    val = random.randint(1, 6) # Non-security context
                    return val

                def generate_safe_token():
                    token = secrets.token_hex(32)
                    secure_hash = hashlib.sha256(token.encode()).hexdigest()
                    return token, secure_hash
                """;
        InspectedSource safeSource = inspectionService.inspectSourceCode(safeCode, "crypto_safe.py");
        List<SecurityFinding> safeFindings = evaluationService.evaluate(safeSource);
        assertFalse(safeFindings.stream().anyMatch(f -> f.getRule() == SecurityRule.WEAK_CRYPTO),
                "sha256 must not be flagged");
        assertFalse(safeFindings.stream().anyMatch(f -> f.getRule() == SecurityRule.INSECURE_RANDOM),
                "dice roll and secrets.token_hex must not be flagged as insecure random");
    }

    @Test
    @DisplayName("Phase 5.2 M2: Dynamic path evaluation across os.path.join and pathlib.Path with multi-hop taint")
    void testDynamicPathEvaluationMultiHop() {
        // 1. os.path.join with multi-hop taint from request
        String osJoinVuln = """
                import os
                def handle_download(request):
                    raw_id = request.args.get("file")
                    filename = raw_id
                    target_dir = "/app/storage"
                    full_path = os.path.join(target_dir, filename)
                    with open(full_path, "r") as f:
                        return f.read()
                """;
        InspectedSource osJoinSource = inspectionService.inspectSourceCode(osJoinVuln, "download.py");
        List<SecurityFinding> osJoinFindings = evaluationService.evaluate(osJoinSource);
        assertTrue(osJoinFindings.stream().anyMatch(f -> f.getRule() == SecurityRule.PATH_TRAVERSAL),
                "os.path.join with multi-hop request argument must be flagged as PATH_TRAVERSAL");

        // 2. pathlib.Path division with tainted variable
        String pathlibVuln = """
                from pathlib import Path
                def load_user_doc(request):
                    doc_name = request.args.get("doc")
                    base = Path("/var/docs")
                    target = base / doc_name
                    with open(target, "rb") as f:
                        return f.read()
                """;
        InspectedSource pathlibSource = inspectionService.inspectSourceCode(pathlibVuln, "pathlib_test.py");
        List<SecurityFinding> pathlibFindings = evaluationService.evaluate(pathlibSource);
        assertTrue(pathlibFindings.stream().anyMatch(f -> f.getRule() == SecurityRule.PATH_TRAVERSAL),
                "pathlib.Path / operator with tainted input must be flagged as PATH_TRAVERSAL");

        // 3. Safe static path with os.path.join (all static literals)
        String osJoinSafe = """
                import os
                def read_config():
                    static_base = "/etc/myapp"
                    config_file = os.path.join(static_base, "settings.json")
                    with open(config_file, "r") as f:
                        return f.read()
                """;
        InspectedSource osJoinSafeSource = inspectionService.inspectSourceCode(osJoinSafe, "config.py");
        List<SecurityFinding> osJoinSafeFindings = evaluationService.evaluate(osJoinSafeSource);
        assertFalse(osJoinSafeFindings.stream().anyMatch(f -> f.getRule() == SecurityRule.PATH_TRAVERSAL),
                "os.path.join with pure static string literals must not produce false positive");

        // 4. Safe static path with pathlib.Path division
        String pathlibSafe = """
                from pathlib import Path
                def read_banner():
                    base = Path("/opt/assets")
                    banner = base / "banner.txt"
                    with open(banner, "r") as f:
                        return f.read()
                """;
        InspectedSource pathlibSafeSource = inspectionService.inspectSourceCode(pathlibSafe, "banner.py");
        List<SecurityFinding> pathlibSafeFindings = evaluationService.evaluate(pathlibSafeSource);
        assertFalse(pathlibSafeFindings.stream().anyMatch(f -> f.getRule() == SecurityRule.PATH_TRAVERSAL),
                "pathlib.Path / with pure static string literals must not produce false positive");
    }

    @Test
    @DisplayName("Phase 5.2 M3: TLS verification bypass (verify=False)")
    void testTlsVerificationBypass() {
        // 1. requests.get with verify=False
        String requestsVuln = """
                import requests
                def call_api():
                    return requests.get("https://internal.service/api", verify=False)
                """;
        InspectedSource reqSource = inspectionService.inspectSourceCode(requestsVuln, "client.py");
        List<SecurityFinding> reqFindings = evaluationService.evaluate(reqSource);
        assertTrue(reqFindings.stream().anyMatch(f -> f.getRule() == SecurityRule.FAIL_OPEN_SECURITY
                && f.getDescription().contains("Disabled TLS Certificate Verification")),
                "requests.get with verify=False must be flagged");

        // 2. httpx.post with verify=False
        String httpxVuln = """
                import httpx
                def send_webhook(payload):
                    return httpx.post("https://payment.gateway/hook", json=payload, verify=False)
                """;
        InspectedSource httpxSource = inspectionService.inspectSourceCode(httpxVuln, "webhook.py");
        List<SecurityFinding> httpxFindings = evaluationService.evaluate(httpxSource);
        assertTrue(httpxFindings.stream().anyMatch(f -> f.getRule() == SecurityRule.FAIL_OPEN_SECURITY
                && f.getDescription().contains("Disabled TLS Certificate Verification")),
                "httpx.post with verify=False must be flagged");

        // 3. requests.get with verify=True (explicit safe)
        String requestsSafe = """
                import requests
                def call_safe():
                    return requests.get("https://api.github.com/status", verify=True)
                """;
        InspectedSource safeReqSource = inspectionService.inspectSourceCode(requestsSafe, "client_safe.py");
        List<SecurityFinding> safeReqFindings = evaluationService.evaluate(safeReqSource);
        assertFalse(safeReqFindings.stream().anyMatch(f -> f.getDescription().contains("Disabled TLS")),
                "verify=True must not be flagged");

        // 4. requests.get with omitted verify (defaults to True)
        String requestsDefault = """
                import requests
                def call_default():
                    return requests.get("https://api.github.com/status")
                """;
        InspectedSource defReqSource = inspectionService.inspectSourceCode(requestsDefault, "client_def.py");
        List<SecurityFinding> defReqFindings = evaluationService.evaluate(defReqSource);
        assertFalse(defReqFindings.stream().anyMatch(f -> f.getDescription().contains("Disabled TLS")),
                "Omitted verify parameter must not be flagged");
    }
}
