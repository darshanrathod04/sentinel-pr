# SentinelPR — Comprehensive Usage & Verification Guide

This guide provides an in-depth reference for SentinelPR, covering supported security rules, command-line interface (CLI) execution, REST API integration, audit session deduplication, and production CI/CD PR Bot automation.

---

## Table of Contents

- [1. Supported Security Rules](#1-supported-security-rules)
  - [SEC-001-FAIL-OPEN: Fail-Open Security Block](#sec-001-fail-open-fail-open-security-block)
  - [SEC-002-UNCLOSED-STREAM: Unclosed I/O Stream](#sec-002-unclosed-stream-unclosed-io-stream)
  - [SEC-003-VOLATILE-COMPOUND: Non-Atomic Volatile Mutation](#sec-003-volatile-compound-non-atomic-volatile-mutation)
  - [SEC-004-UNISOLATED-SUBPROCESS: Un-isolated Subprocess Call](#sec-004-unisolated-subprocess-un-isolated-subprocess-call)
- [2. CLI Usage Guide](#2-cli-usage-guide)
  - [CLI Invocation Syntax](#cli-invocation-syntax)
  - [Sample Terminal Output](#sample-terminal-output)
- [3. REST API Usage Guide](#3-rest-api-usage-guide)
  - [Health Check Endpoint](#health-check-endpoint)
  - [Audit Endpoint: POST /api/v1/sentinel/review](#audit-endpoint-post-apiv1sentinelreview)
  - [Mode A: Audit by Local File Path](#mode-a-audit-by-local-file-path)
  - [Mode B: Audit by Raw Source Code](#mode-b-audit-by-raw-source-code)
  - [Response Schema Breakdown](#response-schema-breakdown)
- [4. Audit Session Memory & Deduplication](#4-audit-session-memory--deduplication)
- [5. CI/CD & GitHub PR Bot Integration Guide](#5-cicd--github-pr-bot-integration-guide)
  - [GitHub Actions Workflow Example](#github-actions-workflow-example)
  - [How It Works on Pull Requests](#how-it-works-on-pull-requests)

---

## 1. Supported Security Rules

SentinelPR inspects the AST of Java source code using `com.sentinelpr.client.ReasoningFacade` and synthesizes AST-verified remediations using `com.sentinelpr.client.DeveloperFacade`.

### SEC-001-FAIL-OPEN: Fail-Open Security Block

- **Rule ID**: `SEC-001-FAIL-OPEN`
- **Severity**: `CRITICAL`
- **Standard**: [CWE-393: Return of Wrong Status Code](https://cwe.mitre.org/data/definitions/393.html)
- **Detection Logic**: Identifies `catch` clauses that intercept broad or critical exceptions (`NullPointerException`, `Exception`, `Throwable`, `RuntimeException`, `SecurityException`) within security-sensitive contexts (methods returning `boolean` or named with `auth`, `security`, `permission`, `access`, `check`, `verify`, `validate`, `can`) and return `true` or grant access.
- **Causal Rationale**: Catching an unhandled exception or null reference and returning `true` defaults to granting access when unexpected system states occur. Attackers can intentionally trigger null dereferences or malformed inputs to bypass authentication or privilege checks.
- **Remediation**: Convert the handler to fail-closed semantics (`return false; // SentinelPR: fail-closed security fix`), throw an explicit `AccessDeniedException`, or propagate a verified `SecurityException`.

#### Vulnerable Code:
```java
public boolean checkUserAuthorization(String userId, String requiredRole) {
    try {
        if (userId == null || userId.isBlank()) {
            throw new NullPointerException("User identity is null");
        }
        return userId.equals("admin") && requiredRole.equals("SUPERUSER");
    } catch (NullPointerException e) {
        // VULNERABLE: Fail-open security block returns true on error
        return true;
    }
}
```

#### Synthesized Unified Diff Patch:
```diff
--- a/src/test/java/com/sentinelpr/fixture/VulnerableService.java
+++ b/src/test/java/com/sentinelpr/fixture/VulnerableService.java
@@ -36,5 +36,5 @@
         } catch (NullPointerException e) {
             // VULNERABLE: Fail-open security block returns true on error
-            return true;
+            return false; // SentinelPR: fail-closed security fix
         }
     }
```

---

### SEC-002-UNCLOSED-STREAM: Unclosed I/O Stream

- **Rule ID**: `SEC-002-UNCLOSED-STREAM`
- **Severity**: `HIGH`
- **Standard**: [CWE-404: Improper Resource Shutdown or Release](https://cwe.mitre.org/data/definitions/404.html)
- **Detection Logic**: Detects instantiations of I/O resources (`FileInputStream`, `FileOutputStream`, `InputStream`, `OutputStream`, `FileReader`, `FileWriter`, `BufferedReader`, `BufferedWriter`, `BufferedInputStream`, `BufferedOutputStream`, `DataInputStream`, `DataOutputStream`) that are neither managed inside a `try (...)` resource specification nor deterministically closed within a `finally` block.
- **Causal Rationale**: If an I/O operation fails or throws an exception before an explicit `.close()` invocation, the underlying operating system file descriptor remains open until JVM garbage collection. Under concurrent request spikes, this triggers OS file descriptor exhaustion (e.g., `java.io.IOException: Too many open files`).
- **Remediation**: Transform stream allocation into a Java 7+ try-with-resources statement, ensuring automated deterministic resource disposal regardless of execution outcome.

#### Vulnerable Code:
```java
public String readConfigurationData(File configFile) throws IOException {
    FileInputStream fis = new FileInputStream(configFile);
    byte[] buffer = new byte[1024];
    int bytesRead = fis.read(buffer);
    return new String(buffer, 0, bytesRead);
}
```

#### Synthesized Unified Diff Patch:
```diff
--- a/src/test/java/com/sentinelpr/fixture/VulnerableService.java
+++ b/src/test/java/com/sentinelpr/fixture/VulnerableService.java
@@ -19,10 +19,10 @@
      */
     public String readConfigurationData(File configFile) throws IOException {
-        FileInputStream fis = new FileInputStream(configFile);
-        byte[] buffer = new byte[1024];
-        int bytesRead = fis.read(buffer);
-        return new String(buffer, 0, bytesRead);
+        try (FileInputStream fis = new FileInputStream(configFile)) {
+            byte[] buffer = new byte[1024];
+            int bytesRead = fis.read(buffer);
+            return new String(buffer, 0, bytesRead);
+        }
     }
```

---

### SEC-003-VOLATILE-COMPOUND: Non-Atomic Volatile Mutation

- **Rule ID**: `SEC-003-VOLATILE-COMPOUND`
- **Severity**: `HIGH`
- **Standard**: [CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')](https://cwe.mitre.org/data/definitions/362.html)
- **Detection Logic**: Detects unary mutations (`counter++`, `++counter`, `counter--`, `--counter`) or compound assignments (`counter += n`, `counter -= n`) executed against `volatile` primitive fields.
- **Causal Rationale**: The `volatile` modifier in Java guarantees CPU cache visibility and prevents instruction reordering; it does **not** provide mutual exclusion or atomic read-modify-write execution. A compound operation (`counter++`) executes as three distinct JVM bytecode instructions (`getfield`, `iadd`, `putfield`). Under concurrent multithreaded access, simultaneous increments collide, causing silent update loss.
- **Remediation**: Replace the `volatile int` field declaration with a `java.util.concurrent.atomic.AtomicInteger` instance and replace mutations with thread-safe atomic primitives such as `.incrementAndGet()`, `.decrementAndGet()`, or `.addAndGet()`.

#### Vulnerable Code:
```java
public class VulnerableService {

    private volatile int requestCount;

    public void trackRequest() {
        requestCount++;
    }
}
```

#### Synthesized Unified Diff Patch:
```diff
--- a/src/test/java/com/sentinelpr/fixture/VulnerableService.java
+++ b/src/test/java/com/sentinelpr/fixture/VulnerableService.java
@@ -1,16 +1,18 @@
 package com.sentinelpr.fixture;
 
+import java.util.concurrent.atomic.AtomicInteger;
+
 public class VulnerableService {
 
-    private volatile int requestCount;
+    private final AtomicInteger requestCount = new AtomicInteger(0);
 
     public void trackRequest() {
-        requestCount++;
+        requestCount.incrementAndGet();
     }
```

---

### SEC-004-UNISOLATED-SUBPROCESS: Un-isolated Subprocess Call

- **Rule ID**: `SEC-004-UNISOLATED-SUBPROCESS`
- **Severity**: `CRITICAL`
- **Standard**: [CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')](https://cwe.mitre.org/data/definitions/78.html)
- **Detection Logic**: Detects unconstrained invocations of `Runtime.getRuntime().exec(...)`.
- **Causal Rationale**: Direct calls to `Runtime.getRuntime().exec` without argument array tokenization, explicit working directory constraints, or process execution timeouts allow unsanitized input parameters to be passed directly to the shell, opening severe command injection vulnerabilities.
- **Remediation**: Refactor process spawning to use `java.lang.ProcessBuilder` with explicit tokenized argument arrays and execution constraints.

#### Vulnerable Code:
```java
public void executeDiagnostic(String command) throws IOException {
    Runtime.getRuntime().exec(command);
}
```

#### Synthesized Unified Diff Patch:
```diff
--- a/src/main/java/com/example/DiagnosticService.java
+++ b/src/main/java/com/example/DiagnosticService.java
@@ -12,3 +12,3 @@
     public void executeDiagnostic(String command) throws IOException {
-        Runtime.getRuntime().exec(command);
+        new ProcessBuilder(command).start();
     }
```

---

## 2. CLI Usage Guide

### CLI Invocation Syntax

SentinelPR can be executed directly from the terminal against a single Java source file or an entire directory tree.

#### Execution via Maven `exec:java`:

**Linux / macOS (Bash / Zsh):**
```bash
mvn test-compile exec:java \
  -Dexec.mainClass="com.sentinelpr.cli.SentinelCliRunner" \
  -Dexec.classpathScope=test \
  -Dexec.args="src/test/java/com/sentinelpr/fixture/VulnerableService.java"
```

**Windows (PowerShell):**
```powershell
mvn test-compile exec:java `
  "-Dexec.mainClass=com.sentinelpr.cli.SentinelCliRunner" `
  "-Dexec.classpathScope=test" `
  "-Dexec.args=src/test/java/com/sentinelpr/fixture/VulnerableService.java"
```

#### Execution via Packaged JAR:
```bash
# 1. Build the executable jar
mvn clean package -DskipTests

# 2. Run against a file
java -jar target/sentinel-pr-1.0.0.jar src/test/java/com/sentinelpr/fixture/VulnerableService.java

# 3. Run against an entire directory
java -jar target/sentinel-pr-1.0.0.jar src/main/java/com/sentinelpr/
```

---

### Sample Terminal Output

When executed, SentinelPR prints:
1. Copilot header and platform metadata
2. Audit execution summary (scanned files, vulnerability count, patch count, cache state)
3. Detected vulnerability details (severity, line numbers, causal rationale, remediation guidance)
4. Verified synthesized patches in unified diff format
5. Complete structured JSON audit report

```text
================================================================================
 SentinelPR — Enterprise Code & Security Review Copilot
 Powered by Shree AI OS (io.github.darshanrathod04:shree-ai-os:1.0.6-developer-preview)
 Target: D:\sentinel-pr\src\test\java\com\sentinelpr\fixture\VulnerableService.java
================================================================================
[SentinelPR] No GEMINI_API_KEY provided; operating in deterministic in-memory provider mode.
[SentinelPR:Memory] Recorded audit session into Memory Kernel for f15a5433f40d

--- [Audit Execution Summary] ---
Status:          SUCCESS
Files Scanned:   1
Vulnerabilities: 3
Patches Created: 3
Cached Session:  false
Message:         Audit completed. Scanned 1 source file(s), identified 3 vulnerability finding(s), synthesized 3 verified patch(es).

--- [Detected Vulnerabilities] ---
  [CRITICAL] Fail-open security catch block grants access upon NullPointerException (D:\sentinel-pr\src\test\java\com\sentinelpr\fixture\VulnerableService.java:36-39)
    Rationale:   Catching [NullPointerException] and returning true creates an exploitable fail-open bypass in 'checkUserAuthorization'. An unexpected error elevates privileges or authorizes unauthorized access.
    Remediation: Fail securely by returning false, throwing an AccessDeniedException, or propagating a verified SecurityException.
  [HIGH] Unclosed I/O resource stream detected: FileInputStream (D:\sentinel-pr\src\test\java\com\sentinelpr\fixture\VulnerableService.java:21-21)
    Rationale:   Stream [FileInputStream] allocated at line 21 is not managed by try-with-resources. If an exception occurs, the operating system file descriptor remains open until GC, risking descriptor exhaustion under load.
    Remediation: Enclose stream instantiation in a try-with-resources statement: try (FileInputStream stream = ...) { ... }
  [HIGH] Non-atomic compound operation on volatile field: requestCount (D:\sentinel-pr\src\test\java\com\sentinelpr\fixture\VulnerableService.java:46-46)
    Rationale:   Compound mutation 'requestCount++' on volatile variable 'requestCount' at line 46 is non-atomic. Volatile guarantees visibility, not mutual exclusion or atomic read-modify-write. Concurrent threads will drop updates.
    Remediation: Replace 'volatile int requestCount' with 'java.util.concurrent.atomic.AtomicInteger requestCount = new AtomicInteger();' and use .incrementAndGet() / .decrementAndGet().

--- [Synthesized Verified Patches (Unified Diff)] ---
  Patch for [SEC-001-FAIL-OPEN] -> Status: SUCCESS (Verified: true)
--- a/src/test/java/com/sentinelpr/fixture/VulnerableService.java
+++ b/src/test/java/com/sentinelpr/fixture/VulnerableService.java
@@ -36,5 +36,5 @@
         } catch (NullPointerException e) {
             // VULNERABLE: Fail-open security block returns true on error
-            return true;
+            return false; // SentinelPR: fail-closed security fix
         }
     }

  Patch for [SEC-002-UNCLOSED-STREAM] -> Status: SUCCESS (Verified: true)
--- a/src/test/java/com/sentinelpr/fixture/VulnerableService.java
+++ b/src/test/java/com/sentinelpr/fixture/VulnerableService.java
@@ -19,10 +19,10 @@
      */
     public String readConfigurationData(File configFile) throws IOException {
-        FileInputStream fis = new FileInputStream(configFile);
-        byte[] buffer = new byte[1024];
-        int bytesRead = fis.read(buffer);
-        return new String(buffer, 0, bytesRead);
+        try (FileInputStream fis = new FileInputStream(configFile)) {
+            byte[] buffer = new byte[1024];
+            int bytesRead = fis.read(buffer);
+            return new String(buffer, 0, bytesRead);
+        }
     }

  Patch for [SEC-003-VOLATILE-COMPOUND] -> Status: SUCCESS (Verified: true)
--- a/src/test/java/com/sentinelpr/fixture/VulnerableService.java
+++ b/src/test/java/com/sentinelpr/fixture/VulnerableService.java
@@ -1,16 +1,18 @@
 package com.sentinelpr.fixture;
 
+import java.util.concurrent.atomic.AtomicInteger;
+
 public class VulnerableService {
 
-    private volatile int requestCount;
+    private final AtomicInteger requestCount = new AtomicInteger(0);
 
     public void trackRequest() {
-        requestCount++;
+        requestCount.incrementAndGet();
     }

--- [Structured JSON Report] ---
{
  "reportId" : "REV-300c8ec6",
  "timestamp" : "2026-09-20T20:33:55.123456Z",
  "targetPath" : "D:\\sentinel-pr\\src\\test\\java\\com\\sentinelpr\\fixture\\VulnerableService.java",
  "scannedFileCount" : 1,
  "vulnerabilityCount" : 3,
  "status" : "SUCCESS",
  "cachedAudit" : false,
  "summary" : "Audit completed. Scanned 1 source file(s), identified 3 vulnerability finding(s), synthesized 3 verified patch(es).",
  "findings" : [ ... ],
  "patches" : [ ... ]
}
```

---

## 3. REST API Usage Guide

When started with `mvn spring-boot:run`, SentinelPR exposes an enterprise REST API on port `8080`.

### Health Check Endpoint

```http
GET /api/v1/sentinel/health
```

#### Example Request:
```bash
curl -s http://localhost:8080/api/v1/sentinel/health
```

#### Example Response:
```json
{
  "service": "SentinelPR - Enterprise Code & Security Review Copilot",
  "status": "UP",
  "platform": "Shree AI OS (1.0.6-developer-preview)",
  "rules": 4
}
```

---

### Audit Endpoint: `POST /api/v1/sentinel/review`

Accepts JSON requests with either:
- `targetPath`: Path on the local filesystem (file or directory).
- `sourceCode`: Raw Java source code string, with optional `simulatedFileName`.

---

### Mode A: Audit by Local File Path

#### Request:
```bash
curl -X POST http://localhost:8080/api/v1/sentinel/review \
  -H "Content-Type: application/json" \
  -d '{
    "targetPath": "src/test/java/com/sentinelpr/fixture/VulnerableService.java"
  }'
```

#### JSON Request Body:
```json
{
  "targetPath": "src/test/java/com/sentinelpr/fixture/VulnerableService.java"
}
```

---

### Mode B: Audit by Raw Source Code

Ideal for PR bots, IDE plugins, or webhook payloads where source text is passed directly in memory without disk persistence.

#### Request:
```bash
curl -X POST http://localhost:8080/api/v1/sentinel/review \
  -H "Content-Type: application/json" \
  -d '{
    "simulatedFileName": "AuthManager.java",
    "sourceCode": "package com.example;\n\npublic class AuthManager {\n    public boolean verifyToken(String token) {\n        try {\n            if (token == null) throw new NullPointerException();\n            return token.equals(\"VALID\");\n        } catch (NullPointerException e) {\n            return true;\n        }\n    }\n}"
  }'
```

#### JSON Request Body:
```json
{
  "simulatedFileName": "AuthManager.java",
  "sourceCode": "package com.example;\n\npublic class AuthManager {\n    public boolean verifyToken(String token) {\n        try {\n            if (token == null) throw new NullPointerException();\n            return token.equals(\"VALID\");\n        } catch (NullPointerException e) {\n            return true;\n        }\n    }\n}"
}
```

---

### Response Schema Breakdown

#### Sample Response JSON:
```json
{
  "reportId": "REV-8b7a12cd",
  "timestamp": "2026-09-20T20:33:55.123456Z",
  "targetPath": "src/test/java/com/sentinelpr/fixture/VulnerableService.java",
  "scannedFileCount": 1,
  "vulnerabilityCount": 3,
  "status": "SUCCESS",
  "cachedAudit": false,
  "summary": "Audit completed. Scanned 1 source file(s), identified 3 vulnerability finding(s), synthesized 3 verified patch(es).",
  "findings": [
    {
      "id": "FND-a19e54d2",
      "rule": "FAIL_OPEN_SECURITY",
      "severity": "CRITICAL",
      "targetFile": "src/test/java/com/sentinelpr/fixture/VulnerableService.java",
      "className": "VulnerableService",
      "methodName": "checkUserAuthorization",
      "startLine": 36,
      "endLine": 39,
      "vulnerableSnippet": "catch (NullPointerException e) {\n    return true;\n}",
      "description": "Fail-open security catch block grants access upon NullPointerException",
      "causalRationale": "Catching [NullPointerException] and returning true creates an exploitable fail-open bypass in 'checkUserAuthorization'. An unexpected error elevates privileges or authorizes unauthorized access.",
      "remediation": "Fail securely by returning false, throwing an AccessDeniedException, or propagating a verified SecurityException.",
      "confidence": 0.98
    },
    {
      "id": "FND-b82c330f",
      "rule": "UNCLOSED_IO_STREAM",
      "severity": "HIGH",
      "targetFile": "src/test/java/com/sentinelpr/fixture/VulnerableService.java",
      "className": "VulnerableService",
      "methodName": "readConfigurationData",
      "startLine": 21,
      "endLine": 21,
      "vulnerableSnippet": "new FileInputStream(configFile)",
      "description": "Unclosed I/O resource stream detected: FileInputStream",
      "causalRationale": "Stream [FileInputStream] allocated at line 21 is not managed by try-with-resources. If an exception occurs, the operating system file descriptor remains open until GC, risking descriptor exhaustion under load.",
      "remediation": "Enclose stream instantiation in a try-with-resources statement: try (FileInputStream stream = ...) { ... }",
      "confidence": 0.95
    },
    {
      "id": "FND-c132966b",
      "rule": "VOLATILE_COMPOUND_OP",
      "severity": "HIGH",
      "targetFile": "src/test/java/com/sentinelpr/fixture/VulnerableService.java",
      "className": "VulnerableService",
      "methodName": "trackRequest",
      "startLine": 46,
      "endLine": 46,
      "vulnerableSnippet": "requestCount++",
      "description": "Non-atomic compound operation on volatile field: requestCount",
      "causalRationale": "Compound mutation 'requestCount++' on volatile variable 'requestCount' at line 46 is non-atomic. Volatile guarantees visibility, not mutual exclusion or atomic read-modify-write. Concurrent threads will drop updates.",
      "remediation": "Replace 'volatile int requestCount' with 'java.util.concurrent.atomic.AtomicInteger requestCount = new AtomicInteger();' and use .incrementAndGet() / .decrementAndGet().",
      "confidence": 0.97
    }
  ],
  "patches": [
    {
      "findingId": "FND-a19e54d2",
      "ruleId": "SEC-001-FAIL-OPEN",
      "targetFile": "src/test/java/com/sentinelpr/fixture/VulnerableService.java",
      "unifiedDiff": "--- a/src/test/java/com/sentinelpr/fixture/VulnerableService.java\n+++ b/src/test/java/com/sentinelpr/fixture/VulnerableService.java\n@@ -36,5 +36,5 @@\n         } catch (NullPointerException e) {\n             // VULNERABLE: Fail-open security block returns true on error\n-            return true;\n+            return false; // SentinelPR: fail-closed security fix\n         }\n     }\n",
      "patchedSource": "...",
      "status": "SUCCESS",
      "verified": true,
      "verificationMessage": "AST syntax and semantic verification PASSED (Java 21 LTS compliant)"
    }
  ]
}
```

#### Fields Description:

| Field | Type | Description |
|---|---|---|
| `reportId` | `String` | Unique execution identifier (e.g. `REV-8b7a12cd`). |
| `timestamp` | `Instant` | UTC ISO-8601 timestamp of audit run. |
| `targetPath` | `String` | Target file path or simulated source identifier. |
| `scannedFileCount` | `int` | Number of Java source files parsed. |
| `vulnerabilityCount`| `int` | Total number of security findings detected. |
| `status` | `String` | `SUCCESS`, `PARTIAL`, or `FAILED`. |
| `cachedAudit` | `boolean` | `true` if retrieved from `ReviewSessionMemory` (MemorySDK), `false` if freshly audited. |
| `summary` | `String` | High-level textual audit summary. |
| `findings[].id` | `String` | Unique finding identifier (e.g. `FND-a19e54d2`). |
| `findings[].rule` | `String` | Enum rule identifier (`FAIL_OPEN_SECURITY`, `UNCLOSED_IO_STREAM`, etc.). |
| `findings[].severity` | `String` | Severity rating: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`. |
| `findings[].startLine` / `endLine` | `int` | Inclusive 1-indexed line boundaries in source code. |
| `findings[].causalRationale` | `String` | Explanatory causal security analysis explaining exploitability. |
| `findings[].remediation` | `String` | Concrete refactoring advice. |
| `patches[].ruleId` | `String` | Rule ID associated with this patch (`SEC-001-FAIL-OPEN`). |
| `patches[].unifiedDiff` | `String` | Standard git-compatible unified diff hunk. |
| `patches[].verified` | `boolean` | `true` if candidate patched source successfully parsed into a Java 21 AST. |
| `patches[].status` | `String` | `SUCCESS`, `PARTIAL`, `FAILED`, `SKIPPED`. |

---

## 4. Audit Session Memory & Deduplication

SentinelPR integrates Shree AI OS **`MemorySDK`** via `ReviewSessionMemory`.

1. **SHA-256 Fingerprinting**: Before AST inspection, the raw source code text is hashed via SHA-256.
2. **Cache Lookup**: If an audit report exists for `AUDIT:<hash>`, SentinelPR skips AST parsing and rule evaluation, returning `cachedAudit: true`.
3. **High PR Throughput**: In large monorepos with hundreds of PR builds, unchanged files consume near-zero compute.

#### Example: Second Audit on Unchanged File:
```text
Status:          SUCCESS
Cached Session:  true
Message:         Session Memory Hit: Unchanged file retrieved from previous audit run without re-evaluating rules.
```

---

## 5. CI/CD & GitHub PR Bot Integration Guide

SentinelPR can be embedded seamlessly into GitHub Actions to review pull requests, fail builds on `CRITICAL` security violations, and post automated unified diff patch suggestions.

### GitHub Actions Workflow Example

Create `.github/workflows/sentinel-pr-review.yml` in your repository:

```yaml
name: "SentinelPR Security Review"

on:
  pull_request:
    branches: [ "main", "master", "develop" ]
    paths:
      - "**.java"

permissions:
  contents: read
  pull-requests: write

jobs:
  sentinel-review:
    name: "SentinelPR Code & Security Copilot"
    runs-on: ubuntu-latest

    steps:
      - name: "Checkout Pull Request Code"
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: "Set up Java 21 LTS"
        uses: actions/setup-java@v4
        with:
          distribution: "temurin"
          java-version: "21"
          cache: "maven"

      - name: "Compile SentinelPR & Fixtures"
        run: |
          mvn test-compile -DskipTests

      - name: "Identify Changed Java Files"
        id: changed-files
        run: |
          # Detect modified/added Java files against target branch
          CHANGED=$(git diff --name-only origin/${{ github.base_ref }}...HEAD | grep -E '\.java$' || true)
          echo "files=$CHANGED" >> $GITHUB_OUTPUT

      - name: "Execute SentinelPR Review"
        id: sentinel-audit
        if: steps.changed-files.outputs.files != ''
        run: |
          mkdir -p .sentinel-out
          for file in ${{ steps.changed-files.outputs.files }}; do
            if [ -f "$file" ]; then
              echo "Auditing $file with SentinelPR..."
              mvn test-compile exec:java \
                -Dexec.mainClass="com.sentinelpr.cli.SentinelCliRunner" \
                -Dexec.classpathScope=test \
                -Dexec.args="$file" > .sentinel-out/report.txt
            fi
          done

      - name: "Post SentinelPR Review Comment"
        if: steps.changed-files.outputs.files != ''
        uses: actions/github-script@v7
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
          script: |
            const fs = require('fs');
            const reportPath = '.sentinel-out/report.txt';
            if (fs.existsSync(reportPath)) {
              const report = fs.readFileSync(reportPath, 'utf8');
              const body = `### SentinelPR Security Review Summary\n\n\`\`\`text\n${report}\n\`\`\``;
              github.rest.issues.createComment({
                issue_number: context.issue.number,
                owner: context.repo.owner,
                repo: context.repo.repo,
                body: body
              });
            }
```

---

### How It Works on Pull Requests

1. **Trigger on PR**: Whenever a developer opens or updates a Pull Request touching Java source files, the action triggers.
2. **AST Inspection**: SentinelPR inspects only the modified `.java` files.
3. **Causal Reasoning**: Evaluates rules (`SEC-001` through `SEC-004`).
4. **Verified Unified Diff**: Synthesizes verified Java 21 patches.
5. **Interactive PR Feedback**: SentinelPR posts an automated GitHub review comment showing the exact diff required to fix the vulnerability, enabling 1-click merge remediation.
