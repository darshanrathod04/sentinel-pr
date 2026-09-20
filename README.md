# SentinelPR — Autonomous Enterprise Code & Security Review Copilot

[![Java 21 LTS](https://img.shields.io/badge/Java-21%20LTS-orange.svg)](https://www.oracle.com/java/technologies/downloads/#java21)
[![Spring Boot 4.0.2](https://img.shields.io/badge/Spring%20Boot-4.0.2-brightgreen.svg)](https://spring.io/projects/spring-boot)
[![Shree AI OS](https://img.shields.io/badge/Shree%20AI%20OS-1.0.6--developer--preview-blue.svg)](https://github.com/darshanrathod04/shree-ai-os)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

**SentinelPR** is an autonomous enterprise code and security review copilot engineered on top of the **Shree AI OS** cognitive operating system platform (`io.github.darshanrathod04:shree-ai-os:1.0.6-developer-preview`).

SentinelPR audits Java codebases at pull request boundaries, identifying critical security and concurrency vulnerabilities through deterministic Abstract Syntax Tree (AST) parsing, cognitive causal reasoning, and verified patch synthesis in standard unified diff format.

---

## Table of Contents

- [Overview](#overview)
- [Architecture & Shree AI OS SDK Integration](#architecture--shree-ai-os-sdk-integration)
- [Key Features](#key-features)
- [Prerequisites](#prerequisites)
- [Quickstart](#quickstart)
  - [1. Run Automated Test Suite](#1-run-automated-test-suite)
  - [2. Execute CLI Audit](#2-execute-cli-audit)
  - [3. Start REST API Server](#3-start-rest-api-server)
- [Supported Security Rules](#supported-security-rules)
- [Project Structure](#project-structure)
- [Configuration](#configuration)

---

## Overview

Traditional static analysis tools rely on rigid regex rules or generate overwhelming false positives without remediation paths. SentinelPR bridges static code inspection and cognitive AI agents by combining:

1. **AST Semantic Inspection**: Deep AST parsing using [JavaParser](https://javaparser.org/) integrated with Shree AI OS [`ProjectSDK`](#projectsdk-ast-parsing--symbol-extraction).
2. **Causal Vulnerability Reasoning**: Exploitability analysis and causal verification powered by [`ReasoningSDK`](#reasoningsdk-causal-security-rule-evaluation).
3. **Verified Patch Synthesis**: Autonomous code refactoring with AST compilation check verification powered by [`DeveloperSDK`](#developersdk-unified-diff-patch-synthesis).
4. **Content-Addressable Audit Memory**: Zero-redundancy session caching via [`MemorySDK`](#memorysdk-audit-fingerprinting--deduplication).

SentinelPR operates either as an embedded CLI utility in CI/CD pipelines (GitHub Actions, GitLab CI) or as a centralized microservice exposing high-throughput REST APIs.

---

## Architecture & Shree AI OS SDK Integration

SentinelPR leverages the 10-SDK cognitive kernel surface provided by **Shree AI OS**:

```
+-----------------------------------------------------------------------------------+
|                               SentinelPR Copilot                                  |
|   (CLI Runner: SentinelCliRunner  |  REST API: /api/v1/sentinel/review)          |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
                         +-------------------------------+
                         |   SentinelAuditOrchestrator   |
                         +-------------------------------+
                           /       |           |        \
                          /        |           |         \
                         v         v           v          v
              +------------+ +-----------+ +-----------+ +---------------+
              | Code       | | Review    | | Rule      | | Automated     |
              | Inspection | | Session   | | Evaluation| | Patch         |
              | Service    | | Memory    | | Service   | | Service       |
              +------------+ +-----------+ +-----------+ +---------------+
                    |              |             |               |
+-------------------|--------------|-------------|---------------|------------------+
| SHREE AI OS       v              v             v               v                  |
| 10-SDK SURFACE:                                                                   |
|              +------------+ +-----------+ +-----------+ +---------------+         |
|              | ProjectSDK | | MemorySDK | |Reasoning- | | DeveloperSDK  |         |
|              | (AST &     | | (SHA-256  | | SDK       | | (Patch Applier|         |
|              | Symbols)   | | Cache)    | | (Causal)  | | & Diff Engine)|         |
|              +------------+ +-----------+ +-----------+ +---------------+         |
|                                                                                   |
|  IdentitySDK  *  KnowledgeSDK  *  PlanningSDK  *  ExecutionSDK  *  ReflectionSDK  |
|  DiagnosticsSDK  *  SettingsSDK (BYOK Gemini Provider / In-Memory Fallback)       |
+-----------------------------------------------------------------------------------+
```

### SDK Integration Map

| Shree AI OS SDK | SentinelPR Facade / Service | Cognitive Responsibility |
|---|---|---|
| **`ProjectSDK`** | `ProjectFacade`<br>`CodeInspectionService` | Structural AST parsing, `CompilationUnit` analysis, class and method symbol extraction, token stream analysis, and recursive directory scanning. |
| **`ReasoningSDK`** | `ReasoningFacade`<br>`RuleEvaluationService` | Causal vulnerability modeling via `DefaultCausalReasoningEngine`, evaluating fail-open security bypasses, stream leaks, volatile race conditions, and un-isolated execution paths. |
| **`DeveloperSDK`** | `DeveloperFacade`<br>`AutomatedPatchService` | Automated patch synthesis, `DefaultPatchExecutionEngine`, AST syntax validation against Java 21 LTS language rules, and standard unified diff generation (`--- a/` / `+++ b/`). |
| **`MemorySDK`** | `ReviewSessionMemory` | Content-addressable SHA-256 fingerprinting and session deduplication, preventing expensive re-audits on unchanged source files. |
| **`SettingsSDK`** | `SentinelClient` | Bring-Your-Own-Key (BYOK) dynamic provider routing (e.g. Google Gemini via `GEMINI_API_KEY`) with deterministic local in-memory fallback. |
| **`DiagnosticsSDK`** | `SentinelClient` / Health API | Runtime health monitoring, provider latency checks, and platform telemetry. |

---

## Key Features

- **Intra-Procedural Taint & Dataflow Engine (`DataflowTracker`)**: Traces untrusted sources (parameters, HTTP inputs) through assignments, method invocations, and returns to sensitive sinks (ProcessBuilder, Runtime.exec, FileInputStream, raw SQL), tracking sanitization guards.
- **False Positive Suppression Engine (`SuppressionManager`)**: Granular policy suppression via `@SuppressWarnings("sentinel:<RULE_ID>")`, inline comments (`// sentinel-ignore <RULE_ID> [reason]`), and repository `.sentinelignore` files, recorded in reports as `suppressedFindings`.
- **Atomic Patch Composition (`PatchComposer`)**: Sequentially applies all verified AST transformations in-memory to generate ONE non-conflicting unified diff per file.
- **Post-Patch Regression Verification (`PatchVerifier`)**: Re-parses patched code with `JavaAstParser` and re-evaluates all security rules to guarantee 0 critical vulnerabilities remain, setting `regressionVerified: true`.
- **Multi-Modal Audit Intake**: Accepts either filesystem paths (individual files or whole directories) or raw source code strings over HTTP.
- **Java 21 LTS Compliant**: Native support for modern Java 21 language constructs (virtual threads, pattern matching, record patterns).
- **High Concurrency & In-Memory Deduplication**: Thread-safe content-addressable SHA-256 session memory via Shree AI OS `MemorySDK`.

---

## Prerequisites

- **Java Development Kit (JDK)**: Java 21 LTS or newer (Oracle JDK, Eclipse Temurin, or OpenJDK).
- **Build Tool**: Apache Maven 3.9.0 or higher.
- **Operating System**: Linux, macOS, or Windows.
- *(Optional)* **Google Gemini API Key**: Set `GEMINI_API_KEY` to enable advanced reasoning via Gemini models (`gemini-3.6-flash`). If not set, SentinelPR automatically operates in deterministic local in-memory provider mode.

Verify your environment:
```bash
java -version
mvn -version
```

---

## Quickstart

### 1. Run Automated Test Suite

SentinelPR includes comprehensive unit and integration tests validating rule evaluation, patch synthesis, AST verification, and memory deduplication:

```bash
mvn clean test
```

Expected output:
```text
[INFO] Running com.sentinelpr.SentinelPrApplicationTest
[SentinelPR] No GEMINI_API_KEY provided; operating in deterministic in-memory provider mode.
[SentinelPR:Memory] Recorded audit session into Memory Kernel for f15a5433f40d
[TEST PASSED] SentinelPR Report Summary: Audit completed. Scanned 1 source file(s), identified 3 vulnerability finding(s), synthesized 3 verified patch(es).
[TEST PATCH GENERATED for SEC-001-FAIL-OPEN]: ...
[TEST PATCH GENERATED for SEC-002-UNCLOSED-STREAM]: ...
[TEST PATCH GENERATED for SEC-003-VOLATILE-COMPOUND]: ...
[INFO] Tests run: 3, Failures: 0, Errors: 0, Skipped: 0
[INFO] BUILD SUCCESS
```

### 2. Execute CLI Audit

Audit any Java source file or project tree directly using the Maven `exec:java` runner:

#### On Linux / macOS / Bash:
```bash
mvn test-compile exec:java \
  -Dexec.mainClass="com.sentinelpr.cli.SentinelCliRunner" \
  -Dexec.classpathScope=test \
  -Dexec.args="src/test/java/com/sentinelpr/fixture/VulnerableService.java"
```

#### On Windows (PowerShell):
```powershell
mvn test-compile exec:java `
  "-Dexec.mainClass=com.sentinelpr.cli.SentinelCliRunner" `
  "-Dexec.classpathScope=test" `
  "-Dexec.args=src/test/java/com/sentinelpr/fixture/VulnerableService.java"
```

#### Running via Packaged Standalone JAR:
```bash
mvn clean package -DskipTests
java -jar target/sentinel-pr-1.0.0.jar src/test/java/com/sentinelpr/fixture/VulnerableService.java
```

### 3. Start REST API Server

Start the SentinelPR Spring Boot microservice:

```bash
mvn spring-boot:run
```

By default, the server binds to `http://localhost:8080`.

#### Verify Health:
```bash
curl -s http://localhost:8080/api/v1/sentinel/health
```

Output:
```json
{
  "service": "SentinelPR - Enterprise Code & Security Review Copilot",
  "status": "UP",
  "platform": "Shree AI OS (1.0.6-developer-preview)",
  "rules": 4
}
```

#### Trigger a Review Request:
```bash
curl -X POST http://localhost:8080/api/v1/sentinel/review \
  -H "Content-Type: application/json" \
  -d '{"targetPath": "src/test/java/com/sentinelpr/fixture/VulnerableService.java"}'
```

---

## Supported Security Rules

| Rule ID | Severity | CWE | Vulnerability Description |
|---|---|---|---|
| **`SEC-001-FAIL-OPEN`** | `CRITICAL` | [CWE-393](https://cwe.mitre.org/data/definitions/393.html) | Catch block catches exception (e.g. `NullPointerException`, `Exception`) and returns `true`, creating an unauthorized authentication/authorization bypass. |
| **`SEC-002-UNCLOSED-STREAM`** | `HIGH` | [CWE-404](https://cwe.mitre.org/data/definitions/404.html) | File/Network stream (`FileInputStream`, etc.) instantiated without try-with-resources or deterministic closure, causing file descriptor leaks. |
| **`SEC-003-VOLATILE-COMPOUND`** | `HIGH` | [CWE-362](https://cwe.mitre.org/data/definitions/362.html) | Non-atomic compound mutation (`counter++`, `counter--`, `counter += 1`) on `volatile` variable, leading to lost updates under concurrency. |
| **`SEC-004-UNISOLATED-SUBPROCESS`** | `CRITICAL` | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) | Un-isolated `Runtime.getRuntime().exec` without argument tokenization or execution constraints, exposing command injection risks. |

*For complete details, patch examples, and remediation rationale, see the [SentinelPR Usage Guide](USAGE_GUIDE.md).*

---

## Project Structure

```
sentinel-pr/
|-- pom.xml                                      # Maven build configuration & dependencies
|-- README.md                                    # Project architecture and quickstart guide
|-- USAGE_GUIDE.md                               # Rules catalog, CLI/API guide, and CI/CD workflow
`-- src/
    |-- main/
    |   |-- java/com/sentinelpr/
    |   |   |-- SentinelPrApplication.java       # Spring Boot main application & bean definitions
    |   |   |-- api/
    |   |   |   |-- SentinelReviewController.java# REST API endpoint (/api/v1/sentinel/review)
    |   |   |   `-- dto/
    |   |   |       `-- ReviewFileRequest.java   # Request payload DTO
    |   |   |-- cli/
    |   |   |   `-- SentinelCliRunner.java       # Command-line interface runner
    |   |   |-- client/
    |   |   |   |-- SentinelClient.java          # Shree AI OS singleton bootstrap & facade
    |   |   |   |-- ProjectFacade.java           # AST parsing & symbol extraction facade
    |   |   |   |-- ReasoningFacade.java         # Causal vulnerability evaluation facade
    |   |   |   `-- DeveloperFacade.java         # Patch synthesis & diff generation facade
    |   |   `-- core/
    |   |       |-- model/
    |   |       |   |-- InspectedSource.java     # Rich AST source graph model
    |   |       |   |-- ReviewReport.java        # Structured audit report model
    |   |       |   |-- SecurityFinding.java     # Finding violation model
    |   |       |   |-- SecurityRule.java        # Security rules enumeration
    |   |       |   |-- Severity.java            # Severity enum (CRITICAL, HIGH, MEDIUM, LOW)
    |   |       |   `-- UnifiedDiffPatch.java    # Synthesized patch & diff model
    |   |       `-- service/
    |   |           |-- CodeInspectionService.java   # Source & directory inspection service
    |   |           |-- RuleEvaluationService.java   # Rule evaluation dispatcher
    |   |           |-- AutomatedPatchService.java   # Patch synthesis orchestrator
    |   |           |-- ReviewSessionMemory.java     # SHA-256 fingerprint deduplication service
    |   |           `-- SentinelAuditOrchestrator.java # End-to-end review pipeline orchestrator
    |   `-- resources/
    |       `-- application.properties           # Spring Boot application configuration
    `-- test/
        `-- java/com/sentinelpr/
            |-- SentinelPrApplicationTest.java   # Integration test suite
            `-- fixture/
                `-- VulnerableService.java       # Test fixture with deliberate vulnerabilities
```

---

## Configuration

SentinelPR can be configured via environment variables or `application.properties`:

| Variable / Property | Default | Description |
|---|---|---|
| `server.port` | `8080` | Port for the Spring Boot REST API server. |
| `SHREE_API_KEY` | `local` | Shree AI OS platform API key. |
| `GEMINI_API_KEY` | *(empty)* | Optional Google Gemini BYOK API key for advanced cloud-assisted causal reasoning. |
| `sentinel.copilot.default-rule-profile` | `enterprise-strict` | Active security rule evaluation profile. |
#   s e n t i n e l - p r  
 