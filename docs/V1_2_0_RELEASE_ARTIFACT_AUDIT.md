# SentinelPR v1.2.0 — Final Release Artifact Audit Report

**Date:** 2026-11-07  
**Target Release:** `v1.2.0`  
**Evaluated Git Baseline SHA:** `f2223e6ca5db835771040f311fc466a7d5b73a8e`  
**Remote `origin/main` Status:** Synchronized at `f2223e6ca5db835771040f311fc466a7d5b73a8e`  
**Clean-Clone Tested SHA:** `f2223e6ca5db835771040f311fc466a7d5b73a8e`  
**Verdict:** **READY WITH CONDITIONS**  
**Release Authorization Status:** **NOT AUTHORIZED / PENDING MAINTAINER RESOLUTION**  
*(This task is strictly an audit. No Git tags, GitHub releases, version bumps in `pom.xml`, or public announcements have been created.)*

---

## 1. Repository Safety and Working Tree State

Before beginning build and inspection operations, the working tree state was recorded:
- **Local HEAD:** `f2223e6ca5db835771040f311fc466a7d5b73a8e`
- **Remote `origin/main`:** `f2223e6ca5db835771040f311fc466a7d5b73a8e`
- **Preserved Tracked Modifications (12 files):**
  - `src/main/java/com/sentinelpr/SentinelPrApplication.java`
  - `src/main/java/com/sentinelpr/api/SentinelReviewController.java`
  - `src/main/java/com/sentinelpr/client/ReasoningFacade.java`
  - `src/main/java/com/sentinelpr/core/analysis/DataflowTracker.java`
  - `src/main/java/com/sentinelpr/core/analysis/calibration/ConfidenceCalibrator.java`
  - `src/main/java/com/sentinelpr/core/analysis/taint/TaintSink.java`
  - `src/main/java/com/sentinelpr/core/governance/audit/AuditTrailEntry.java`
  - `src/main/java/com/sentinelpr/core/governance/audit/AuditTrailLogger.java`
  - `src/main/java/com/sentinelpr/core/model/ReviewReport.java`
  - `src/main/java/com/sentinelpr/core/service/SentinelAuditOrchestrator.java`
  - `src/main/java/com/sentinelpr/github/GitHubApiClient.java`
  - `src/test/java/com/sentinelpr/reproduction/Phase4A7SccFailureReproductionTest.java`
- **Preserved Untracked Paths (21 directories/files):**
  - `sentinel-pr/`, `src/main/resources/static/`, `src/main/java/com/sentinelpr/api/auth/`, `src/main/java/com/sentinelpr/core/watch/`, `src/main/java/com/sentinelpr/core/multirepo/`, and all related test suites.
- All pre-existing modified and untracked files were preserved without any destructive resets, cleans, stashes, or blind staging.

---

## 2. Build Environment and Verification Lifecycle

### 2.1 Build Environment
- **Operating System:** Windows 11 (amd64, 10.0)
- **Java Runtime:** Eclipse Adoptium JDK 21.0.7 (build 21.0.7+6-LTS)
- **Maven Version:** Apache Maven 3.9.11 (`D:\apache-maven-3.9.11`)

### 2.2 Maven Verification Build (`mvn clean verify`)
To eliminate interference from untracked local work, the release candidate was built from an isolated clone of the exact `origin/main` commit (`f2223e6ca5db835771040f311fc466a7d5b73a8e`):

- **Command:** `mvn clean verify`
- **Exit Code:** `0`
- **Build Duration:** `03:35 min`
- **Test Results Summary:**
  - **Tests run:** `254`
  - **Failures:** `0`
  - **Errors:** `0`
  - **Skipped:** `0`
  - **Status:** `BUILD SUCCESS`

*(Note on Local Workspace vs. Clean Clone: In the local dirty working tree, `mvn clean verify` attempted to compile and execute 341 tests, including 87 tests in untracked enterprise directories `src/test/java/com/sentinelpr/cli/` and `src/test/java/com/sentinelpr/core/multirepo/`. This failed on 2 uncommitted enterprise tests. In the clean remote clone, exactly 254 tracked tests exist, and all 254 passed cleanly.)*

---

## 3. Generated Artifact Names, Sizes, and SHA-256 Checksums

The Maven package and repackage lifecycle produced two artifacts in `target/`:

| Artifact Name | Type / Packaging | File Size (Bytes) | SHA-256 Checksum |
| :--- | :--- | :--- | :--- |
| **`sentinel-pr-1.1.4.jar`** | Spring Boot Executable Fat JAR (with nested `BOOT-INF/lib`) | 200,917,058 (~191.6 MB) | `76F2E419247D7CAEC05EE517629606CA9F8385CDA0748755B3F4CA25CB9D5A50` |
| **`sentinel-pr-1.1.4.jar.original`** | Standard Thin JAR (Application classes only) | 413,701 (~404 KB) | `1B0992D534030904EE947DAD7667FA27F0936A0B2B8AEF09E7C984E4F3920B69` |

*(Note on Artifact Versioning: The artifact currently bears version `1.1.4` because `pom.xml` version bump to `1.2.0` is strictly restricted to maintainer release authorization.)*

---

## 4. JAR Inspection and Archive Integrity

An inspection of the generated fat JAR (`sentinel-pr-1.1.4.jar`) was performed:

### 4.1 Manifest Attributes (`META-INF/MANIFEST.MF`)
```manifest
Manifest-Version: 1.0
Created-By: Maven JAR Plugin 3.4.2
Build-Jdk-Spec: 21
Implementation-Title: SentinelPR - Enterprise Code & Security Review Copilot
Implementation-Version: 1.1.4
Main-Class: org.springframework.boot.loader.launch.JarLauncher
Start-Class: com.sentinelpr.SentinelPrApplication
Spring-Boot-Version: 4.0.2
Spring-Boot-Classes: BOOT-INF/classes/
Spring-Boot-Lib: BOOT-INF/lib/
Spring-Boot-Classpath-Index: BOOT-INF/classpath.idx
Spring-Boot-Layers-Index: BOOT-INF/layers.idx
```

### 4.2 Content and Hygiene Verification
1. **Archive Integrity:** The JAR archive unpacked and decompressed without corruption or CRC errors.
2. **Exclusion of Test Classes:** A scan for test patterns (`jar tf ... | grep -i Test`) confirmed that **zero test classes** or fixtures are packaged in `BOOT-INF/classes`.
3. **Exclusion of Credentials and Sensitive Artifacts:** Confirmed **zero `.env` files, `.key` files, credentials, or private keys** exist in the archive. Only production classes (`SecretScanningEngine.class`, `HardcodedSecretRemediationStrategy.class`) matched security token queries.
4. **Java Runtime Compatibility:** The compiled bytecode specifies Java 21 LTS class file major version (`65.0`). Compatible with standard Java 21+ runtimes.

---

## 5. Clean-Environment Execution Results

The executable JAR was extracted to an isolated directory outside the repository (`C:\Users\darsh\AppData\Local\Temp\sentinel-clean-exec`) with zero repository or Maven dependencies.

### 5.1 CLI PropertiesLauncher Execution (Documented for GitHub Actions)
Executing via Spring Boot's `PropertiesLauncher` with `loader.main=com.sentinelpr.cli.SentinelCliRunner`:
```bash
java -Dloader.main=com.sentinelpr.cli.SentinelCliRunner -cp sentinel-pr.jar org.springframework.boot.loader.launch.PropertiesLauncher Sample.java
```
- **CLI Startup:** Started cleanly with Shree AI OS runtime initialization.
- **Help/Usage Menu:** Correctly printed full option menu on missing input and exited with code `3`.
- **Authorized Java Sample Scan:** Correctly scanned `Sample.java`, identified CRITICAL `UNISOLATED_SUBPROCESS`, generated verified unified diff patch, and exited with code `0`.
- **Authorized Python Sample Scan:** Correctly scanned `test_sqli.py`, identified `PYTHON_SQL_INJECTION`, enforced `MANUAL_REMEDIATION_REQUIRED`, and exited with code `0`.
- **Invalid Input Handling:** Scanning a non-existent file produced the controlled error `[SentinelPR:CLI] Error: Target path not found: ...` and exited with code `3`.
- **Zero Hidden Dependencies:** Verified that execution does not depend on repository files, git index, IDE, or Maven target folders.

### 5.2 Direct `java -jar` Execution Discrepancy (Identified Defect)
Executing via direct `java -jar sentinel-pr.jar`:
- **Observed Behavior:** Triggers `JarLauncher` -> `SentinelPrApplication.main(args)`.
- **Error Encountered:** Spring Boot 4.0.2 application context initialization fails:
  ```text
  org.springframework.beans.factory.BeanCreationException: Error creating bean with name 'sentinelReviewController': Failed to instantiate [com.sentinelpr.api.SentinelReviewController]: No default constructor found
  Caused by: java.lang.NoSuchMethodException: com.sentinelpr.api.SentinelReviewController.<init>()
  ```
- **Root Cause Analysis:** `SentinelReviewController` has multiple parameterized constructors but lacks `@Autowired` on any constructor and has no `@Bean` definition in `SentinelPrApplication`. Spring Boot component scanning attempts to locate a non-existent no-arg constructor, causing context initialization failure when running as a Spring Boot web service.

---

## 6. GitHub Action Compatibility Audit

An audit of [`action.yml`](file:///d:/sentinel-pr/action.yml) confirmed:

1. **Artifact Filename & Download URL:**
   - Expected asset: `https://github.com/darshanrathod04/sentinel-pr/releases/download/v${VERSION}/sentinel-pr-${VERSION}.jar`.
   - Saved locally as: `sentinel-pr.jar`.
2. **Version Input & Fallback:**
   - Default input: `version: "1.2.0"`.
   - Fallback logic: If `v1.2.0` release asset is not found (HTTP 404), it falls back gracefully to `v1.1.4`.
3. **Execution Command:**
   - Line 123:
     ```bash
     CMD=(java -Dloader.main=com.sentinelpr.cli.SentinelCliRunner -cp sentinel-pr.jar org.springframework.boot.loader.launch.PropertiesLauncher --target .)
     ```
   - Invokes `PropertiesLauncher` directly, bypassing the Spring Boot web context initialization issue and executing `SentinelCliRunner` successfully.
4. **PR Diff Contract:** Enforces three-dot merge-base diff extraction with safe fallback to two-dot diff and GitHub API diff; explicitly refuses unconstrained full scan on PR failure.

---

## 7. Release Documentation Discrepancies and Python Boundaries

### 7.1 Identified Discrepancies
1. **CLI Invocation Syntax:**
   - `README.md` and `docs/CLI.md` document `java -jar sentinel-pr.jar <target-path> [options]`.
   - As demonstrated in Section 5.2, direct `java -jar` triggers `SentinelPrApplication` which crashes on `SentinelReviewController` bean instantiation. Users running the CLI must use `java -Dloader.main=com.sentinelpr.cli.SentinelCliRunner -cp sentinel-pr.jar org.springframework.boot.loader.launch.PropertiesLauncher <target-path>` (as GitHub Actions does).
2. **Version Numbers:**
   - `pom.xml`: `1.1.4` (pending maintainer bump).
   - `README.md`: mentions `v1.1.4`.
   - `docs/CLI.md`: mentions `v1.0.0`.
   - `action.yml`: defaults to `1.2.0`.

### 7.2 Explicit Python Architecture Boundaries
- **Intra-Procedural Taint Only:** Dataflow propagation is strictly intra-procedural (bounded to the enclosing function/method). Inter-procedural call-graph tracking is not implemented.
- **Unsupported Automated Python Remediation:** 100% of detected Python findings require manual remediation (`MANUAL_REMEDIATION_REQUIRED`). Zero automated AST diff patches are synthesized for Python.
- **Static Manifest Scanning Only:** Supports `requirements.txt`, `pyproject.toml`, `poetry.lock`, and `Pipfile`. Does not execute or parse dynamic `setup.py` or JSON `Pipfile.lock`.
- **Curated Offline Database:** Evaluates dependencies against a static dictionary of 8 critical CVEs.
- **Non-Exhaustive Detection:** Analysis is targeted to high-confidence AST patterns and sinks. SentinelPR makes no claim of comprehensive Python security detection.

---

## 8. Exact Reproduction Commands

```bash
# 1. Clean clone from origin/main
git clone https://github.com/darshanrathod04/sentinel-pr.git /tmp/sentinel-audit
cd /tmp/sentinel-audit
git checkout f2223e6ca5db835771040f311fc466a7d5b73a8e

# 2. Run full Maven verification lifecycle
mvn clean verify

# 3. Verify SHA-256 checksums
certutil -hashfile target/sentinel-pr-1.1.4.jar SHA256

# 4. Clean execution of CLI
mkdir /tmp/clean-exec
cp target/sentinel-pr-1.1.4.jar /tmp/clean-exec/sentinel-pr.jar
cd /tmp/clean-exec
java "-Dloader.main=com.sentinelpr.cli.SentinelCliRunner" -cp sentinel-pr.jar org.springframework.boot.loader.launch.PropertiesLauncher
```

---

## 9. Final Release Artifact Verdict

### **Verdict:** **READY WITH CONDITIONS**

### Conditions for Maintainer Release Sign-off:
1. **Fix or Document Direct `java -jar` Invocations:**
   - In `SentinelReviewController.java`, add `@Autowired` on the preferred constructor (or declare a `@Bean public SentinelReviewController ...` in `SentinelPrApplication.java`), OR
   - Update `README.md` and `docs/CLI.md` to document the exact `PropertiesLauncher` invocation command used by GitHub Actions (`java -Dloader.main=com.sentinelpr.cli.SentinelCliRunner -cp sentinel-pr.jar org.springframework.boot.loader.launch.PropertiesLauncher ...`).
2. **Version Bump in `pom.xml`:** Update `<version>1.1.4</version>` to `<version>1.2.0</version>` prior to tagging `v1.2.0`.
3. **Align Documentation Headers:** Synchronize version labels in `README.md` and `docs/CLI.md` to `v1.2.0`.
4. **Isolate Release Builds:** Maintainers must run `mvn clean verify` in a clean checkout to prevent uncommitted local enterprise tests from being included in the build.
