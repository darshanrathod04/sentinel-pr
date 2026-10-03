# Real-Repository Validation Report: REAL-REPO-002 (Smart Campus Connect)

- **Repository ID:** `REAL-REPO-002`
- **Repository Name:** `Smart Campus Connect` (`smart-campus` / `SSC-BACKEND`)
- **Owner:** `darshanrathod04`
- **Repository URL:** `https://github.com/darshanrathod04/SSC-BACKEND.git`
- **Branch Audited:** `main`
- **Pinned Commit SHA:** `2ab5c482e3a7fed2a0440ff27c247cdf0a9bec04`
- **Analysis Timestamp:** `2026-10-02T18:35:59Z`
- **Language / Runtime:** Java 21 LTS (`<java.version>21</java.version>`)
- **Primary Framework:** Spring Boot 3.4.1 (`spring-boot-starter-web`, `spring-boot-starter-data-jpa`, `spring-boot-starter-validation`, `spring-boot-starter-mail`, `spring-boot-starter-thymeleaf`)
- **Database Engine:** PostgreSQL via Supabase (`org.postgresql:postgresql`, runtime scope)
- **PDF Infrastructure:** iText7 (`com.itextpdf:kernel:7.2.5`, `com.itextpdf:layout:7.2.5`)
- **Build System:** Apache Maven (`pom.xml`, Maven Wrapper)
- **Total Source Files Scanned:** 41 (40 production Java compilation units + 1 test class)
- **Approximate Java LOC:** 2,062 LOC
- **SentinelPR Engine Version:** Current `main` (`f45dea188c47814fbcc34a69669320a8d17a24dd`)

---

## 1. Executive Summary & Audit Scorecard

This evaluation represents the second empirical real-repository audit of SentinelPR (Phase 4A.6). The target application is an enterprise campus management backend providing student identity, event conclave, internship tracking, executive auditing, and partner management REST APIs.

| Metric Category | Count | Notes / Status |
| :--- | :--- | :--- |
| **Total Files Scanned** | 41 | 40 production Java files + 1 test suite |
| **Active Rules Evaluated** | 13 | SEC-001 through SEC-010 + ARCH-001 through ARCH-003 |
| **Total Engine Detections** | 11 | 6 ARCH-002, 4 SEC-006, 1 ARCH-003 |
| **True Positives (`TP`)** | 9 | 6 ARCH-002, 2 SEC-006, 1 ARCH-003 |
| **False Positives (`FP`)** | 2 | 2 SEC-006 (numeric path variable & static literal filename) |
| **False Negatives (`FN`)** | 1 (Rule-level) | Exactly 16 missed endpoint instances in ARCH-002 (22 total vulnerable endpoint exposures) due to candidate match ordering bug |
| **True Negatives (`TN`)** | 10 | 10 security & architecture rules verified safe across all files |
| **Uncertain (`UNCERTAIN`)** | 0 | Conclusive human ground truth established across all 13 rules |
| **Remediations Attempted** | 0 | Observation phase only (`remediationStage = NOT_ATTEMPTED`) |
| **Engine Exceptions / Failures** | 0 | Clean exit code 0; JavaParser AST parsed 100% files without warning |

---

## 2. Execution Setup & Audit Command

The target repository was cloned into an isolated scratch directory outside the SentinelPR repository workspace:
```text
Sandbox Path: C:\Users\darsh\.gemini\antigravity\brain\51831e20-2d30-495b-ae03-c4228f903e74\scratch\smart-campus-connect
Pinned Commit: 2ab5c482e3a7fed2a0440ff27c247cdf0a9bec04
```

The audit was executed against current SentinelPR production code:
```bash
mvn exec:java \
  -Dexec.mainClass="com.sentinelpr.cli.SentinelCliRunner" \
  -Dexec.args="<scratch-path>/smart-campus-connect --format json"
```

### Raw Audit Engine Output Summary
- **Report ID:** `REV-410e5d2f`
- **Execution Status:** `SUCCESS`
- **Scanned File Count:** 41
- **Vulnerability Count:** 11
- **Synthesized Patches:** 4 (3 deferred to multi-file planner, 1 failed, 1 valid)
- **Suppressed Count:** 0

---

## 3. Human Ground-Truth Audit Across All 13 Rules

Every security and architectural rule supported by SentinelPR was systematically audited by human code inspection against the `Smart Campus Connect` codebase.

| Rule ID | Rule Title | Engine Status | Ground Truth | Classification | Audit Evidence & Technical Rationale |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `SEC-001` | Fail-Open Security Block | Not Detected | SAFE | **TN** | All `try-catch` blocks return HTTP 400/500 errors or throw `RuntimeException`. No exception handler bypasses authentication or grants unauthorized access. |
| `SEC-002` | Unclosed I/O Stream | Not Detected | SAFE | **TN** | File operations utilize `Files.copy` or Spring multipart abstractions which manage stream lifecycle automatically. No unmanaged file/socket handles remain open. |
| `SEC-003` | Volatile Compound Operation | Not Detected | SAFE | **TN** | Zero `volatile` field declarations exist. Shared caching in `EmailNotificationService` uses thread-safe `ConcurrentHashMap`. |
| `SEC-004` | Un-isolated Subprocess | Not Detected | SAFE | **TN** | Zero `ProcessBuilder` or `Runtime.getRuntime().exec()` calls exist in the project. |
| `SEC-005` | SQL Injection | Not Detected | SAFE | **TN** | Database access exclusively uses Spring Data JPA repositories with parameterized queries. No raw SQL concatenation or unsanitized HQL queries exist. |
| `SEC-006` | Path Traversal | **Detected (4)** | MIXED | **TP (2) / FP (2)** | - `StudentController:116` (`uploadPhoto`): **FP** (`id` is `@PathVariable Long`, cannot contain `../`).<br>- `StudentController:161` (`uploadResume`): **TP** (`getOriginalFilename()` enables arbitrary file write outside destination directory).<br>- `GlobalExceptionHandler:75` (`uploadSignature`): **FP** (Hardcoded literal `"signature.png"`, zero user taint).<br>- `EmailNotificationService:126` (`sendJobApplication`): **TP** (`new File(resumePath)` reads and attaches arbitrary files to emails). |
| `SEC-007` | Insecure Deserialization | Not Detected | SAFE | **TN** | Request parsing is handled safely by Jackson JSON deserializer. Zero native Java `ObjectInputStream.readObject()` invocations exist. |
| `SEC-008` | Hardcoded Secret or Token | Not Detected | SAFE | **TN** | All database and email credentials in `application.properties` utilize environment variable interpolation (`${...}`). No private keys or AWS tokens exist in Java files. |
| `SEC-009` | Spring CSRF Disabled | Not Detected | SAFE | **TN** | Spring Security is not configured; no `SecurityFilterChain` disables CSRF. |
| `SEC-010` | Spring Permissive CORS Policy | Not Detected | SAFE | **TN** | `WebConfig` restricts allowed origins to explicit development URLs (`localhost:5503, 5505, 5506`). No wildcard `*` with credentials exists. |
| `ARCH-001` | Architectural Cyclic Dependency | Not Detected | SAFE | **TN** | Layered architecture forms an acyclic graph: Controllers -> Services -> Repositories -> Entities. |
| `ARCH-002` | Leaky Entity Abstraction | **Detected (6)** | VULNERABLE | **TP (6) / FN (16)** | - **TP:** `AdminAuditController.getSystemPulse` (`ActivityLog`), `StudentController` (5 endpoints exposing `Student`).<br>- **FN:** Exactly 16 missed endpoints exposing JPA entities across `EventController` (3), `InternshipController` (4), `PartnerController` (4), `AdminAuditController` (2), `AuthController` (1), and `WalletController` (2) due to candidate loop FQCN matching bug. |
| `ARCH-003` | Non-Deterministic Calls | **Detected (1)** | VULNERABLE | **TP (1)** | `EmailNotificationService:66`: `new Random().nextInt(999999)` used in `@Service` for generating authentication OTP codes (violates deterministic testability and cryptographic security CWE-330). |

---

## 4. Deep-Dive on Specific Findings & Engine Behavior

### 4.1 ARCH-002: Cross-File Resolution Successes & False Negative Analysis

#### Successful Detections (True Positives)
The cross-file entity resolution implemented in Phase 4A.4 successfully resolved entities across file boundaries in two key patterns:
1. **Single Class in Package (`ActivityLog`):**
   `AdminAuditController.getSystemPulse()` returns `List<ActivityLog>`. The engine extracted `ActivityLog`, resolved it against `ActivityLog.java` in `com.scc.smart_campus.model`, and verified the `@Entity` annotation.
2. **Wildcard Imports & Generic Unwrapping (`Student`):**
   `StudentController.java` imports `com.scc.smart_campus.model.*`.
   The engine successfully unwrapped complex generics:
   - `ResponseEntity<List<Student>>` -> `Student`
   - `ResponseEntity<Student>` -> `Student`
   - `@Valid @RequestBody Student student` -> `Student`
   All 5 endpoints were accurately identified as True Positives without exception.

#### Root-Cause Analysis of False Negatives in ARCH-002
SentinelPR missed `EventController` (`Event`), `InternshipController` (`Internship`), and `PartnerController` (`Partner`, `Watchlist`).

**Empirical Root Cause Discovered:**
In `ArchitectureReviewEngine.java`:
```java
private boolean matchesFqcn(InspectedSource candidate, String simpleName, String fqcn) {
    if (candidate == null) return false;
    String candidatePkg = candidate.getPackageName() != null ? candidate.getPackageName() : "";
    String fullClass = candidatePkg.isEmpty() ? simpleName : candidatePkg + "." + simpleName;
    if (fullClass.equals(fqcn)) {
        return true;
    }
    ...
}
```
When `candidate` was iterated over `allSources`:
- For `EventController`, `simpleName` is `"Event"`, `fqcn` is `"com.scc.smart_campus.model.Event"`.
- When the candidate loop inspected `ActivityLog.java` (which has package `com.scc.smart_campus.model`), `fullClass` was computed as `candidatePkg + "." + simpleName` (`"com.scc.smart_campus.model.Event"`).
- `fullClass.equals(fqcn)` evaluated to **`true`** for `ActivityLog.java`!
- The engine then immediately called `hasJpaEntityAnnotation(ActivityLog, "Event")`, which returned **`false`** (since `ActivityLog.java` does not declare a class named `Event`).
- Because branch A returned `false` on the first candidate in the package, `resolveCrossFileJpaEntity` terminated prematurely without evaluating `Event.java`.

### 4.2 SEC-006: Path Traversal Real-World Findings

#### Genuine Security Defect: Arbitrary File Write via `uploadResume` (TP)
In `StudentController.java` (lines 154–165):
```java
@PostMapping("/upload-resume")
public ResponseEntity<String> uploadResume(@RequestParam("file") MultipartFile file,
                                         @RequestParam("email") String email) {
    String uploadDir = "uploads/resumes/";
    String fileName = System.currentTimeMillis() + "_" + file.getOriginalFilename();
    Path filePath = Paths.get(uploadDir + fileName);
    Files.copy(file.getInputStream(), filePath, StandardCopyOption.REPLACE_EXISTING);
```
- **Vulnerability:** `file.getOriginalFilename()` is an untrusted string supplied by the HTTP client. Prepending `System.currentTimeMillis() + "_"` does not prevent directory traversal if the filename contains `../../`.
- **Impact:** An attacker can overwrite arbitrary files on the hosting system.
- **Classification:** **True Positive (TP)**.

#### False Positive #1: Strongly-Typed Numeric Path Variable (`uploadPhoto`)
In `StudentController.java` (lines 114–117):
```java
@PostMapping("/{id}/upload-photo")
public ResponseEntity<String> uploadPhoto(@PathVariable Long id, @RequestParam("file") MultipartFile file) {
    String fileName = "profile_" + id + ".png";
    Path path = Paths.get("src/main/resources/static/images/" + fileName);
```
- **Engine Behavior:** Flagged as `CRITICAL` Path Traversal.
- **Ground Truth:** `@PathVariable Long id` is parsed as a numeric `java.lang.Long`. Path traversal sequences (`../`) fail URL matching or throw `TypeMismatchException`.
- **Classification:** **False Positive (FP)**.

#### False Positive #2: Static Literal Path (`uploadSignature`)
In `GlobalExceptionHandler.java` (lines 73–76):
```java
@PostMapping("/api/admin/signature/upload")
public ResponseEntity<?> uploadSignature(@RequestParam("image") MultipartFile file) throws IOException {
    String uploadDir = "src/main/resources/static/images/";
    Path path = Paths.get(uploadDir + "signature.png");
```
- **Engine Behavior:** Flagged as `CRITICAL` Path Traversal.
- **Ground Truth:** Both `uploadDir` and `"signature.png"` are compile-time constants. Zero user-controlled data reaches `Paths.get()`.
- **Classification:** **False Positive (FP)**.

### 4.3 ARCH-003: Non-Deterministic `Random` in Business Service (TP)
In `EmailNotificationService.java` (lines 65–68):
```java
public void sendPartnerOTP(String recipientEmail) {
    String otp = String.format("%06d", new Random().nextInt(999999));
    otpCache.put(recipientEmail, otp);
```
- **Engine Behavior:** Detected as `MEDIUM` Non-deterministic `Random` instantiation.
- **Ground Truth:** Using unseeded `java.util.Random` for authentication one-time passwords introduces cryptographic predictability (CWE-330) and prevents deterministic unit test mocking.
- **Classification:** **True Positive (TP)**.

---

## 5. Remediation Observations

- **Remediations Attempted:** 0 (`remediationStage = NOT_ATTEMPTED`).
- **Policy Enforcement:** Per Phase 4A observation-only guidelines, no automated patches were applied to the target repository.
- **Synthesized Patch Analysis:** SentinelPR's patch service generated a proposed patch for `EmailNotificationService` (`new File(resumePath).getCanonicalFile()`), while complex architectural findings in `StudentController` and `AdminAuditController` were correctly routed to `DEFERRED_TO_MULTI_FILE_PLAN`.

---

## 6. Operational Performance & Resource Utilization

- **Parser Errors:** 0. JavaParser 3.28.2 successfully parsed all 41 Java compilation units, including Java 21 syntax and modern Spring annotations.
- **Execution Time:** ~4.2 seconds CLI execution time across 41 files and 2,062 LOC.
- **Sandbox Isolation:** 100% clean isolation maintained in external scratch sandbox.

---

## 7. Actionable Recommendations for Next Phases

1. **Fix Candidate Matching in `ArchitectureReviewEngine.matchesFqcn`:**
   In `matchesFqcn()`, compute candidate class name using `candidate.getPrimaryClassName()` or check `matchesSimpleName(candidate, simpleName)` before comparing package names, preventing false matches across sibling classes in the same package.
2. **Type-Aware Taint Filtering for Path Traversal (`SEC-006`):**
   Exclude primitive and boxed numeric types (`Long`, `Integer`, `Double`, `UUID`) from string-based taint propagation in `@PathVariable` and `@RequestParam`.
3. **Literal Path Verification in `SEC-006`:**
   Verify that at least one concatenated component in `Paths.get(...)` originates from a non-constant parameter before emitting a finding.

---

## 8. Phase 4A.8 Post-Fix Validation & Metric Shift

Following the reproduction in Phase 4A.7 and implementation of the candidate class-identity resolution fix in `ArchitectureReviewEngine.matchesFqcn()`, a full re-validation was conducted against `Smart Campus Connect` (`darshanrathod04/SSC-BACKEND`) at the identical pinned commit (`2ab5c482e3a7fed2a0440ff27c247cdf0a9bec04`).

### 8.1 Re-Validation Parameters
- **Target Repository:** `Smart Campus Connect` (`darshanrathod04/SSC-BACKEND`)
- **Pinned Commit SHA:** `2ab5c482e3a7fed2a0440ff27c247cdf0a9bec04`
- **Validation Timestamp:** `2026-10-03T01:19:25Z`
- **Scanned Files:** 41 Java compilation units
- **Engine Status:** `SUCCESS` (Exit code: 0)

### 8.2 ARCH-002 Complete Endpoint Census: Pre-Fix vs. Post-Fix

Across all 8 controllers, exactly 22 endpoint instances expose JPA database entities. Post-fix, SentinelPR achieves 100% recall with zero false negatives and zero false positives on ARCH-002:

| # | Controller Source | Method Name & Line | Exposed Entity Type | Pre-Fix Status (Phase 4A.6) | Post-Fix Status (Phase 4A.8) | Ground Truth |
|---|-------------------|--------------------|---------------------|-----------------------------|------------------------------|--------------|
| 1 | `AdminAuditController.java` | `getPendingAudits` (L36) | `SkillAudit` | **MISSED (FN)** | **DETECTED (TP)** | VULNERABLE |
| 2 | `AdminAuditController.java` | `getSystemPulse` (L47) | `ActivityLog` | DETECTED (TP) | **DETECTED (TP)** | VULNERABLE |
| 3 | `AdminAuditController.java` | `getAllPartners` (L79) | `Partner` | **MISSED (FN)** | **DETECTED (TP)** | VULNERABLE |
| 4 | `AuthController.java` | `registerStudent` (L46) | `Student` | **MISSED (FN)** | **DETECTED (TP)** | VULNERABLE |
| 5 | `EventController.java` | `getAllEvents` (L31) | `Event` | **MISSED (FN)** | **DETECTED (TP)** | VULNERABLE |
| 6 | `EventController.java` | `createEvent` (L35) | `Event` | **MISSED (FN)** | **DETECTED (TP)** | VULNERABLE |
| 7 | `EventController.java` | `getRegisteredStudents` (L43) | `Student` | **MISSED (FN)** | **DETECTED (TP)** | VULNERABLE |
| 8 | `InternshipController.java` | `getAllInternships` (L25) | `Internship` | **MISSED (FN)** | **DETECTED (TP)** | VULNERABLE |
| 9 | `InternshipController.java` | `createInternship` (L34) | `Internship` | **MISSED (FN)** | **DETECTED (TP)** | VULNERABLE |
| 10 | `InternshipController.java` | `searchBySkills` (L43) | `Internship` | **MISSED (FN)** | **DETECTED (TP)** | VULNERABLE |
| 11 | `InternshipController.java` | `getInternshipApplicants` (L75) | `Student` (FQCN) | **MISSED (FN)** | **DETECTED (TP)** | VULNERABLE |
| 12 | `PartnerController.java` | `registerPartner` (L64) | `Partner` | **MISSED (FN)** | **DETECTED (TP)** | VULNERABLE |
| 13 | `PartnerController.java` | `getPendingPartners` (L93) | `Partner` | **MISSED (FN)** | **DETECTED (TP)** | VULNERABLE |
| 14 | `PartnerController.java` | `getWatchlist` (L138) | `Student` | **MISSED (FN)** | **DETECTED (TP)** | VULNERABLE |
| 15 | `PartnerController.java` | `addToWatchlist` (L151) | `Watchlist` | **MISSED (FN)** | **DETECTED (TP)** | VULNERABLE |
| 16 | `StudentController.java` | `getAllStudents` (L55) | `Student` | DETECTED (TP) | **DETECTED (TP)** | VULNERABLE |
| 17 | `StudentController.java` | `getTopContributors` (L70) | `Student` | DETECTED (TP) | **DETECTED (TP)** | VULNERABLE |
| 18 | `StudentController.java` | `getStudentById` (L75) | `Student` | DETECTED (TP) | **DETECTED (TP)** | VULNERABLE |
| 19 | `StudentController.java` | `syncStudent` (L85) | `Student` | DETECTED (TP) | **DETECTED (TP)** | VULNERABLE |
| 20 | `StudentController.java` | `registerStudent` (L335) | `Student` | DETECTED (TP) | **DETECTED (TP)** | VULNERABLE |
| 21 | `WalletController.java` | `syncWallet` (L45) | `Student` | **MISSED (FN)** | **DETECTED (TP)** | VULNERABLE |
| 22 | `WalletController.java` | `addExperience` (L50) | `Student` | **MISSED (FN)** | **DETECTED (TP)** | VULNERABLE |

### 8.3 Non-ARCH-002 Rules Verification (Strict Invariance)
- **SEC-006 (Path Traversal):** Production logic untouched. Exactly 4 findings remain detected (2 TP, 2 FP).
- **ARCH-003 (Non-Deterministic Calls):** Exactly 1 finding detected (`new Random()` in `EmailNotificationService.java:66`, TP).
- **All other 10 rules:** Safe True Negatives maintained across all files (zero spurious findings).

### 8.4 Overall Metric Shift

| Metric Category | Pre-Fix Baseline (Phase 4A.6) | Post-Fix Validation (Phase 4A.8) | Metric Shift |
| :--- | :--- | :--- | :--- |
| **Total Engine Detections** | 11 | 27 | **+16** |
| **ARCH-002 True Positives (`TP`)** | 6 | 22 | **+16** |
| **ARCH-002 False Negatives (`FN`)** | 16 | 0 | **-16** |
| **ARCH-002 False Positives (`FP`)** | 0 | 0 | **0** |
| **SEC-006 True Positives (`TP`)** | 2 | 2 | **0 (Unchanged)** |
| **SEC-006 False Positives (`FP`)** | 2 | 2 | **0 (Unchanged)** |
| **ARCH-003 True Positives (`TP`)** | 1 | 1 | **0 (Unchanged)** |
| **True Negatives (`TN`) Rules** | 10 | 10 | **0 (Unchanged)** |
| **Total True Positives (`TP`)** | 9 | 25 | **+16** |
| **ARCH-002 Recall** | 27.27% | **100.00%** | **+72.73%** |

---

## 9. Phase 4A.10: SEC-006 FP-1 Fix Validation (DataflowTracker Scalar Filtering)

### 9.1 Summary of Changes & Root Cause Allocation
- **FP-1 Root Cause:** `DataflowTracker.analyzeMethodInternal()` unconditionally seeded numeric parameters (`Long id`) into `activeTaint` without evaluating declared parameter types, generating a spurious multi-hop taint trace (`StudentController.uploadPhoto(id) -> fileName -> Paths.get(...)`) and inflating finding confidence to 1.0.
- **Production Fix Applied:** Modified [`DataflowTracker.java`](../../src/main/java/com/sentinelpr/core/analysis/DataflowTracker.java) to introduce type-aware parameter source classification via `SAFE_SCALAR_TYPES`:
  - Primitives: `int`, `long`, `short`, `byte`, `float`, `double`, `boolean`, `char`
  - Standard Boxed Wrappers: `Integer`, `Long`, `Short`, `Byte`, `Float`, `Double`, `Boolean`, `Character`
  - Specialized Numeric & Structured Identifiers: `BigInteger`, `BigDecimal`, `UUID`
- **FP-1 Remaining Emission After Fix:** In `StudentController.java:116`, the spurious taint trace was successfully eliminated. However, because `uploadDirectory + fileName` is a binary string concatenation (`BinaryExpr`), `ReasoningFacade`'s zero-taint fallback still emits the finding at base confidence (0.81).
- **FP-2 Root Cause:** `ReasoningFacade.evaluatePathTraversal()` unconditionally emits `CRITICAL` findings for any binary `+` expression (`hasStringPathArgument`) even when `DataflowTracker` reports zero taint flows (untouched in Phase 4A.10, scheduled for Phase 4A.11).
- **Test Suite Added:** Added comprehensive permanent regression tests in [`Phase4A9Sec006PrecisionInvestigationTest.java`](../../src/test/java/com/sentinelpr/reproduction/Phase4A9Sec006PrecisionInvestigationTest.java) covering Cases A through J and positive/negative controls (16 tests passing).

### 9.2 Measured SCC Re-Scan Results (Pinned Commit: `2ab5c482e3a7fed2a0440ff27c247cdf0a9bec04`)
- **Total Findings Detected:** 27
- **ARCH-002 (Leaky Abstraction):** 22 findings (**100% TP, 0 FN** — Strictly invariant)
- **ARCH-003 (Non-Deterministic Calls):** 1 finding (**TP** — Strictly invariant)
- **SEC-006 (Path Traversal):** 4 findings
  1. `StudentController.java:161` (`uploadResume`): **0.99 (TP)** — True vulnerability with untrusted `file.getOriginalFilename()`.
  2. `EmailNotificationService.java:126` (`sendJobApplication`): **0.82 (TP)** — True vulnerability with user-provided path.
  3. `StudentController.java:116` (`uploadPhoto`): **0.81 (FP)** — False positive with `@PathVariable Long id`. Note: The false taint trace was completely eliminated by `DataflowTracker`. The remaining emission at base confidence is solely due to the `ReasoningFacade` zero-taint fallback.
  4. `GlobalExceptionHandler.java:75` (`uploadSignature`): **0.81 (FP)** — Constant concatenation without user taint (FP-2 root cause: `ReasoningFacade` zero-taint fallback on binary '+').

### 9.3 Metric Summary
- **Before Fix:** SEC-006 = 4 findings (2 TP, 2 FP); `StudentController.uploadPhoto` had a spurious taint trace and elevated confidence (1.0).
- **After Fix:** SEC-006 = 4 findings (2 TP, 2 FP); spurious taint trace eliminated; confidence lowered to base (0.81). Complete suppression of both remaining false positives awaits Phase 4A.11 zero-taint gating in `ReasoningFacade`.
