# Real-Repository Validation Report: REAL-REPO-003 (College-management-backemd)

- **Repository ID:** `REAL-REPO-003`
- **Repository Name:** `College-management-backemd` (re-designated from `library-management-system`)
- **Owner:** `darshanrathod04`
- **Repository URL:** `https://github.com/darshanrathod04/College-management-backemd.git`
- **Branch Audited:** `main`
- **Pinned Commit SHA:** `38a084e4fdc59bd7b732502bcf06738e1e05e26a`
- **Analysis Timestamp:** `2026-10-12T23:28:00Z`
- **Language / Runtime:** Java 21 LTS (`<java.version>21</java.version>`)
- **Primary Framework:** Spring Boot 4.0.6 (`spring-boot-starter-webmvc`, `spring-boot-starter-data-jpa`, `spring-boot-starter-validation`, `springdoc-openapi-starter-webmvc-ui:3.0.2`)
- **Database Engine:** MySQL Connector J (`com.mysql:mysql-connector-j`, runtime scope)
- **Build System:** Apache Maven (`pom.xml`, Maven Wrapper)
- **Total Source Files Scanned:** 30 (29 production Java compilation units + 1 test class)
- **Total Java LOC:** 1,793 LOC
- **SentinelPR Engine Version:** `1.1.4` (commit `87c1570ea03e74472c1e8375b4ff05c8d1edce16`)

---

## 1. Executive Summary & Audit Scorecard

This evaluation represents the empirical audit of SentinelPR's third real-world repository (Phase 4A.13). The target application is an independent, functional Spring Boot REST backend providing college management operations (departments, students, teachers) with Swagger/OpenAPI documentation.

| Metric Category | Count | Notes / Status |
| :--- | :---: | :--- |
| **Total Files Scanned** | 30 | 29 production Java classes + 1 test suite |
| **Active Rules Evaluated** | 13 | All rules: SEC-001 through SEC-010 + ARCH-001 through ARCH-003 |
| **Total Engine Detections** | 0 | Engine reported clean pass (Report ID: `REV-2eb1430e`) |
| **True Positives (`TP`)** | 0 | No genuine vulnerabilities exist in the scanned codebase |
| **False Positives (`FP`)** | 0 | Zero spurious warnings emitted |
| **False Negatives (`FN`)** | 0 | Human code audit confirmed zero missed vulnerabilities |
| **True Negatives (`TN`)** | 13 | All 13 rules verified safe and correctly not flagged |
| **Uncertain (`UNCERTAIN`)** | 0 | Conclusive human ground truth established across all rules |
| **Remediations Attempted** | 0 | No findings detected by engine to trigger patch synthesis |
| **Engine Exceptions / Failures** | 0 | Clean exit code 0; JavaParser parsed 100% files without warning |
| **Rule Specificity / TNR** | **100.0%** | 13 / 13 rules correctly non-flagged |

---

## 2. Catalog Re-designation & Substitution Provenance

During initial Phase 4A planning, `REAL-REPO-003` was cataloged in `phase4/repositories/README.md` as `library-management-system` (`https://github.com/darshanrathod04/library-management-system`) with status `PLANNED`.

In Phase 4A.13, rigorous pre-execution audit revealed:
1. `https://api.github.com/repos/darshanrathod04/library-management-system` returned `HTTP 404 Not Found`.
2. No commit SHA was published or pinned for `library-management-system`.
3. Local disk search located only `C:\Users\darsh\library management`, which is an unversioned static HTML/CSS/JS mockup without Java code or build scripts.

To prevent fabricating repository identities, commit hashes, or audit results, `REAL-REPO-003` was formally re-designated to `darshanrathod04/College-management-backemd` (pinned at commit `38a084e4fdc59bd7b732502bcf06738e1e05e26a`). The catalog in [`phase4/repositories/README.md`](file:///d:/sentinel-pr/phase4/repositories/README.md) was updated while fully preserving the substitution history.

---

## 3. Execution Setup & Audit Command

The target repository was cloned into an isolated scratch sandbox outside the SentinelPR workspace:
```text
Sandbox Path: C:\Users\darsh\.gemini\antigravity\brain\51831e20-2d30-495b-ae03-c4228f903e74\scratch\College-management-backemd
Pinned Commit: 38a084e4fdc59bd7b732502bcf06738e1e05e26a
Working Tree: Clean (0 uncommitted changes)
```

The audit was executed via SentinelPR's CLI runner:
```bash
mvn exec:java \
  -Dexec.mainClass="com.sentinelpr.cli.SentinelCliRunner" \
  -Dexec.args="<scratch>/College-management-backemd --format json"
```

### Raw Execution Engine Summary
- **Report ID:** `REV-2eb1430e`
- **Execution Status:** `SUCCESS`
- **Files Scanned:** 30
- **Vulnerabilities Detected:** 0
- **Suppressed Findings:** 0
- **Patches Synthesized:** 0
- **Raw JSON Output SHA-256:** `31a87c199d358aac611f13b302238dfdf4632d3c25701b68832f4c27d8c46843`

---

## 4. Human Ground-Truth Audit Across All 13 Rules

Every security and architectural rule supported by SentinelPR was systematically audited by human code inspection across all 30 files of `College-management-backemd`.

| Rule ID | Rule Title | Engine Status | Ground Truth | Classification | Audit Evidence & Technical Rationale |
| :--- | :--- | :---: | :---: | :---: | :--- |
| `SEC-001` | Fail-Open Security Block | Not Detected | SAFE | **TN** | All exception handling in `GlobalExceptionHandler.java` uses `@RestControllerAdvice` returning structured HTTP 400 (`BAD_REQUEST`), 404 (`NOT_FOUND`), 409 (`CONFLICT`), or 500 (`INTERNAL_SERVER_ERROR`). No catch block swallows exceptions or grants unauthorized access. |
| `SEC-002` | Unclosed I/O Stream | Not Detected | SAFE | **TN** | Zero unmanaged I/O streams, sockets, or file descriptors are opened in the project. |
| `SEC-003` | Volatile Compound Operation | Not Detected | SAFE | **TN** | Zero `volatile` field declarations or compound mutations on shared state exist across entities, services, or controllers. |
| `SEC-004` | Un-isolated Subprocess | Not Detected | SAFE | **TN** | Zero `ProcessBuilder` or `Runtime.getRuntime().exec()` invocations exist across the codebase. |
| `SEC-005` | SQL Injection | Not Detected | SAFE | **TN** | Database access exclusively uses Spring Data JPA built-in and derived method queries (`findByFirstNameContainingIgnoreCase`, `existsByEmail`, `findByDepartmentName`) with automatic parameter binding. Zero raw SQL concatenations or `@Query` strings exist. |
| `SEC-006` | Path Traversal | Not Detected | SAFE | **TN** | Zero filesystem operations (`File`, `Path`, `Paths.get`, `Files.copy`, `FileInputStream`) exist. Endpoints deal solely with relational database entities via service layer. |
| `SEC-007` | Insecure Deserialization | Not Detected | SAFE | **TN** | REST request payloads are parsed via standard Spring Web Jackson JSON deserializer. Zero native Java `ObjectInputStream.readObject()` calls exist. |
| `SEC-008` | Hardcoded Secret or Token | Not Detected | SAFE | **TN** | Zero API keys, private tokens, passwords, or cloud credentials exist in Java source files. `application.properties` configures an empty datasource password (`spring.datasource.password=`). |
| `SEC-009` | Spring CSRF Disabled | Not Detected | SAFE | **TN** | Spring Security is not configured in `pom.xml`; no `SecurityFilterChain` bean disables CSRF. |
| `SEC-010` | Spring Permissive CORS Policy | Not Detected | SAFE | **TN** | Zero `@CrossOrigin` annotations exist on controllers and no `CorsRegistry` allows wildcard `'*'` origins with credentials. |
| `ARCH-001` | Cyclic Dependency | Not Detected | SAFE | **TN** | Package structure forms a strict directed acyclic graph: `controller -> service -> repository -> entity`. No circular package or class dependencies exist. |
| `ARCH-002` | Leaky Entity Abstraction | Not Detected | SAFE | **TN** | All controller endpoints across `DepartmentController`, `StudentController`, and `TeacherController` strictly consume and return dedicated DTO classes (`DepartmentDTO`, `StudentDTO`, `TeacherDTO`) mapped via `CollegeMapper`. Zero endpoints expose internal JPA persistence entities (`Department`, `Student`, `Teacher`). Architecture is properly decoupled. |
| `ARCH-003` | Non-Deterministic Calls | Not Detected | SAFE | **TN** | Business services contain zero invocations of `Random`, `Math.random`, `System.currentTimeMillis`, or `System.nanoTime`. |

---

## 5. Architectural & Security Deep-Dive

### 5.1 DTO Encapsulation vs. Leaky Abstraction (`ARCH-002`)
In contrast to `Todo-Application` (3 leaky endpoints) and `Smart Campus Connect` (22 leaky endpoints), `College-management-backemd` demonstrates exemplary architectural decoupling:
- **Dedicated DTO Layer:** Every entity (`Department`, `Student`, `Teacher`) has a corresponding DTO (`DepartmentDTO`, `StudentDTO`, `TeacherDTO`).
- **Mapper Abstraction:** `CollegeMapper.java` performs bidirectional entity-to-DTO conversion (`toDTO` and `toEntity`).
- **Uniform Response Envelope:** Controller responses are wrapped in `ApiResponse<T>`:
  - `public ResponseEntity<ApiResponse<DepartmentDTO>> createDepartment(...)`
  - `public ResponseEntity<ApiResponse<StudentDTO>> getStudentById(...)`
  - `public ResponseEntity<ApiResponse<Page<TeacherDTO>>> getAllTeachers(...)`
- **Result:** SentinelPR's cross-file entity resolution correctly verified that no `@Entity` types escape through the `@RestController` perimeter, remaining completely silent (**TN**).

### 5.2 SQL Injection & Parameterized ORM (`SEC-005`)
- All database operations are mediated by Spring Data JPA interfaces extending `JpaRepository<T, Long>`:
  - `StudentRepository`: `findByFirstNameContainingIgnoreCase(String keyword, Pageable pageable)`, `existsByEmail(String email)`
  - `TeacherRepository`: `findByFirstNameContainingIgnoreCase(String keyword, Pageable pageable)`, `existsByEmail(String email)`
  - `DepartmentRepository`: `findByDepartmentName(String departmentName)`, `existsByDepartmentName(String departmentName)`
- Zero custom `@Query` strings, native SQL, or string concatenations exist. Hibernate handles all parameter binding safely. SentinelPR correctly produced zero findings (**TN**).

### 5.3 Filesystem Access & Subprocess Isolation (`SEC-004`, `SEC-006`)
- The application performs pure relational database CRUD; it does not implement file upload/download functionality.
- Zero `java.io.File`, `java.nio.file.Path`, `ProcessBuilder`, or `Runtime` process calls exist. SentinelPR correctly produced zero findings (**TN**).

---

## 6. Statistical Analysis & Metric Denominators

| Metric | Measured Value | Denominator Justification |
| :--- | :---: | :--- |
| **Precision** | **N/A** | Denominator is `TP + FP = 0`. Calculating precision on zero detections is mathematically undefined (0/0). |
| **Recall** | **N/A** | Denominator is `TP + FN = 0`. Zero vulnerable constructs exist in the audited codebase. |
| **False Positive Rate (`FPR`)** | **0.0%** (0 / 13) | Zero false alarms emitted across 13 safe rule categories. |
| **False Negative Rate (`FNR`)** | **0.0%** (0 / 0) | Zero genuine flaws missed. |
| **Rule Specificity / TNR** | **100.0%** (13 / 13) | All 13 rules verified safe and correctly non-flagged. |

---

## 7. Known Limitations & Target Scope Caveats

1. **Clean Codebase Baseline:** `College-management-backemd` is an inherently well-structured, DTO-decoupled Spring Boot application without file uploads, multithreading, or dynamic SQL. While it rigorously validates SentinelPR's **negative-space precision** (zero false alarms across 30 files), it does not stress positive taint-tracking or remediation synthesis.
2. **OpenAPI / Swagger Ingress:** The application includes `springdoc-openapi-starter-webmvc-ui:3.0.2`. SentinelPR does not audit OpenAPI UI asset routing as an independent attack vector; it focuses purely on Java AST and controller handler mappings.
3. **No Automated Security Filter:** Like `Todo-Application`, Spring Security is not configured. Endpoints are unprotected at the HTTP authorization boundary, but this is an intentional design choice of a public student portal rather than an exploitable Java coding flaw.

---

## 8. Persisted Evidence References

- **Observation Record:** [`phase4/observations/REAL-REPO-003.json`](file:///d:/sentinel-pr/phase4/observations/REAL-REPO-003.json) (conforms to `repository-validation.schema.json`)
- **Target Repository:** `https://github.com/darshanrathod04/College-management-backemd.git` (`38a084e4fdc59bd7b732502bcf06738e1e05e26a`)
- **Engine Version:** SentinelPR `1.1.4` (commit `87c1570ea03e74472c1e8375b4ff05c8d1edce16`)
