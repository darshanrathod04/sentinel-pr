# SentinelPR — Security & Architecture Rule Catalog (v1.0.0)

All rules are declared in `com.sentinelpr.core.model.SecurityRule` and evaluated by `ReasoningFacade`, `SecretScanningEngine`, `FrameworkContextAnalyzer`, and `ArchitectureReviewEngine` on JavaParser ASTs (Java 21 language level). 13 rules ship in v1.0.0: 10 security (`SEC-*`) and 3 architectural (`ARCH-*`).

Severity levels (`Severity` enum): `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`. SARIF mapping: CRITICAL/HIGH → `error`, MEDIUM → `warning`, LOW/INFO → `note`.

Suppression options (per finding): `@SuppressWarnings("sentinel:<RULE_ID>")` or `"sentinel:all"`, inline `// sentinel-ignore <RULE_ID>` comments, and `.sentinelignore` files — see [docs/GOVERNANCE.md](GOVERNANCE.md).

---

## SEC-001-FAIL-OPEN — Fail-Open Security Block

| | |
|---|---|
| **Severity** | CRITICAL |
| **CWE** | CWE-393 |
| **Analyzer** | `ReasoningFacade.evaluateFailOpenSecurity` |

**Detection logic.** Flags `catch` clauses that intercept security-relevant exceptions (`NullPointerException`, `Exception`, `Throwable`, `RuntimeException`, `SecurityException`) inside security-sensitive contexts — methods returning `boolean`, or method names containing authorization vocabulary (`auth`, `security`, `permission`, `access`, `check`, `verify`, `validate`, `can`) — where the catch block grants access (returns `true` or completes the security decision).

**Why it is dangerous.** Returning "allow" when an unexpected state occurs (a null user, an internal error) turns any induced exception into an authentication or authorization bypass. Attackers deliberately trigger the failure path to skip the check entirely.

**Remediation.** Fail closed: return `false`, throw `AccessDeniedException`, or propagate a `SecurityException` instead of granting access.

**Vulnerable:**
```java
public boolean checkUserAuthorization(String userId, String requiredRole) {
    try {
        if (userId == null || userId.isBlank()) {
            throw new NullPointerException("User identity is null");
        }
        return userId.equals("admin") && requiredRole.equals("SUPERUSER");
    } catch (NullPointerException e) {
        return true;   // fail-open: grants access on error
    }
}
```

**Fixed (patch synthesized by SentinelPR):**
```java
public boolean checkUserAuthorization(String userId, String requiredRole) {
    try {
        if (userId == null || userId.isBlank()) {
            throw new NullPointerException("User identity is null");
        }
        return userId.equals("admin") && requiredRole.equals("SUPERUSER");
    } catch (NullPointerException e) {
        return false;  // SentinelPR: fail-closed security fix
    }
}
```

---

## SEC-002-UNCLOSED-STREAM — Unclosed I/O Stream

| | |
|---|---|
| **Severity** | HIGH |
| **CWE** | CWE-404 |
| **Analyzer** | `ReasoningFacade.evaluateUnclosedIoStreams` |

**Detection logic.** Flags instantiations of tracked stream types (`FileInputStream`, `FileOutputStream`, `InputStream`, `OutputStream`, `FileReader`, `FileWriter`, `BufferedReader`, `BufferedWriter`, `BufferedInputStream`, `BufferedOutputStream`, `DataInputStream`, `DataOutputStream`) that are not wrapped in a try-with-resources statement and have no deterministic `close()` on all exit paths.

**Why it is dangerous.** Each leak holds an OS file descriptor. Repeated leaks exhaust the process descriptor limit, causing `Too many open files` failures that can take down services and corrupt state.

**Remediation.** Use try-with-resources so the compiler generates deterministic closes even on exceptions.

**Vulnerable:**
```java
public String readConfigurationData(File configFile) throws IOException {
    FileInputStream fis = new FileInputStream(configFile);
    byte[] buffer = new byte[1024];
    int bytesRead = fis.read(buffer);
    return new String(buffer, 0, bytesRead);
}
```

**Fixed (patch synthesized by SentinelPR):**
```java
public String readConfigurationData(File configFile) throws IOException {
    try (FileInputStream fis = new FileInputStream(configFile)) {
        byte[] buffer = new byte[1024];
        int bytesRead = fis.read(buffer);
        return new String(buffer, 0, bytesRead);
    }
}
```

---

## SEC-003-VOLATILE-COMPOUND — Non-Atomic Volatile Compound Operation

| | |
|---|---|
| **Severity** | HIGH |
| **CWE** | CWE-362 |
| **Analyzer** | `ReasoningFacade.evaluateVolatileCompoundOps` |

**Detection logic.** Flags compound mutations (`++`, `--`, `+=`, and equivalent read-modify-write assignment expressions) applied to fields declared `volatile`.

**Why it is dangerous.** `volatile` guarantees visibility, not atomicity. `requestCount++` compiles to read-modify-write; two threads can interleave and lose updates, producing silently incorrect counters, quotas, or rate limits.

**Remediation.** Replace the primitive with `java.util.concurrent.atomic.AtomicInteger` (or `AtomicLong`) and use `incrementAndGet()`.

**Vulnerable:**
```java
public class VulnerableService {
    private volatile int requestCount;

    public void trackRequest() {
        requestCount++;
    }

    public int getRequestCount() {
        return requestCount;
    }
}
```

**Fixed (patch synthesized by SentinelPR):**
```java
import java.util.concurrent.atomic.AtomicInteger;

public class VulnerableService {
    private final AtomicInteger requestCount = new AtomicInteger(0);

    public void trackRequest() {
        requestCount.incrementAndGet();
    }

    public int getRequestCount() {
        return requestCount.get();
    }
}
```

---

## SEC-004-UNISOLATED-SUBPROCESS — Un-isolated Subprocess Call

| | |
|---|---|
| **Severity** | CRITICAL |
| **CWE** | CWE-78 |
| **Analyzer** | `ReasoningFacade.evaluateSubprocessCalls` |

**Detection logic.** Flags `Runtime.exec(...)` and `ProcessBuilder` invocations lacking strict argument isolation, boundary validation, or process-termination guarantees (e.g. shell string interpolation of untrusted input, missing timeouts/`destroy()`).

**Why it is dangerous.** Untrusted data reaching a shell or process argument enables OS command injection — full host compromise under the JVM's privileges.

**Remediation.** Prefer `ProcessBuilder` with explicit argument arrays (never a single shell string), validate inputs against allowlists, and always bound process lifetime.

**Vulnerable:**
```java
public void runReport(String fileName) throws IOException {
    Runtime.getRuntime().exec("cmd.exe /C report.bat " + fileName);
}
```

**Fixed (patch synthesized by SentinelPR):**
```java
public void runReport(String fileName) throws IOException {
    new ProcessBuilder("cmd.exe", "/C", "report.bat", fileName);
}
```

> The automated transformation rewrites `Runtime.getRuntime().exec(` → `new ProcessBuilder(`; manual hardening (allowlist validation, timeout) is still expected for full isolation.

---

## SEC-005-SQL-INJECTION — SQL Injection

| | |
|---|---|
| **Severity** | CRITICAL |
| **CWE** | CWE-89 |
| **Analyzers** | `ReasoningFacade.evaluateSqlInjection`, `DataflowTracker` (SQL sinks) |

**Detection logic.** Flags non-parameterized SQL reaching execution sinks — `executeQuery`, `executeUpdate`, `execute`, `prepareStatement`, `createQuery`, `createNativeQuery`, `query`, `update`, `queryForList`, `queryForObject`, `queryForMap`, `queryForRowSet`, `prepareCall` — built by string concatenation (`+`) or formatted strings. `DataflowTracker` additionally traces taint from method parameters and HTTP inputs (`getParameter`, `getHeader`, `getQueryString`, `getInputStream`, `getReader`, `getPart`, `getCookies`) through assignments into those sinks, honoring sanitizer-style calls (`sanitize`, `validate`, `encode`, `normalize`, `setString`, `setParameter`, …).

**Why it is dangerous.** Concatenated SQL lets attackers alter query semantics — extract arbitrary data, bypass authentication, or destroy tables.

**Remediation.** Use `PreparedStatement` placeholders (`setString`/`setInt`) or parameterized JPA queries; never concatenate user input into SQL text.

**Vulnerable:**
```java
public User findUser(String userId) throws SQLException {
    Statement stmt = connection.createStatement();
    ResultSet rs = stmt.executeQuery(
        "SELECT * FROM users WHERE id = '" + userId + "'");
    return map(rs);
}
```

**Fixed (patch synthesized by SentinelPR):**

The automated transformation replaces the concatenated value with a `?` placeholder
(the SQL text becomes `"... WHERE id = ?"`); the developer completes the
`PreparedStatement` parameterization:

```java
public User findUser(String userId) throws SQLException {
    // Synthesized: concatenation replaced with '?' placeholder
    // Developer completes: PreparedStatement ps = connection.prepareStatement(sql);
    //                      ps.setString(1, userId);
    Statement stmt = connection.createStatement();
    ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id = ?");
    return map(rs);
}
```

---

## SEC-006-PATH-TRAVERSAL — Path Traversal

| | |
|---|---|
| **Severity** | CRITICAL |
| **CWE** | CWE-22 |
| **Analyzers** | `ReasoningFacade.evaluatePathTraversal`, `DataflowTracker` (file sinks) |

**Detection logic.** Flags user-controlled values (string concatenation, `String`-typed parameters) flowing into `File`/`Path`/file-stream operations where the enclosing method lacks traversal guards: `.normalize()`, `getCanonicalPath()`, `getCanonicalFile()`, `toRealPath()`, or a `startsWith(...)` base-directory containment check.

**Why it is dangerous.** `../` sequences in a filename escape the intended directory, letting attackers read or overwrite arbitrary files (`/etc/passwd`, configuration, credentials).

**Remediation.** Normalize the path and verify it remains inside the approved base directory before any I/O; reject otherwise.

**Vulnerable:**
```java
public String readUserFile(String fileName) throws IOException {
    Path target = Path.of("/var/app/data/" + fileName);
    return Files.readString(target);
}
```

**Fixed (patch synthesized by SentinelPR):**
```java
public String readUserFile(String fileName) throws IOException {
    Path basePath = Path.of("/var/app/data");
    Path target = Path.of(basePath.toString(), fileName).normalize();
    if (!target.startsWith(basePath.normalize())) {
        throw new SecurityException("Path traversal attempt detected");
    }
    return Files.readString(target);
}
```

---

## SEC-007-INSECURE-DESERIALIZATION — Insecure Deserialization

| | |
|---|---|
| **Severity** | CRITICAL |
| **CWE** | CWE-502 |
| **Analyzer** | `ReasoningFacade.evaluateInsecureDeserialization` |

**Detection logic.** Flags `ObjectInputStream.readObject()` calls whose method and imports show no deserialization filtering (`setObjectInputFilter`, `ObjectInputFilter`, `LookAheadObjectInputStream`, `ValidatingObjectInputStream`).

**Why it is dangerous.** Deserializing untrusted streams can instantiate attacker-chosen gadgets, leading to remote code execution or denial of service before any application code runs.

**Remediation.** Apply a strict `ObjectInputFilter` allowlist, or use validating stream wrappers; prefer data formats without native deserialization (JSON) for untrusted input.

**Vulnerable:**
```java
public Object decode(byte[] bytes) throws IOException, ClassNotFoundException {
    try (ObjectInputStream ois =
             new ObjectInputStream(new ByteArrayInputStream(bytes))) {
        return ois.readObject();
    }
}
```

**Fixed (patch synthesized by SentinelPR):**

The automated transformation injects a strict default-deny `ObjectInputFilter`
immediately after the `ObjectInputStream` is created (filter
`"java.lang.*;java.util.*;!*"`):

```java
public Object decode(byte[] bytes) throws IOException, ClassNotFoundException {
    try (ObjectInputStream ois =
             new ObjectInputStream(new ByteArrayInputStream(bytes))) {
        ois.setObjectInputFilter(java.io.ObjectInputFilter.Config.createFilter("java.lang.*;java.util.*;!*"));
        return ois.readObject();
    }
}
```

> Adjust the synthesized filter pattern to an explicit allowlist of the application's
> expected serializable classes before merging.

---

## SEC-008-HARDCODED-SECRET — Hardcoded Secret or Token

| | |
|---|---|
| **Severity** | HIGH |
| **CWE** | CWE-798 |
| **Analyzer** | `SecretScanningEngine.scan` |

**Detection logic.** Four matchers over string literals and variable assignments:

1. AWS access key IDs: `\bAKIA[0-9A-Z]{16}\b`
2. PEM private key headers: `-----BEGIN (RSA|EC|DSA|OPENSSH)? PRIVATE KEY-----`
3. Generic credential assignment: `api[_-]?key`, `access[_-]?token`, `auth[_-]?token`, `client[_-]?secret` / `bearer` followed by ≥16-char values
4. Password-shaped variable names (`password`, `passwd`, `pwd`, `db_pass`, `secret_key`, `api_key`, `client_secret`) holding non-placeholder literals

High-entropy tokens (≥16 chars) are additionally scored with **Shannon entropy** (threshold `3.2`) and charset variety (≥2 character classes). Common placeholders (`password123`, `changeme`, `dummy`, `test`, …), repetitive strings (≤2 distinct chars), and whitelisted annotation contexts (`@Value`, `@Column`, …) are excluded. Reported secrets are **redacted** to first-4/last-4 characters in findings.

**Why it is dangerous.** Committed credentials are permanent repository history; they enable account takeover, cloud account compromise, and lateral movement long after rotation of the visible copy.

**Remediation.** Externalize to environment variables (`System.getenv("...")`) or inject via Spring `@Value("${secret.name}")` backed by a secure secret manager; rotate the exposed credential.

**Vulnerable:**
```java
public class ReportJob {
    private static final String AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE";
}
```

**Fixed (patch synthesized by SentinelPR):**
```java
public class ReportJob {
    private static final String AWS_ACCESS_KEY_ID = System.getenv("AWS_ACCESS_KEY_ID");
}
```

---

## SEC-009-SPRING-SECURITY-CSRF-DISABLED — Spring Security CSRF Disabled

| | |
|---|---|
| **Severity** | HIGH |
| **CWE** | CWE-352 |
| **Analyzer** | `FrameworkContextAnalyzer.evaluateCsrfDisabled` |

**Detection logic.** Flags `SecurityFilterChain` / `WebSecurityConfigurer` beans (or methods taking `HttpSecurity`) whose body disables CSRF — `.csrf(...).disable()` or `AbstractHttpConfigurer::disable` — **without** configuring `SessionCreationPolicy.STATELESS`.

**Why it is dangerous.** Disabling CSRF on stateful (cookie/session) applications lets attacker pages forge state-changing requests with the victim's ambient credentials.

**Remediation.** Keep CSRF protection enabled for stateful apps; disable it only together with `SessionCreationPolicy.STATELESS` (pure token-based APIs).

**Vulnerable:**
```java
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.csrf(csrf -> csrf.disable());
    return http.build();
}
```

**Fixed:**
```java
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .csrf(AbstractHttpConfigurer::disable);   // safe: stateless API
    return http.build();
}
```

> **Automated patch limitation:** the synthesized transformation currently replaces the
> flagged snippet with a `// CSRF protection preserved` marker rather than performing the
> stateless rewrite — completing the safe configuration (stateless policy or re-enabled CSRF)
> is a developer action.

---

## SEC-010-SPRING-PERMISSIVE-CORS — Spring Permissive CORS Policy

| | |
|---|---|
| **Severity** | MEDIUM |
| **CWE** | CWE-942 |
| **Analyzer** | `FrameworkContextAnalyzer.evaluatePermissiveCors` |

**Detection logic.** Flags wildcard origins (`"*"`) passed to `addAllowedOrigin`, `allowedOrigins`, `addAllowedOriginPattern`, or `allowedOriginPatterns`, and `@CrossOrigin` annotations that default to or explicitly set `*` (bare `@CrossOrigin`, `@CrossOrigin("*")`, `origins = "*"`, `originPatterns = "*"`).

**Why it is dangerous.** Any origin can read authenticated cross-origin responses, exposing APIs and user data to malicious websites.

**Remediation.** Restrict allowed origins to explicit trusted domains.

**Vulnerable:**
```java
@Bean
public WebMvcConfigurer corsConfigurer() {
    return new WebMvcConfigurer() {
        @Override
        public void addCorsMappings(CorsRegistry registry) {
            registry.addMapping("/api/**").allowedOrigins("*");
        }
    };
}
```

**Fixed (patch synthesized by SentinelPR):**
```java
@Bean
public WebMvcConfigurer corsConfigurer() {
    return new WebMvcConfigurer() {
        @Override
        public void addCorsMappings(CorsRegistry registry) {
            registry.addMapping("/api/**").allowedOrigins("https://trusted.domain.com");
        }
    };
}
```

> The automated patch substitutes the literal `https://trusted.domain.com`; replace it with your real production origin.

---

## ARCH-001-CYCLIC-DEPENDENCY — Architectural Cyclic Dependency

| | |
|---|---|
| **Severity** | MEDIUM |
| **CWE** | CWE-1047 |
| **Analyzer** | `ArchitectureReviewEngine.evaluateCyclicDependencies` |

**Detection logic.** Builds a class-level reference graph per file from imports, field types, and method parameter/return types (generics stripped); reports bidirectional references between two classes across the analyzed source set.

**Why it is dangerous.** Cycles prevent independent modularization and testing, cause initialization-order hazards, and accelerate architectural decay.

**Remediation.** Break the cycle with Dependency Inversion (introduce an interface) or extract the shared domain model into a separate module.

**Vulnerable:**
```java
// OrderService.java
import com.acme.billing.InvoiceService;         // A → B

// InvoiceService.java
import com.acme.order.OrderService;             // B → A (cycle)
```

**Fixed:**
```java
// Introduce an interface owned by the consumer side
public interface InvoiceSender { void send(Invoice invoice); }

// OrderService depends on the abstraction, not on InvoiceService
public class OrderService {
    private final InvoiceSender invoiceSender;
    public OrderService(InvoiceSender invoiceSender) { this.invoiceSender = invoiceSender; }
}
```

---

## ARCH-002-LEAKY-ABSTRACTION — Leaky Entity Abstraction in REST Controller

| | |
|---|---|
| **Severity** | HIGH |
| **CWE** | CWE-497 |
| **Analyzer** | `ArchitectureReviewEngine.evaluateLeakyAbstractions` |

**Detection logic.** In `@RestController`/`@Controller` classes, flags endpoint methods (`@*Mapping`) whose return type or parameters are database entities — type names ending in `Entity` or types from files importing `javax.persistence.Entity` / `jakarta.persistence.Entity` (unwrapped from `List<>`, `ResponseEntity<>`, `Optional<>`, etc.).

**Why it is dangerous.** Exposing JPA entities over HTTP leaks internal schema (columns, audit fields, relations) and enables over-posting / mass-assignment attacks on fields such as `role` or `isAdmin`.

**Remediation.** Encapsulate entities behind DTOs at the controller boundary (e.g. `UserDto` instead of `UserEntity`). SentinelPR's `MultiFileFixPlanner` can coordinate the Service + Controller refactor as one verified multi-file plan.

**Vulnerable:**
```java
@RestController
public class UserController {
    @GetMapping("/users/{id}")
    public UserEntity getUser(@PathVariable String id) {
        return userService.getUser(id);   // entity leaks to HTTP
    }
}
```

**Fixed:**
```java
public record UserDto(String id, String displayName) {
    public static UserDto from(UserEntity e) {
        return new UserDto(e.getId(), e.getDisplayName());
    }
}

@RestController
public class UserController {
    @GetMapping("/users/{id}")
    public UserDto getUser(@PathVariable String id) {
        return UserDto.from(userService.getUser(id));
    }
}
```

---

## ARCH-003-NON-DETERMINISTIC-CALL — Non-Deterministic Time or Random Invocation

| | |
|---|---|
| **Severity** | MEDIUM |
| **CWE** | CWE-676 |
| **Analyzer** | `ArchitectureReviewEngine.evaluateNonDeterministicCalls` |

**Detection logic.** Flags direct invocations of `System.currentTimeMillis()` and instantiations/uses of `java.util.Random` inside business service code, where determinism is required for testing and auditability.

**Why it is dangerous.** Behavior depending on wall-clock or unseeded randomness cannot be frozen in tests, producing flaky CI pipelines and untestable edge cases (timezone shifts, boundary times) and weaker auditability.

**Remediation.** Inject `java.time.Clock` (substitutable in tests) and use `SecureRandom` instances supplied as dependencies.

**Vulnerable:**
```java
public String generateSessionToken() {
    long now = System.currentTimeMillis();
    return "S" + now + new Random().nextInt(1000);
}
```

**Fixed:**
```java
public class TokenService {
    private final Clock clock;
    private final SecureRandom secureRandom;

    public TokenService(Clock clock, SecureRandom secureRandom) {
        this.clock = clock;
        this.secureRandom = secureRandom;
    }

    public String generateSessionToken() {
        return "S" + clock.millis() + secureRandom.nextInt(1000);
    }
}
```

---

## Confidence & Prioritization

Every finding is post-processed by `ConfidenceCalibrator` (threshold `0.70`):

| Factor | Weight |
|---|---|
| Taint-path continuity (source → sink) | 0.35 |
| AST precision / rule fidelity | 0.30 |
| Absence of defensive sanitizers | 0.20 |
| Public API exposure / reachability | 0.15 |

Findings below the threshold are recorded as suppressed with type `LOW_CONFIDENCE_HEURISTIC` instead of blocking the PR. Each finding also carries a `CausalChain` (trigger, root cause, propagation hops, exploit vector, business impact, `BlastRadius` ∈ `LOCAL_METHOD | SERVICE_COMPONENT | TENANT_DATA | SYSTEM_WIDE`) and an `ExploitabilityIndex` rank (1–5).
