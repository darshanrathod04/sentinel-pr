package com.sentinelpr.core.model;

/**
 * Enterprise security and architectural audit rules evaluated by SentinelPR.
 */
public enum SecurityRule {
    FAIL_OPEN_SECURITY(
            "SEC-001-FAIL-OPEN",
            "Fail-Open Security Block",
            Severity.CRITICAL,
            "CWE-393: Catch block catches an exception (e.g. NullPointerException/Exception) and grants access or returns true, creating an unauthorized bypass."
    ),
    UNCLOSED_IO_STREAM(
            "SEC-002-UNCLOSED-STREAM",
            "Unclosed I/O Stream",
            Severity.HIGH,
            "CWE-404: I/O stream or file descriptor is instantiated without try-with-resources or deterministic close, leading to file descriptor exhaustion."
    ),
    VOLATILE_COMPOUND_OP(
            "SEC-003-VOLATILE-COMPOUND",
            "Volatile Compound Operation",
            Severity.HIGH,
            "CWE-362: Compound mutation (e.g., ++, --, +=) on a volatile variable is non-atomic and introduces race conditions under concurrent execution."
    ),
    UNISOLATED_SUBPROCESS(
            "SEC-004-UNISOLATED-SUBPROCESS",
            "Un-isolated Subprocess Call",
            Severity.CRITICAL,
            "CWE-78: ProcessBuilder or Runtime.exec invoked without strict argument isolation, boundary validation, or process termination guarantees."
    ),
    SQL_INJECTION(
            "SEC-005-SQL-INJECTION",
            "SQL Injection",
            Severity.CRITICAL,
            "CWE-89: Un-parameterized raw string concatenation or formatted strings passed into SQL execution sinks."
    ),
    PATH_TRAVERSAL(
            "SEC-006-PATH-TRAVERSAL",
            "Path Traversal",
            Severity.CRITICAL,
            "CWE-22: User input concatenated directly into File/Path operations without normalization or containment validation."
    ),
    INSECURE_DESERIALIZATION(
            "SEC-007-INSECURE-DESERIALIZATION",
            "Insecure Deserialization",
            Severity.CRITICAL,
            "CWE-502: Unvalidated ObjectInputStream.readObject() calls without custom filtering or LookAheadObjectInputStream."
    ),
    HARDCODED_SECRET(
            "SEC-008-HARDCODED-SECRET",
            "Hardcoded Secret or Token",
            Severity.HIGH,
            "CWE-798: High-entropy secret, API key, AWS credential, private key, or password embedded in source code."
    ),
    SPRING_SECURITY_CSRF_DISABLED(
            "SEC-009-SPRING-SECURITY-CSRF-DISABLED",
            "Spring Security CSRF Disabled",
            Severity.HIGH,
            "CWE-352: SecurityFilterChain bean explicitly disables CSRF protection without configuring stateless session management."
    ),
    SPRING_PERMISSIVE_CORS(
            "SEC-010-SPRING-PERMISSIVE-CORS",
            "Spring Permissive CORS Policy",
            Severity.MEDIUM,
            "CWE-942: Permissive CORS policy with wildcard origin '*' allows unauthorized cross-origin requests."
    ),

    // Extended OWASP Top 10 Security Rules
    XXE_INJECTION(
            "SEC-011-XXE",
            "XML External Entity (XXE) Injection",
            Severity.CRITICAL,
            "CWE-611: XML parser instantiated without disabling external DTDs or external entity resolution, allowing unauthorized file disclosure or SSRF."
    ),
    SSRF(
            "SEC-012-SSRF",
            "Server-Side Request Forgery (SSRF)",
            Severity.CRITICAL,
            "CWE-918: Unvalidated user input or dynamic URL passed directly into HTTP client requests without host allowlisting or containment validation."
    ),
    JWT_NONE_ALGORITHM(
            "SEC-013-JWT-NONE-ALG",
            "JWT Insecure None Algorithm or Signature Bypass",
            Severity.CRITICAL,
            "CWE-347: JSON Web Token parsed or validated with 'none' algorithm allowed, or token decoded without cryptographic signature verification."
    ),
    LOG_INJECTION(
            "SEC-014-LOG-INJECTION",
            "Log Injection and Forging",
            Severity.HIGH,
            "CWE-117: Unsanitized user input written directly to logging sinks allowing log forging or CRLF log splitting."
    ),
    LDAP_INJECTION(
            "SEC-015-LDAP-INJECTION",
            "LDAP Injection",
            Severity.CRITICAL,
            "CWE-90: Unsanitized input concatenated into LDAP search filters or DirContext queries without proper encoding."
    ),
    XPATH_INJECTION(
            "SEC-016-XPATH-INJECTION",
            "XPath Injection",
            Severity.CRITICAL,
            "CWE-643: User input concatenated directly into XPath expression compilation or evaluation without parameterized variables."
    ),
    OPEN_REDIRECT(
            "SEC-017-OPEN-REDIRECT",
            "Open Redirect",
            Severity.HIGH,
            "CWE-601: Untrusted URL or user-supplied target passed directly to HTTP redirection without allowlist validation."
    ),
    WEAK_CRYPTO(
            "SEC-018-WEAK-CRYPTO",
            "Broken or Risky Cryptographic Algorithm",
            Severity.HIGH,
            "CWE-327: Use of broken or obsolete cryptographic algorithms (MD5, SHA-1, DES, RC4, or AES/ECB) for security-sensitive operations."
    ),
    INSECURE_RANDOM(
            "SEC-019-INSECURE-RANDOM",
            "Insecure Randomness in Security Context",
            Severity.HIGH,
            "CWE-338: Use of cryptographically weak PRNG (java.util.Random, Math.random) for generating security tokens, keys, salts, or passwords."
    ),
    XSS(
            "SEC-020-XSS",
            "Cross-Site Scripting (XSS)",
            Severity.HIGH,
            "CWE-79: Unsanitized user input written directly to HTTP response output streams or HTML body without HTML entity encoding."
    ),

    // Architectural Hygiene Rules (P4)
    ARCH_CYCLIC_DEPENDENCY(
            "ARCH-001-CYCLIC-DEPENDENCY",
            "Architectural Cyclic Dependency",
            Severity.MEDIUM,
            "CWE-1047: Circular dependencies between packages or classes violate modular layering and impair maintainability."
    ),
    ARCH_LEAKY_ABSTRACTION(
            "ARCH-002-LEAKY-ABSTRACTION",
            "Leaky Entity Abstraction in REST Controller",
            Severity.HIGH,
            "CWE-497: Database entity classes exposed directly in @RestController endpoints leak internal schema details without DTO encapsulation."
    ),
    ARCH_NON_DETERMINISTIC_CALL(
            "ARCH-003-NON-DETERMINISTIC-CALLS",
            "Non-Deterministic Time or Random Invocation",
            Severity.MEDIUM,
            "Direct invocations of System.currentTimeMillis() or Random in business services prevent deterministic testing; inject java.time.Clock or SecureRandom."
    );

    private final String ruleId;
    private final String title;
    private final Severity severity;
    private final String explanation;

    SecurityRule(String ruleId, String title, Severity severity, String explanation) {
        this.ruleId = ruleId;
        this.title = title;
        this.severity = severity;
        this.explanation = explanation;
    }

    public String getRuleId() {
        return ruleId;
    }

    public String getTitle() {
        return title;
    }

    public Severity getSeverity() {
        return severity;
    }

    public String getExplanation() {
        return explanation;
    }

    public boolean isArchitecturalRule() {
        return ruleId.startsWith("ARCH-");
    }

    public static SecurityRule[] getCoreSecurityRules() {
        return java.util.Arrays.stream(values())
                .filter(r -> !r.isArchitecturalRule())
                .toArray(SecurityRule[]::new);
    }

    public static int getCoreSecurityRulesCount() {
        return getCoreSecurityRules().length;
    }
}
