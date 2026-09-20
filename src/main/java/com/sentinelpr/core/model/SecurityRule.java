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
}
