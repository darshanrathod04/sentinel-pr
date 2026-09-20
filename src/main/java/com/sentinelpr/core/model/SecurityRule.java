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
