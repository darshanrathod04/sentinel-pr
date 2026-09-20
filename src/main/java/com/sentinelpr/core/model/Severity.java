package com.sentinelpr.core.model;

/**
 * Vulnerability severity classifications according to CVSS standard mapping.
 */
public enum Severity {
    CRITICAL("Critical risk requiring immediate remediation prior to production merge"),
    HIGH("High risk that can lead to resource leaks, race conditions, or access bypass"),
    MEDIUM("Medium architectural or security concern"),
    LOW("Low severity or code smell"),
    INFO("Informational finding");

    private final String description;

    Severity(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }
}
