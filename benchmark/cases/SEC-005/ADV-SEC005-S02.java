package com.sentinelpr.benchmark.cases.sec005;

public class AdvSec005UnrelatedConcatSafe {

    public String formatAuditLog(String action, String principal, long durationMs) {
        StringBuilder header = new StringBuilder("AUDIT_EVENT: ");
        String logEntry = header.toString() + "[" + action + "] performed by " + principal + " in " + durationMs + "ms";
        return logEntry;
    }
}
