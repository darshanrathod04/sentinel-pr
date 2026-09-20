package com.sentinelpr.fixture;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

/**
 * <b>TaintedVulnerableService</b>
 *
 * <p>Test fixture demonstrating:</p>
 * <ol>
 *   <li>Tainted source-to-sink dataflow (user input -> Runtime.exec)</li>
 *   <li>Sanitized dataflow path (user input -> validator -> sink)</li>
 *   <li>Intentional false-positive suppressed via {@code @SuppressWarnings("sentinel:SEC-001")}</li>
 *   <li>Intentional false-positive suppressed via {@code // sentinel-ignore SEC-002}</li>
 *   <li>Multiple co-located defects requiring atomic patch composition (SEC-001, SEC-002, SEC-003)</li>
 * </ol>
 */
public class TaintedVulnerableService {

    // Co-located defect 1: Volatile compound mutation
    private volatile int activeOperations;

    /**
     * Taint Scenario 1: Untrusted parameter flows to command execution sink without sanitization.
     */
    public void executeUserCommand(String untrustedInput) throws IOException {
        String preparedCommand = "sh -c " + untrustedInput;
        Runtime.getRuntime().exec(preparedCommand);
    }

    /**
     * Taint Scenario 2: Untrusted parameter passes through a sanitizer before execution.
     */
    public void executeSanitizedCommand(String untrustedInput) throws IOException {
        if (!validateCommand(untrustedInput)) {
            return;
        }
        Runtime.getRuntime().exec(untrustedInput);
    }

    private boolean validateCommand(String input) {
        return input != null && input.matches("^[a-zA-Z0-9_-]+$");
    }

    /**
     * Suppression Scenario 1: Fail-open catch block suppressed by @SuppressWarnings("sentinel:SEC-001").
     */
    @SuppressWarnings("sentinel:SEC-001")
    public boolean checkPermissionWithAnnotation(String token) {
        try {
            if (token == null) {
                throw new NullPointerException("Token null");
            }
            return token.equals("ROOT");
        } catch (NullPointerException e) {
            // Intentional false positive suppressed by annotation
            return true;
        }
    }

    /**
     * Suppression Scenario 2: Unclosed stream suppressed by inline comment.
     */
    public String readWithCommentSuppression(File file) throws IOException {
        // sentinel-ignore SEC-002 Stream resource closed by caller lifecycle
        FileInputStream fis = new FileInputStream(file);
        byte[] buffer = new byte[64];
        int read = fis.read(buffer);
        return new String(buffer, 0, read);
    }

    /**
     * Co-located defect 2: Unsuppressed unclosed I/O stream requiring patch.
     */
    public String readTelemetryLog(File logFile) throws IOException {
        FileInputStream fis = new FileInputStream(logFile);
        byte[] buffer = new byte[128];
        int read = fis.read(buffer);
        return new String(buffer, 0, read);
    }

    /**
     * Co-located defect 3: Unsuppressed fail-open catch block requiring patch.
     */
    public boolean checkSuperAdmin(String user) {
        try {
            if (user == null || user.isBlank()) {
                throw new NullPointerException("User null");
            }
            return user.equals("superadmin");
        } catch (NullPointerException e) {
            return true;
        }
    }

    /**
     * Co-located defect 1 mutation: Non-atomic compound operation on volatile field.
     */
    public void trackOperation() {
        activeOperations++;
    }

    public int getActiveOperations() {
        return activeOperations;
    }
}
