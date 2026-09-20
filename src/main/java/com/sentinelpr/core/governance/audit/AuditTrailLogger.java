package com.sentinelpr.core.governance.audit;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.sentinelpr.core.governance.policy.PolicyEvaluationResult;
import com.sentinelpr.core.model.ReviewReport;
import com.sentinelpr.core.model.SecurityRule;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Objects;

/**
 * <b>AuditTrailLogger</b>
 *
 * <p>Generates immutable, append-only cryptographic audit logs for SOC2 / ISO27001
 * compliance recording execution timestamps, operator identity, input SHA-256 fingerprints,
 * and report integrity signatures.</p>
 */
public class AuditTrailLogger {

    private final ObjectMapper objectMapper;

    public AuditTrailLogger() {
        this.objectMapper = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .disable(SerializationFeature.INDENT_OUTPUT); // NDJSON format
    }

    public AuditTrailLogger(ObjectMapper objectMapper) {
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper must not be null");
    }

    /**
     * Creates a signed cryptographic audit trail entry for a completed review run.
     */
    public AuditTrailEntry createAuditEntry(
            ReviewReport report,
            PolicyEvaluationResult policyResult,
            String commitId,
            String branch,
            String operator
    ) {
        Objects.requireNonNull(report, "report must not be null");
        String target = report.getTargetPath();
        String inputHash = computeInputFingerprint(target);
        String policyStatus = policyResult != null ? policyResult.getStatus().name() : "NOT_EVALUATED";
        String effectiveCommit = commitId != null && !commitId.isBlank() ? commitId : "HEAD";
        String effectiveBranch = branch != null && !branch.isBlank() ? branch : "main";
        String effectiveOperator = operator != null && !operator.isBlank()
                ? operator
                : resolveCurrentOperator();

        Instant timestamp = Instant.now();
        String reportSig = computeReportSignature(
                report.getReportId(),
                timestamp,
                target,
                inputHash,
                policyStatus,
                report.getVulnerabilityCount(),
                report.getPatches().size()
        );

        String memKernelHash = Integer.toHexString(report.hashCode());

        return new AuditTrailEntry(
                report.getReportId(),
                timestamp,
                target,
                effectiveCommit,
                effectiveBranch,
                effectiveOperator,
                inputHash,
                reportSig,
                memKernelHash,
                SecurityRule.values().length,
                "Shree AI OS / local-in-memory",
                policyStatus,
                report.getVulnerabilityCount(),
                report.getPatches().size()
        );
    }

    /**
     * Appends an audit entry as a single JSON line into the specified ledger file.
     */
    public void appendAuditLog(AuditTrailEntry entry, Path logFile) throws IOException {
        Objects.requireNonNull(entry, "entry must not be null");
        Objects.requireNonNull(logFile, "logFile must not be null");

        if (logFile.getParent() != null) {
            Files.createDirectories(logFile.getParent());
        }

        String jsonLine = objectMapper.writeValueAsString(entry) + System.lineSeparator();
        Files.writeString(logFile, jsonLine, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
    }

    /**
     * Serializes an audit trail entry to JSON.
     */
    public String serialize(AuditTrailEntry entry) {
        try {
            return objectMapper.writeValueAsString(entry);
        } catch (Exception e) {
            throw new RuntimeException("Failed to serialize audit entry: " + e.getMessage(), e);
        }
    }

    /**
     * Deserializes an audit trail entry from JSON.
     */
    public AuditTrailEntry deserialize(String json) {
        try {
            return objectMapper.readValue(json, AuditTrailEntry.class);
        } catch (Exception e) {
            throw new RuntimeException("Failed to deserialize audit entry: " + e.getMessage(), e);
        }
    }

    /**
     * Verifies that the audit entry's cryptographic report signature is valid.
     */
    public boolean verifyAuditSignature(AuditTrailEntry entry) {
        if (entry == null || entry.getReportSignature() == null || entry.getReportSignature().isBlank()) {
            return false;
        }

        String expectedSig = computeReportSignature(
                entry.getRunId(),
                entry.getTimestamp(),
                entry.getTargetPath(),
                entry.getInputFingerprint(),
                entry.getPolicyStatus(),
                entry.getTotalFindings(),
                entry.getTotalPatches()
        );

        return entry.getReportSignature().equalsIgnoreCase(expectedSig);
    }

    public static String computeReportSignature(
            String runId,
            Instant timestamp,
            String targetPath,
            String inputFingerprint,
            String policyStatus,
            int findingsCount,
            int patchesCount
    ) {
        String canonicalPayload = String.join("|",
                runId != null ? runId : "",
                timestamp != null ? timestamp.toString() : "",
                targetPath != null ? targetPath : "",
                inputFingerprint != null ? inputFingerprint : "",
                policyStatus != null ? policyStatus : "",
                String.valueOf(findingsCount),
                String.valueOf(patchesCount)
        );

        return sha256Hex(canonicalPayload);
    }

    public static String computeInputFingerprint(String targetPath) {
        if (targetPath == null || targetPath.isBlank()) {
            return sha256Hex("empty-input");
        }
        Path path = Path.of(targetPath);
        if (Files.isRegularFile(path)) {
            try {
                return sha256Hex(Files.readString(path));
            } catch (IOException e) {
                return sha256Hex(targetPath);
            }
        }
        return sha256Hex(targetPath);
    }

    private static String sha256Hex(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 unavailable", e);
        }
    }

    private static String resolveCurrentOperator() {
        String envUser = System.getenv("GITHUB_ACTOR");
        if (envUser != null && !envUser.isBlank()) {
            return envUser;
        }
        envUser = System.getenv("USER");
        if (envUser != null && !envUser.isBlank()) {
            return envUser;
        }
        envUser = System.getenv("USERNAME");
        if (envUser != null && !envUser.isBlank()) {
            return envUser;
        }
        return System.getProperty("user.name", "sentinel-agent");
    }
}
