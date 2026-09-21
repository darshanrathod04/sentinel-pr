package com.sentinelpr.client;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.sentinelpr.core.governance.policy.PolicyEvaluationResult;
import com.sentinelpr.core.model.ReviewReport;
import com.sentinelpr.core.model.SecurityFinding;
import com.sentinelpr.core.model.Severity;
import com.shreeai.os.platform.sdk.MemorySDK;
import com.shreeai.os.platform.sdk.SDKResponse;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * <b>MemoryFacade</b>
 *
 * <p>Adapter over Shree AI OS {@link MemorySDK} for persisting and inspecting past SentinelPR
 * review session metadata.</p>
 *
 * <p><b>Strict Governance Guardrail:</b> Stores ONLY audit metadata (runId, fingerprint,
 * findings breakdown, severity, and timestamp). NEVER persists raw source code, patch bodies,
 * or file contents into long-term memory.</p>
 */
public class MemoryFacade {

    private final MemorySDK memorySdk;
    private final ObjectMapper objectMapper;
    private final Map<String, AuditSessionMetadata> fastSessionCache = new java.util.concurrent.ConcurrentHashMap<>();
    private final List<String> memoryIndex = new java.util.concurrent.CopyOnWriteArrayList<>();

    private static final String SESSION_PREFIX = "SESSION:";
    private static final String INDEX_KEY = "SESSION_INDEX";

    public MemoryFacade(MemorySDK memorySdk) {
        this.memorySdk = Objects.requireNonNull(memorySdk, "memorySdk must not be null");
        this.objectMapper = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .setSerializationInclusion(JsonInclude.Include.NON_NULL);
    }

    /**
     * Records audit review session metadata into the Memory Kernel.
     */
    public AuditSessionMetadata recordSession(ReviewReport report, PolicyEvaluationResult policyResult, long durationMs) {
        Objects.requireNonNull(report, "report must not be null");

        String runId = report.getReportId() != null ? report.getReportId() : "REV-" + System.currentTimeMillis();
        String targetPath = report.getTargetPath() != null ? report.getTargetPath() : "unknown";
        Instant timestamp = report.getTimestamp() != null ? report.getTimestamp() : Instant.now();
        String status = report.getStatus() != null ? report.getStatus() : "SUCCESS";
        String policyStatus = policyResult != null ? policyResult.getStatus().name() : "N/A";

        // Aggregate severity counts
        Map<String, Integer> severityCounts = new HashMap<>();
        severityCounts.put("CRITICAL", 0);
        severityCounts.put("HIGH", 0);
        severityCounts.put("MEDIUM", 0);
        severityCounts.put("LOW", 0);

        List<FindingSummary> summaries = new ArrayList<>();
        if (report.getFindings() != null) {
            for (SecurityFinding f : report.getFindings()) {
                String sev = f.getSeverity() != null ? f.getSeverity().name() : "MEDIUM";
                severityCounts.put(sev, severityCounts.getOrDefault(sev, 0) + 1);

                summaries.add(new FindingSummary(
                        f.getRule() != null ? f.getRule().getRuleId() : "SEC-000",
                        sev,
                        f.getTargetFile(),
                        f.getStartLine(),
                        f.getEndLine(),
                        f.getDescription()
                ));
            }
        }

        AuditSessionMetadata metadata = new AuditSessionMetadata(
                runId,
                targetPath,
                timestamp,
                status,
                policyStatus,
                report.getScannedFileCount(),
                report.getVulnerabilityCount(),
                report.getSuppressedCount(),
                severityCounts,
                summaries,
                durationMs
        );

        fastSessionCache.put(runId, metadata);
        if (!memoryIndex.contains(runId)) {
            memoryIndex.add(runId);
        }

        try {
            String json = objectMapper.writeValueAsString(metadata);
            memorySdk.store(SESSION_PREFIX + runId, json);

            // Update session index
            updateSessionIndex(runId);
        } catch (Exception e) {
            System.err.println("[SentinelPR:MemoryFacade] Failed to store audit session metadata: " + e.getMessage());
        }

        return metadata;
    }

    /**
     * Lists historical audit session metadata stored in Memory Kernel.
     */
    public List<AuditSessionMetadata> listHistory() {
        List<String> runIds = getSessionIndex();
        List<AuditSessionMetadata> history = new ArrayList<>();

        for (String runId : runIds) {
            getSession(runId).ifPresent(history::add);
        }

        return history;
    }

    /**
     * Retrieves specific session metadata by run ID.
     */
    public Optional<AuditSessionMetadata> getSession(String runId) {
        if (runId == null || runId.isBlank()) {
            return Optional.empty();
        }

        AuditSessionMetadata cached = fastSessionCache.get(runId);
        if (cached != null) {
            return Optional.of(cached);
        }

        try {
            SDKResponse resp = memorySdk.recall(SESSION_PREFIX + runId);
            if (resp != null && resp.answer() != null && !resp.answer().isBlank() && !resp.answer().contains("not found")) {
                AuditSessionMetadata meta = objectMapper.readValue(resp.answer(), AuditSessionMetadata.class);
                if (meta != null) {
                    fastSessionCache.put(runId, meta);
                    return Optional.of(meta);
                }
            }
        } catch (Exception e) {
            // ignore retrieval failure
        }
        return Optional.empty();
    }

    /**
     * Formats past review sessions as a CLI summary table.
     */
    public String formatHistoryTable() {
        List<AuditSessionMetadata> sessions = listHistory();
        StringBuilder sb = new StringBuilder();
        sb.append("========================================================================================================================\n");
        sb.append("                                           SentinelPR Review Session History\n");
        sb.append("========================================================================================================================\n");
        sb.append(String.format(" %-15s | %-20s | %-32s | %-16s | %-10s | %-8s%n",
                "RUN ID", "TIMESTAMP", "TARGET", "VIOLATIONS", "POLICY", "STATUS"));
        sb.append("----------------+----------------------+----------------------------------+------------------+------------+----------\n");

        if (sessions.isEmpty()) {
            sb.append(" [No prior review sessions recorded in Memory Kernel]\n");
        } else {
            for (AuditSessionMetadata s : sessions) {
                String targetDisplay = s.getTargetPath();
                if (targetDisplay.length() > 32) {
                    targetDisplay = "..." + targetDisplay.substring(targetDisplay.length() - 29);
                }
                String violStr = String.format("%d (Crit: %d)",
                        s.getVulnerabilityCount(),
                        s.getSeverityCounts().getOrDefault("CRITICAL", 0));
                sb.append(String.format(" %-15s | %-20s | %-32s | %-16s | %-10s | %-8s%n",
                        s.getRunId(),
                        s.getTimestamp() != null ? s.getTimestamp().toString().substring(0, Math.min(19, s.getTimestamp().toString().length())) : "N/A",
                        targetDisplay,
                        violStr,
                        s.getPolicyStatus(),
                        s.getStatus()));
            }
        }
        sb.append("========================================================================================================================\n");
        return sb.toString();
    }

    /**
     * Formats detailed session inspection for a specific run ID.
     */
    public String formatSessionDetail(String runId) {
        Optional<AuditSessionMetadata> opt = getSession(runId);
        if (opt.isEmpty()) {
            return "[SentinelPR:Memory] No session found matching run ID: " + runId;
        }

        AuditSessionMetadata s = opt.get();
        StringBuilder sb = new StringBuilder();
        sb.append("================================================================================\n");
        sb.append(" SentinelPR Session Inspection: ").append(s.getRunId()).append("\n");
        sb.append("================================================================================\n");
        sb.append(" Run ID:          ").append(s.getRunId()).append("\n");
        sb.append(" Timestamp:       ").append(s.getTimestamp()).append("\n");
        sb.append(" Target Path:     ").append(s.getTargetPath()).append("\n");
        sb.append(" Status:          ").append(s.getStatus()).append("\n");
        sb.append(" Policy Verdict:  ").append(s.getPolicyStatus()).append("\n");
        sb.append(" Files Scanned:   ").append(s.getTotalFilesScanned()).append("\n");
        sb.append(" Vulnerabilities: ").append(s.getVulnerabilityCount())
                .append(String.format(" (Critical: %d, High: %d, Medium: %d, Low: %d)%n",
                        s.getSeverityCounts().getOrDefault("CRITICAL", 0),
                        s.getSeverityCounts().getOrDefault("HIGH", 0),
                        s.getSeverityCounts().getOrDefault("MEDIUM", 0),
                        s.getSeverityCounts().getOrDefault("LOW", 0)));
        sb.append(" Suppressed:      ").append(s.getSuppressedCount()).append("\n");
        sb.append(" Duration:        ").append(s.getTotalDurationMs()).append(" ms\n");

        sb.append("\n--- Findings Metadata (Source code redacted for governance) ---\n");
        if (s.getFindings().isEmpty()) {
            sb.append("  [Clean - No vulnerabilities detected]\n");
        } else {
            for (FindingSummary f : s.getFindings()) {
                sb.append(String.format("  [%-8s] %s (%s:%d-%d)%n",
                        f.getSeverity(), f.getRuleId(), f.getTargetFile(), f.getStartLine(), f.getEndLine()));
                sb.append("             ").append(f.getDescription()).append("\n");
            }
        }
        sb.append("================================================================================\n");
        return sb.toString();
    }

    private synchronized void updateSessionIndex(String newRunId) {
        if (!memoryIndex.contains(newRunId)) {
            memoryIndex.add(newRunId);
        }
        List<String> index = new ArrayList<>(memoryIndex);
        try {
            String json = objectMapper.writeValueAsString(index);
            memorySdk.store(INDEX_KEY, json);
        } catch (Exception ignored) {
        }
    }

    @SuppressWarnings("unchecked")
    private List<String> getSessionIndex() {
        if (!memoryIndex.isEmpty()) {
            return new ArrayList<>(memoryIndex);
        }
        try {
            SDKResponse resp = memorySdk.recall(INDEX_KEY);
            if (resp != null && resp.answer() != null && !resp.answer().isBlank() && !resp.answer().contains("not found")) {
                List<String> recalled = objectMapper.readValue(resp.answer(), List.class);
                if (recalled != null) {
                    for (String id : recalled) {
                        if (!memoryIndex.contains(id)) {
                            memoryIndex.add(id);
                        }
                    }
                    return new ArrayList<>(memoryIndex);
                }
            }
        } catch (Exception ignored) {
        }
        return new ArrayList<>(memoryIndex);
    }

    // ─── Metadata DTOs ─────────────────────────────────────────────────────────

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class AuditSessionMetadata {
        private String runId;
        private String targetPath;
        private Instant timestamp;
        private String status;
        private String policyStatus;
        private int totalFilesScanned;
        private int vulnerabilityCount;
        private int suppressedCount;
        private Map<String, Integer> severityCounts;
        private List<FindingSummary> findings;
        private long totalDurationMs;

        public AuditSessionMetadata() {
        }

        public AuditSessionMetadata(
                String runId,
                String targetPath,
                Instant timestamp,
                String status,
                String policyStatus,
                int totalFilesScanned,
                int vulnerabilityCount,
                int suppressedCount,
                Map<String, Integer> severityCounts,
                List<FindingSummary> findings,
                long totalDurationMs
        ) {
            this.runId = runId;
            this.targetPath = targetPath;
            this.timestamp = timestamp;
            this.status = status;
            this.policyStatus = policyStatus;
            this.totalFilesScanned = totalFilesScanned;
            this.vulnerabilityCount = vulnerabilityCount;
            this.suppressedCount = suppressedCount;
            this.severityCounts = severityCounts != null ? severityCounts : Collections.emptyMap();
            this.findings = findings != null ? findings : Collections.emptyList();
            this.totalDurationMs = totalDurationMs;
        }

        public String getRunId() { return runId; }
        public void setRunId(String runId) { this.runId = runId; }

        public String getTargetPath() { return targetPath; }
        public void setTargetPath(String targetPath) { this.targetPath = targetPath; }

        public Instant getTimestamp() { return timestamp; }
        public void setTimestamp(Instant timestamp) { this.timestamp = timestamp; }

        public String getStatus() { return status; }
        public void setStatus(String status) { this.status = status; }

        public String getPolicyStatus() { return policyStatus; }
        public void setPolicyStatus(String policyStatus) { this.policyStatus = policyStatus; }

        public int getTotalFilesScanned() { return totalFilesScanned; }
        public void setTotalFilesScanned(int totalFilesScanned) { this.totalFilesScanned = totalFilesScanned; }

        public int getVulnerabilityCount() { return vulnerabilityCount; }
        public void setVulnerabilityCount(int vulnerabilityCount) { this.vulnerabilityCount = vulnerabilityCount; }

        public int getSuppressedCount() { return suppressedCount; }
        public void setSuppressedCount(int suppressedCount) { this.suppressedCount = suppressedCount; }

        public Map<String, Integer> getSeverityCounts() { return severityCounts; }
        public void setSeverityCounts(Map<String, Integer> severityCounts) { this.severityCounts = severityCounts; }

        public List<FindingSummary> getFindings() { return findings; }
        public void setFindings(List<FindingSummary> findings) { this.findings = findings; }

        public long getTotalDurationMs() { return totalDurationMs; }
        public void setTotalDurationMs(long totalDurationMs) { this.totalDurationMs = totalDurationMs; }
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class FindingSummary {
        private String ruleId;
        private String severity;
        private String targetFile;
        private int startLine;
        private int endLine;
        private String description;

        public FindingSummary() {
        }

        public FindingSummary(String ruleId, String severity, String targetFile, int startLine, int endLine, String description) {
            this.ruleId = ruleId;
            this.severity = severity;
            this.targetFile = targetFile;
            this.startLine = startLine;
            this.endLine = endLine;
            this.description = description;
        }

        public String getRuleId() { return ruleId; }
        public void setRuleId(String ruleId) { this.ruleId = ruleId; }

        public String getSeverity() { return severity; }
        public void setSeverity(String severity) { this.severity = severity; }

        public String getTargetFile() { return targetFile; }
        public void setTargetFile(String targetFile) { this.targetFile = targetFile; }

        public int getStartLine() { return startLine; }
        public void setStartLine(int startLine) { this.startLine = startLine; }

        public int getEndLine() { return endLine; }
        public void setEndLine(int endLine) { this.endLine = endLine; }

        public String getDescription() { return description; }
        public void setDescription(String description) { this.description = description; }
    }
}
