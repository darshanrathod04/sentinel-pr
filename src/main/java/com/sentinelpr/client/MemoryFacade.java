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

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
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
 * <p><b>Source of Truth:</b> {@link MemorySDK} remains the primary cognitive storage source of truth.
 * A local workspace ledger ({@code .sentinelhistory.json}) provides durable cross-process survival
 * for CLI invocations with schema versioning. The JSON ledger never overwrites MemorySDK during hydration.</p>
 *
 * <p><b>Strict Governance Guardrail:</b> Stores ONLY audit metadata (runId, timestamp, targetPath,
 * policyStatus, status, severity counts, finding summaries, and durationMs).
 * NEVER persists raw source code, unified diffs, or patch bodies into memory or ledger.</p>
 */
public class MemoryFacade {

    public static final String AUDIT_PREFIX = "AUDIT:";
    public static final String AUDIT_INDEX_KEY = "AUDIT_INDEX";
    public static final String SESSION_PREFIX = "SESSION:";
    public static final String LEGACY_INDEX_KEY = "SESSION_INDEX";
    public static final String DEFAULT_HISTORY_FILE = ".sentinelhistory.json";
    public static final String CURRENT_SCHEMA_VERSION = "1.0.0";

    private final MemorySDK memorySdk;
    private final ObjectMapper objectMapper;
    private final Path workspaceHistoryPath;
    private final String workspaceId;
    private final Map<String, AuditSessionMetadata> fastSessionCache = new java.util.concurrent.ConcurrentHashMap<>();
    private final List<String> memoryIndex = new java.util.concurrent.CopyOnWriteArrayList<>();

    public MemoryFacade(MemorySDK memorySdk) {
        this(memorySdk, Path.of(DEFAULT_HISTORY_FILE));
    }

    public MemoryFacade(MemorySDK memorySdk, Path workspaceHistoryPath) {
        this.memorySdk = Objects.requireNonNull(memorySdk, "memorySdk must not be null");
        this.workspaceHistoryPath = workspaceHistoryPath != null ? workspaceHistoryPath : Path.of(DEFAULT_HISTORY_FILE);
        this.workspaceId = computeWorkspaceId();
        this.objectMapper = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .setSerializationInclusion(JsonInclude.Include.NON_NULL);
    }

    private static String computeWorkspaceId() {
        try {
            Path current = Path.of("").toAbsolutePath();
            String name = current.getFileName() != null ? current.getFileName().toString() : "workspace";
            return name + "-" + Integer.toHexString(current.toString().hashCode());
        } catch (Exception e) {
            return "sentinel-pr-workspace";
        }
    }

    /**
     * Records audit review session metadata into the Memory Kernel and durable workspace ledger.
     * MemorySDK remains the primary source of truth.
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

        // 1. Primary Source of Truth: Store into MemorySDK
        try {
            String json = objectMapper.writeValueAsString(metadata);
            memorySdk.store(AUDIT_PREFIX + runId, json);
            memorySdk.store(SESSION_PREFIX + runId, json);

            updateSessionIndexInMemorySdk(runId);
        } catch (Exception e) {
            System.err.println("[SentinelPR:MemoryFacade] Failed to store audit session metadata in MemorySDK: " + e.getMessage());
        }

        // 2. Durable Workspace Ledger: Persist versioned schema to workspace disk
        persistLedgerToDisk();

        return metadata;
    }

    /**
     * Reads all historical audit session metadata stored in Memory Kernel / Workspace Ledger,
     * returned in reverse chronological order (newest first).
     */
    public List<AuditSessionMetadata> readHistory() {
        List<String> runIds = getSessionIndex();
        List<AuditSessionMetadata> history = new ArrayList<>();

        for (String runId : runIds) {
            getSession(runId).ifPresent(history::add);
        }

        // If history is still empty, load from disk ledger cache
        if (history.isEmpty()) {
            loadLedgerFromDisk();
            for (String runId : memoryIndex) {
                AuditSessionMetadata s = fastSessionCache.get(runId);
                if (s != null && !history.contains(s)) {
                    history.add(s);
                }
            }
        }

        // Sort in reverse chronological order (newest first)
        history.sort((a, b) -> {
            if (a.getTimestamp() == null && b.getTimestamp() == null) return 0;
            if (a.getTimestamp() == null) return 1;
            if (b.getTimestamp() == null) return -1;
            return b.getTimestamp().compareTo(a.getTimestamp());
        });

        return history;
    }

    /**
     * Lists historical audit session metadata stored in Memory Kernel (alias for readHistory).
     */
    public List<AuditSessionMetadata> listHistory() {
        return readHistory();
    }

    /**
     * Retrieves specific session metadata by run ID.
     * MemorySDK remains the primary source of truth; falls back to workspace ledger cache without overwriting MemorySDK.
     */
    public Optional<AuditSessionMetadata> getSession(String runId) {
        if (runId == null || runId.isBlank()) {
            return Optional.empty();
        }

        // 1. In-memory fast cache
        AuditSessionMetadata cached = fastSessionCache.get(runId);
        if (cached != null) {
            return Optional.of(cached);
        }

        // 2. MemorySDK recall (Source of Truth)
        try {
            SDKResponse resp = memorySdk.recall(AUDIT_PREFIX + runId);
            if (resp == null || resp.answer() == null || resp.answer().isBlank() || resp.answer().contains("not found")) {
                resp = memorySdk.recall(SESSION_PREFIX + runId);
            }
            if (resp != null && resp.answer() != null && !resp.answer().isBlank() && !resp.answer().contains("not found")) {
                try {
                    AuditSessionMetadata meta = objectMapper.readValue(resp.answer(), AuditSessionMetadata.class);
                    if (meta != null) {
                        fastSessionCache.put(runId, meta);
                        return Optional.of(meta);
                    }
                } catch (Exception ignored) {
                    // Non-JSON answer from runtime LLM fallback
                }
            }
        } catch (Exception ignored) {
        }

        // 3. Fallback to durable workspace ledger cache (do NOT overwrite MemorySDK during hydration)
        loadLedgerFromDisk();
        cached = fastSessionCache.get(runId);
        return Optional.ofNullable(cached);
    }

    /**
     * Formats past review sessions as a CLI summary table in reverse chronological order.
     */
    public String formatHistoryTable() {
        List<AuditSessionMetadata> sessions = readHistory();
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
                String targetDisplay = s.getTargetPath() != null ? s.getTargetPath() : "unknown";
                if (targetDisplay.length() > 32) {
                    targetDisplay = "..." + targetDisplay.substring(targetDisplay.length() - 29);
                }
                String violStr = String.format("%d (Crit: %d)",
                        s.getVulnerabilityCount(),
                        s.getSeverityCounts() != null ? s.getSeverityCounts().getOrDefault("CRITICAL", 0) : 0);
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
                        s.getSeverityCounts() != null ? s.getSeverityCounts().getOrDefault("CRITICAL", 0) : 0,
                        s.getSeverityCounts() != null ? s.getSeverityCounts().getOrDefault("HIGH", 0) : 0,
                        s.getSeverityCounts() != null ? s.getSeverityCounts().getOrDefault("MEDIUM", 0) : 0,
                        s.getSeverityCounts() != null ? s.getSeverityCounts().getOrDefault("LOW", 0) : 0));
        sb.append(" Suppressed:      ").append(s.getSuppressedCount()).append("\n");
        sb.append(" Duration:        ").append(s.getTotalDurationMs()).append(" ms\n");

        sb.append("\n--- Findings Metadata (Source code redacted for governance) ---\n");
        if (s.getFindings() == null || s.getFindings().isEmpty()) {
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

    private synchronized void updateSessionIndexInMemorySdk(String newRunId) {
        if (!memoryIndex.contains(newRunId)) {
            memoryIndex.add(newRunId);
        }
        List<String> index = new ArrayList<>(memoryIndex);
        try {
            String json = objectMapper.writeValueAsString(index);
            memorySdk.store(AUDIT_INDEX_KEY, json);
            memorySdk.store(LEGACY_INDEX_KEY, json);
        } catch (Exception ignored) {
        }
    }

    @SuppressWarnings("unchecked")
    private List<String> getSessionIndex() {
        // Query MemorySDK first
        try {
            SDKResponse resp = memorySdk.recall(AUDIT_INDEX_KEY);
            if (resp == null || resp.answer() == null || resp.answer().isBlank() || resp.answer().contains("not found")) {
                resp = memorySdk.recall(LEGACY_INDEX_KEY);
            }
            if (resp != null && resp.answer() != null && !resp.answer().isBlank() && !resp.answer().contains("not found")) {
                try {
                    List<String> recalled = objectMapper.readValue(resp.answer(), List.class);
                    if (recalled != null && !recalled.isEmpty()) {
                        for (String id : recalled) {
                            if (!memoryIndex.contains(id)) {
                                memoryIndex.add(id);
                            }
                        }
                        return new ArrayList<>(memoryIndex);
                    }
                } catch (Exception ignored) {
                }
            }
        } catch (Exception ignored) {
        }

        if (!memoryIndex.isEmpty()) {
            return new ArrayList<>(memoryIndex);
        }

        // Fallback to disk ledger cache
        loadLedgerFromDisk();
        return new ArrayList<>(memoryIndex);
    }

    /**
     * Hydrates local in-memory cache from durable workspace ledger.
     * Guardrail: Never overwrites MemorySDK during hydration.
     */
    private synchronized void loadLedgerFromDisk() {
        if (workspaceHistoryPath == null || !Files.exists(workspaceHistoryPath)) {
            return;
        }
        try {
            String content = Files.readString(workspaceHistoryPath);
            if (content == null || content.isBlank()) {
                return;
            }
            WorkspaceHistoryLedger ledger = objectMapper.readValue(content, WorkspaceHistoryLedger.class);
            if (ledger != null && ledger.getSessions() != null) {
                for (AuditSessionMetadata s : ledger.getSessions()) {
                    if (s != null && s.getRunId() != null) {
                        fastSessionCache.putIfAbsent(s.getRunId(), s);
                        if (!memoryIndex.contains(s.getRunId())) {
                            memoryIndex.add(s.getRunId());
                        }
                    }
                }
            }
        } catch (Exception e) {
            // Note: workspace ledger read fallback
        }
    }

    /**
     * Persists current session metadata into versioned workspace ledger file.
     */
    private synchronized void persistLedgerToDisk() {
        if (workspaceHistoryPath == null) {
            return;
        }
        try {
            // Gather all cached sessions
            List<AuditSessionMetadata> sessions = new ArrayList<>();
            for (String id : memoryIndex) {
                AuditSessionMetadata s = fastSessionCache.get(id);
                if (s != null && !sessions.contains(s)) {
                    sessions.add(s);
                }
            }

            WorkspaceHistoryLedger ledger = new WorkspaceHistoryLedger(
                    CURRENT_SCHEMA_VERSION,
                    workspaceId,
                    sessions
            );

            String json = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(ledger);
            Path parent = workspaceHistoryPath.getParent();
            if (parent != null && !Files.exists(parent)) {
                Files.createDirectories(parent);
            }
            Files.writeString(workspaceHistoryPath, json);
        } catch (Exception e) {
            System.err.println("[SentinelPR:MemoryFacade] Note: Could not persist workspace history ledger: " + e.getMessage());
        }
    }

    public synchronized void clearCache() {
        fastSessionCache.clear();
        memoryIndex.clear();
    }

    public Path getWorkspaceHistoryPath() {
        return workspaceHistoryPath;
    }

    public String getWorkspaceId() {
        return workspaceId;
    }

    // ─── Versioned Ledger Schema & Metadata DTOs ───────────────────────────────

    /**
     * Versioned schema container for workspace audit history ledger (.sentinelhistory.json).
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class WorkspaceHistoryLedger {
        private String schemaVersion = CURRENT_SCHEMA_VERSION;
        private String workspaceId;
        private List<AuditSessionMetadata> sessions = new ArrayList<>();

        public WorkspaceHistoryLedger() {
        }

        public WorkspaceHistoryLedger(String schemaVersion, String workspaceId, List<AuditSessionMetadata> sessions) {
            this.schemaVersion = schemaVersion;
            this.workspaceId = workspaceId;
            this.sessions = sessions != null ? sessions : new ArrayList<>();
        }

        public String getSchemaVersion() { return schemaVersion; }
        public void setSchemaVersion(String schemaVersion) { this.schemaVersion = schemaVersion; }

        public String getWorkspaceId() { return workspaceId; }
        public void setWorkspaceId(String workspaceId) { this.workspaceId = workspaceId; }

        public List<AuditSessionMetadata> getSessions() { return sessions; }
        public void setSessions(List<AuditSessionMetadata> sessions) { this.sessions = sessions; }
    }

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
