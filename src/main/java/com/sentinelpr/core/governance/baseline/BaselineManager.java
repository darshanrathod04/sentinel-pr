package com.sentinelpr.core.governance.baseline;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.sentinelpr.core.model.ReviewReport;
import com.sentinelpr.core.model.SecurityFinding;
import com.sentinelpr.core.model.SuppressedFinding;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * <b>BaselineManager</b>
 *
 * <p>Manages technical debt snapshots for SentinelPR. Captures discovered findings
 * into baseline snapshots, exports to disk, and filters discovered findings to
 * suppress legacy accepted defects as {@code BASELINE_ACCEPTED}.</p>
 */
public class BaselineManager {

    public static final String SUPPRESSION_TYPE = "BASELINE_ACCEPTED";
    public static final String DEFAULT_BASELINE_FILENAME = ".sentinelbaseline.json";

    private final ObjectMapper objectMapper;

    public BaselineManager() {
        this.objectMapper = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .enable(SerializationFeature.INDENT_OUTPUT);
    }

    public BaselineManager(ObjectMapper objectMapper) {
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper must not be null");
    }

    /**
     * Captures all active findings from a {@link ReviewReport} into a {@link BaselineSnapshot}.
     */
    public BaselineSnapshot captureBaseline(ReviewReport report) {
        Objects.requireNonNull(report, "report must not be null");
        List<BaselineEntry> entries = new ArrayList<>();
        for (SecurityFinding finding : report.getFindings()) {
            entries.add(BaselineEntry.fromFinding(finding));
        }
        return new BaselineSnapshot(report.getTargetPath(), entries);
    }

    /**
     * Exports a review report's findings directly to a baseline file.
     */
    public void exportBaseline(ReviewReport report, Path outputPath) throws IOException {
        Objects.requireNonNull(report, "report must not be null");
        exportBaseline(captureBaseline(report), outputPath);
    }

    /**
     * Exports a baseline snapshot to disk.
     */
    public void exportBaseline(BaselineSnapshot snapshot, Path outputPath) throws IOException {
        Objects.requireNonNull(snapshot, "snapshot must not be null");
        Objects.requireNonNull(outputPath, "outputPath must not be null");

        if (outputPath.getParent() != null) {
            Files.createDirectories(outputPath.getParent());
        }
        String json = objectMapper.writeValueAsString(snapshot);
        Files.writeString(outputPath, json);
    }

    /**
     * Loads a baseline snapshot from disk.
     */
    public BaselineSnapshot loadBaseline(Path baselinePath) throws IOException {
        Objects.requireNonNull(baselinePath, "baselinePath must not be null");
        if (!Files.exists(baselinePath)) {
            throw new IllegalArgumentException("Baseline file does not exist: " + baselinePath);
        }
        return objectMapper.readValue(baselinePath.toFile(), BaselineSnapshot.class);
    }

    /**
     * Deserializes a baseline snapshot from JSON string.
     */
    public BaselineSnapshot loadBaselineFromString(String json) {
        try {
            return objectMapper.readValue(json, BaselineSnapshot.class);
        } catch (Exception e) {
            throw new RuntimeException("Failed to deserialize baseline snapshot: " + e.getMessage(), e);
        }
    }

    /**
     * Result of filtering findings against a baseline snapshot.
     */
    public static class BaselineFilterResult {
        private final List<SecurityFinding> activeFindings;
        private final List<SuppressedFinding> baselineAcceptedFindings;

        public BaselineFilterResult(List<SecurityFinding> activeFindings, List<SuppressedFinding> baselineAcceptedFindings) {
            this.activeFindings = Collections.unmodifiableList(new ArrayList<>(activeFindings));
            this.baselineAcceptedFindings = Collections.unmodifiableList(new ArrayList<>(baselineAcceptedFindings));
        }

        public List<SecurityFinding> getActiveFindings() {
            return activeFindings;
        }

        public List<SuppressedFinding> getBaselineAcceptedFindings() {
            return baselineAcceptedFindings;
        }

        public int getActiveCount() {
            return activeFindings.size();
        }

        public int getSuppressedCount() {
            return baselineAcceptedFindings.size();
        }
    }

    /**
     * Filters findings against a baseline snapshot:
     * <ul>
     *   <li>Findings matching baseline are categorized as suppressed {@code BASELINE_ACCEPTED}.</li>
     *   <li>New findings not in baseline remain active PR blockers.</li>
     * </ul>
     */
    public BaselineFilterResult filterWithBaseline(List<SecurityFinding> findings, BaselineSnapshot baseline) {
        if (baseline == null || baseline.getEntries().isEmpty() || findings == null || findings.isEmpty()) {
            return new BaselineFilterResult(findings != null ? findings : List.of(), List.of());
        }

        List<SecurityFinding> active = new ArrayList<>();
        List<SuppressedFinding> suppressed = new ArrayList<>();

        for (SecurityFinding finding : findings) {
            Optional<BaselineEntry> match = baseline.findMatchingEntry(finding);
            if (match.isPresent()) {
                BaselineEntry entry = match.get();
                String reason = String.format("Accepted technical debt present in baseline snapshot (fingerprint: %s)", entry.getFingerprint());
                suppressed.add(new SuppressedFinding(finding, reason, SUPPRESSION_TYPE));
            } else {
                active.add(finding);
            }
        }

        return new BaselineFilterResult(active, suppressed);
    }
}
