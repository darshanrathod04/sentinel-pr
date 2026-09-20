package com.sentinelpr.core.governance.baseline;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.sentinelpr.core.model.SecurityFinding;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * <b>BaselineSnapshot</b>
 *
 * <p>Snapshot containing all accepted technical debt and legacy findings for a repository.</p>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class BaselineSnapshot {

    public static final String CURRENT_VERSION = "1.0";

    private final String version;
    private final Instant createdAt;
    private final String targetPath;
    private final int totalEntries;
    private final List<BaselineEntry> entries;

    public BaselineSnapshot(String targetPath, List<BaselineEntry> entries) {
        this(CURRENT_VERSION, Instant.now(), targetPath, entries != null ? entries.size() : 0, entries);
    }

    @JsonCreator
    public BaselineSnapshot(
            @JsonProperty("version") String version,
            @JsonProperty("createdAt") Instant createdAt,
            @JsonProperty("targetPath") String targetPath,
            @JsonProperty("totalEntries") int totalEntries,
            @JsonProperty("entries") List<BaselineEntry> entries
    ) {
        this.version = version != null ? version : CURRENT_VERSION;
        this.createdAt = createdAt != null ? createdAt : Instant.now();
        this.targetPath = targetPath != null ? targetPath : "";
        this.entries = entries != null ? Collections.unmodifiableList(new ArrayList<>(entries)) : List.of();
        this.totalEntries = this.entries.size();
    }

    public Optional<BaselineEntry> findMatchingEntry(SecurityFinding finding) {
        if (finding == null || entries.isEmpty()) {
            return Optional.empty();
        }
        for (BaselineEntry entry : entries) {
            if (entry.matches(finding)) {
                return Optional.of(entry);
            }
        }
        return Optional.empty();
    }

    public boolean hasMatch(SecurityFinding finding) {
        return findMatchingEntry(finding).isPresent();
    }

    public String getVersion() {
        return version;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public String getTargetPath() {
        return targetPath;
    }

    public int getTotalEntries() {
        return totalEntries;
    }

    public List<BaselineEntry> getEntries() {
        return entries;
    }
}
