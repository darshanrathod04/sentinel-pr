package com.sentinelpr.core.model;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.Objects;

/**
 * <b>SuppressedFinding</b>
 *
 * <p>Represents a security finding that was suppressed by an annotation,
 * an inline comment, or a repository {@code .sentinelignore} configuration.</p>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class SuppressedFinding {

    private final SecurityFinding finding;
    private final String matchedReason;
    private final String suppressionType; // ANNOTATION, INLINE_COMMENT, IGNORE_FILE

    public SuppressedFinding(SecurityFinding finding, String matchedReason, String suppressionType) {
        this.finding = Objects.requireNonNull(finding, "finding must not be null");
        this.matchedReason = matchedReason != null ? matchedReason : "Suppressed by policy";
        this.suppressionType = suppressionType != null ? suppressionType : "ANNOTATION";
    }

    public SecurityFinding getFinding() {
        return finding;
    }

    public String getMatchedReason() {
        return matchedReason;
    }

    public String getSuppressionType() {
        return suppressionType;
    }

    @Override
    public String toString() {
        return "SuppressedFinding{" +
                "finding=" + finding.getId() +
                ", rule=" + finding.getRule().getRuleId() +
                ", type='" + suppressionType + '\'' +
                ", reason='" + matchedReason + '\'' +
                '}';
    }
}
