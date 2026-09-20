package com.sentinelpr.core.analysis;

/**
 * <b>SuppressionResult</b>
 *
 * <p>Evaluation outcome from SuppressionManager.</p>
 */
public class SuppressionResult {

    private final boolean suppressed;
    private final String reason;
    private final String type; // ANNOTATION, INLINE_COMMENT, IGNORE_FILE

    private SuppressionResult(boolean suppressed, String reason, String type) {
        this.suppressed = suppressed;
        this.reason = reason;
        this.type = type;
    }

    public static SuppressionResult notSuppressed() {
        return new SuppressionResult(false, null, null);
    }

    public static SuppressionResult suppressed(String reason, String type) {
        return new SuppressionResult(true, reason, type);
    }

    public boolean isSuppressed() {
        return suppressed;
    }

    public String getReason() {
        return reason;
    }

    public String getType() {
        return type;
    }
}
