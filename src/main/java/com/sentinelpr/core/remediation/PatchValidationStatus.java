package com.sentinelpr.core.remediation;

/**
 * <b>PatchValidationStatus</b>
 *
 * <p>Represents the AST syntax validation status of a synthesized patch.</p>
 */
public enum PatchValidationStatus {
    /**
     * Synthesized patch is syntactically valid Java 21 LTS code.
     */
    VALID_PATCH,

    /**
     * Synthesized patch resulted in compilation/syntax errors and was rejected.
     */
    INVALID_PATCH,

    /**
     * No transformation was applicable or the source was unchanged.
     */
    NOT_APPLICABLE,

    /**
     * Non-Java or complex finding where automated AST transformation is not supported
     * and manual engineering remediation is required.
     */
    MANUAL_REMEDIATION_REQUIRED
}
