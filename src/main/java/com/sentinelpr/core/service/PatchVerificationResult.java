package com.sentinelpr.core.service;

import com.sentinelpr.core.model.SecurityFinding;

import java.util.Collections;
import java.util.List;

/**
 * <b>PatchVerificationResult</b>
 *
 * <p>Outcome of post-patch AST syntax validation and regression evaluation.</p>
 */
public class PatchVerificationResult {

    private final boolean syntaxValid;
    private final boolean regressionVerified;
    private final List<SecurityFinding> remainingFindings;
    private final String message;

    public PatchVerificationResult(
            boolean syntaxValid,
            boolean regressionVerified,
            List<SecurityFinding> remainingFindings,
            String message
    ) {
        this.syntaxValid = syntaxValid;
        this.regressionVerified = regressionVerified;
        this.remainingFindings = remainingFindings != null ? Collections.unmodifiableList(remainingFindings) : List.of();
        this.message = message != null ? message : "";
    }

    public boolean isSyntaxValid() {
        return syntaxValid;
    }

    public boolean isRegressionVerified() {
        return regressionVerified;
    }

    public List<SecurityFinding> getRemainingFindings() {
        return remainingFindings;
    }

    public String getMessage() {
        return message;
    }
}
