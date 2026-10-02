package com.sentinelpr.benchmark.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public class CompilationExpectation {

    private boolean originalCompiles = true;
    private boolean patchedCompiles = true;
    private String compilationSkipReason;

    public CompilationExpectation() {}

    public boolean isOriginalCompiles() {
        return originalCompiles;
    }

    public void setOriginalCompiles(boolean originalCompiles) {
        this.originalCompiles = originalCompiles;
    }

    public boolean isPatchedCompiles() {
        return patchedCompiles;
    }

    public void setPatchedCompiles(boolean patchedCompiles) {
        this.patchedCompiles = patchedCompiles;
    }

    public String getCompilationSkipReason() {
        return compilationSkipReason;
    }

    public void setCompilationSkipReason(String compilationSkipReason) {
        this.compilationSkipReason = compilationSkipReason;
    }
}
