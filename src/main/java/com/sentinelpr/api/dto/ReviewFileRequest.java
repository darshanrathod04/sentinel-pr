package com.sentinelpr.api.dto;

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * Request payload for POST /api/v1/sentinel/review.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ReviewFileRequest {

    private String targetPath;
    private String sourceCode;
    private String simulatedFileName;

    public ReviewFileRequest() {
    }

    public ReviewFileRequest(String targetPath, String sourceCode, String simulatedFileName) {
        this.targetPath = targetPath;
        this.sourceCode = sourceCode;
        this.simulatedFileName = simulatedFileName;
    }

    public String getTargetPath() {
        return targetPath;
    }

    public void setTargetPath(String targetPath) {
        this.targetPath = targetPath;
    }

    public String getSourceCode() {
        return sourceCode;
    }

    public void setSourceCode(String sourceCode) {
        this.sourceCode = sourceCode;
    }

    public String getSimulatedFileName() {
        return simulatedFileName;
    }

    public void setSimulatedFileName(String simulatedFileName) {
        this.simulatedFileName = simulatedFileName;
    }
}
