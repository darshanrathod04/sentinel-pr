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
    private String diffContent;
    private String format; // "json", "sarif", "github"

    public ReviewFileRequest() {
    }

    public ReviewFileRequest(String targetPath, String sourceCode, String simulatedFileName) {
        this(targetPath, sourceCode, simulatedFileName, null, "json");
    }

    public ReviewFileRequest(String targetPath, String sourceCode, String simulatedFileName, String diffContent, String format) {
        this.targetPath = targetPath;
        this.sourceCode = sourceCode;
        this.simulatedFileName = simulatedFileName;
        this.diffContent = diffContent;
        this.format = format;
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

    public String getDiffContent() {
        return diffContent;
    }

    public void setDiffContent(String diffContent) {
        this.diffContent = diffContent;
    }

    public String getFormat() {
        return format;
    }

    public void setFormat(String format) {
        this.format = format;
    }
}
