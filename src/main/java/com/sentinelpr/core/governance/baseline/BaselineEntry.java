package com.sentinelpr.core.governance.baseline;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.sentinelpr.core.model.SecurityFinding;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Objects;

/**
 * <b>BaselineEntry</b>
 *
 * <p>Represents a single known security defect or technical debt item captured
 * in a repository baseline snapshot.</p>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class BaselineEntry {

    private final String fingerprint;
    private final String filePath;
    private final String ruleId;
    private final int startLine;
    private final int endLine;
    private final String className;
    private final String methodName;
    private final String snippet;
    private final Instant capturedAt;

    @JsonCreator
    public BaselineEntry(
            @JsonProperty("fingerprint") String fingerprint,
            @JsonProperty("filePath") String filePath,
            @JsonProperty("ruleId") String ruleId,
            @JsonProperty("startLine") int startLine,
            @JsonProperty("endLine") int endLine,
            @JsonProperty("className") String className,
            @JsonProperty("methodName") String methodName,
            @JsonProperty("snippet") String snippet,
            @JsonProperty("capturedAt") Instant capturedAt
    ) {
        this.fingerprint = Objects.requireNonNull(fingerprint, "fingerprint must not be null");
        this.filePath = filePath != null ? normalizePath(filePath) : "";
        this.ruleId = ruleId != null ? ruleId : "";
        this.startLine = startLine;
        this.endLine = endLine;
        this.className = className != null ? className : "";
        this.methodName = methodName != null ? methodName : "";
        this.snippet = snippet != null ? snippet.trim() : "";
        this.capturedAt = capturedAt != null ? capturedAt : Instant.now();
    }

    public static BaselineEntry fromFinding(SecurityFinding finding) {
        Objects.requireNonNull(finding, "finding must not be null");
        String normPath = normalizePath(finding.getTargetFile());
        String ruleId = finding.getRule().getRuleId();
        String methodName = finding.getMethodName() != null ? finding.getMethodName() : "";
        String snippet = finding.getVulnerableSnippet() != null ? finding.getVulnerableSnippet() : "";
        String fingerprint = computeFingerprint(normPath, ruleId, methodName, snippet);

        return new BaselineEntry(
                fingerprint,
                normPath,
                ruleId,
                finding.getStartLine(),
                finding.getEndLine(),
                finding.getClassName(),
                methodName,
                snippet,
                Instant.now()
        );
    }

    public static String computeFingerprint(String filePath, String ruleId, String methodName, String snippet) {
        String cleanPath = normalizePath(filePath);
        String cleanRule = ruleId != null ? ruleId.trim() : "";
        String cleanMethod = methodName != null ? methodName.trim() : "";
        String cleanSnippet = snippet != null ? snippet.replaceAll("\\s+", " ").trim() : "";

        String payload = cleanPath + "|" + cleanRule + "|" + cleanMethod + "|" + cleanSnippet;
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(payload.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash).substring(0, 32);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm unavailable", e);
        }
    }

    /**
     * Checks if this baseline entry matches a discovered security finding.
     */
    public boolean matches(SecurityFinding finding) {
        if (finding == null) {
            return false;
        }

        // 1. Direct fingerprint match
        String findingNormPath = normalizePath(finding.getTargetFile());
        String findingRuleId = finding.getRule().getRuleId();
        String findingMethod = finding.getMethodName() != null ? finding.getMethodName() : "";
        String findingSnippet = finding.getVulnerableSnippet() != null ? finding.getVulnerableSnippet() : "";
        String findingFingerprint = computeFingerprint(findingNormPath, findingRuleId, findingMethod, findingSnippet);

        if (this.fingerprint.equalsIgnoreCase(findingFingerprint)) {
            return true;
        }

        // 2. Structural match: same file and same rule with line proximity (+/- 5 lines) or same method
        boolean fileMatches = this.filePath.equalsIgnoreCase(findingNormPath)
                || this.filePath.endsWith(findingNormPath)
                || findingNormPath.endsWith(this.filePath);

        if (fileMatches && this.ruleId.equalsIgnoreCase(findingRuleId)) {
            if (!this.methodName.isBlank() && this.methodName.equals(findingMethod)) {
                return true;
            }
            int lineDiff = Math.abs(this.startLine - finding.getStartLine());
            if (lineDiff <= 5) {
                return true;
            }
        }

        return false;
    }

    private static String normalizePath(String path) {
        if (path == null) {
            return "";
        }
        String p = path.replace('\\', '/').trim();
        if (p.startsWith("/")) {
            p = p.substring(1);
        }
        return p;
    }

    public String getFingerprint() {
        return fingerprint;
    }

    public String getFilePath() {
        return filePath;
    }

    public String getRuleId() {
        return ruleId;
    }

    public int getStartLine() {
        return startLine;
    }

    public int getEndLine() {
        return endLine;
    }

    public String getClassName() {
        return className;
    }

    public String getMethodName() {
        return methodName;
    }

    public String getSnippet() {
        return snippet;
    }

    public Instant getCapturedAt() {
        return capturedAt;
    }

    @Override
    public String toString() {
        return "BaselineEntry{" +
                "ruleId='" + ruleId + '\'' +
                ", filePath='" + filePath + '\'' +
                ", line=" + startLine + "-" + endLine +
                ", fingerprint='" + fingerprint + '\'' +
                '}';
    }
}
