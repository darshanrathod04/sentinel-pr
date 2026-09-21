package com.sentinelpr.core.export.github;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.sentinelpr.core.model.ReviewReport;
import com.sentinelpr.core.model.SecurityFinding;
import com.sentinelpr.core.model.Severity;
import com.sentinelpr.core.model.SuppressedFinding;
import com.sentinelpr.core.model.UnifiedDiffPatch;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * <b>PrReviewCommentBuilder</b>
 *
 * <p>Synthesizes GitHub Pull Request Review API payloads ({@code POST /repos/{owner}/{repo}/pulls/{pull_number}/reviews})
 * containing inline security review comments, collapsible code suggestion blocks ({@code ```suggestion```}),
 * and an executive markdown summary table with regression verification badges.</p>
 */
public class PrReviewCommentBuilder {

    private final ObjectMapper objectMapper;

    public PrReviewCommentBuilder() {
        this.objectMapper = new ObjectMapper()
                .enable(SerializationFeature.INDENT_OUTPUT);
    }

    public PrReviewCommentBuilder(ObjectMapper objectMapper) {
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper must not be null");
    }

    /**
     * GitHub Pull Request Review API payload DTO.
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class GitHubReviewPayload {

        @JsonProperty("commit_id")
        private final String commitId;

        @JsonProperty("body")
        private final String body;

        @JsonProperty("event")
        private final String event;

        @JsonProperty("comments")
        private final List<GitHubInlineComment> comments;

        public GitHubReviewPayload(String commitId, String body, String event, List<GitHubInlineComment> comments) {
            this.commitId = commitId;
            this.body = body != null ? body : "";
            this.event = event != null ? event : "COMMENT";
            this.comments = comments != null ? Collections.unmodifiableList(comments) : List.of();
        }

        public String getCommitId() {
            return commitId;
        }

        public String getBody() {
            return body;
        }

        public String getEvent() {
            return event;
        }

        public List<GitHubInlineComment> getComments() {
            return comments;
        }
    }

    /**
     * GitHub PR inline comment DTO.
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class GitHubInlineComment {

        @JsonProperty("path")
        private final String path;

        @JsonProperty("line")
        private final int line;

        @JsonProperty("start_line")
        private final Integer startLine;

        @JsonProperty("side")
        private final String side;

        @JsonProperty("body")
        private final String body;

        public GitHubInlineComment(String path, int line, String body) {
            this(path, line, null, "RIGHT", body);
        }

        public GitHubInlineComment(String path, int line, Integer startLine, String side, String body) {
            this.path = path != null ? path : "";
            this.line = Math.max(1, line);
            this.startLine = (startLine != null && startLine > 0 && startLine < line) ? startLine : null;
            this.side = side != null ? side : "RIGHT";
            this.body = body != null ? body : "";
        }

        public String getPath() {
            return path;
        }

        public int getLine() {
            return line;
        }

        public Integer getStartLine() {
            return startLine;
        }

        public String getSide() {
            return side;
        }

        public String getBody() {
            return body;
        }
    }

    /**
     * Builds the complete GitHub PR Review payload without commit_id.
     */
    public GitHubReviewPayload buildReviewPayload(ReviewReport report) {
        return buildReviewPayload(report, null, null);
    }

    public GitHubReviewPayload buildReviewPayload(ReviewReport report, String commitId) {
        return buildReviewPayload(report, null, commitId);
    }

    public GitHubReviewPayload buildReviewPayload(ReviewReport report, com.sentinelpr.core.governance.policy.PolicyEvaluationResult policyResult) {
        return buildReviewPayload(report, policyResult, null);
    }

    /**
     * Builds the complete GitHub PR Review payload with policy awareness and optional commit_id.
     */
    public GitHubReviewPayload buildReviewPayload(
            ReviewReport report,
            com.sentinelpr.core.governance.policy.PolicyEvaluationResult policyResult,
            String commitId
    ) {
        Objects.requireNonNull(report, "report must not be null");

        String event = determineReviewEvent(report, policyResult);
        String body = buildReviewSummaryMarkdown(report, policyResult, event);

        List<GitHubInlineComment> comments = new ArrayList<>();
        for (SecurityFinding finding : report.getFindings()) {
            UnifiedDiffPatch patch = findPatchForFinding(finding, report.getPatches());
            String commentBody = buildInlineCommentMarkdown(finding, patch);

            String filePath = cleanFilePath(finding.getTargetFile());
            int targetLine = finding.getEndLine() > 0 ? finding.getEndLine() : Math.max(1, finding.getStartLine());
            Integer startLine = (finding.getStartLine() > 0 && finding.getStartLine() < targetLine)
                    ? finding.getStartLine()
                    : null;

            comments.add(new GitHubInlineComment(filePath, targetLine, startLine, "RIGHT", commentBody));
        }

        return new GitHubReviewPayload(commitId, body, event, comments);
    }

    /**
     * Resolves the matching patch for a finding, handling composite patches.
     */
    public UnifiedDiffPatch findPatchForFinding(SecurityFinding finding, List<UnifiedDiffPatch> patches) {
        if (finding == null || patches == null || patches.isEmpty()) {
            return null;
        }
        for (UnifiedDiffPatch p : patches) {
            if (p.getFindingId() != null && (p.getFindingId().equals(finding.getId()) || p.getFindingId().contains(finding.getId()))) {
                return p;
            }
        }
        for (UnifiedDiffPatch p : patches) {
            if (p.getRuleId() != null && p.getRuleId().contains(finding.getRule().getRuleId())) {
                return p;
            }
        }
        for (UnifiedDiffPatch p : patches) {
            if (p.getTargetFile() != null && !p.getTargetFile().isBlank()) {
                String normPatchFile = cleanFilePath(p.getTargetFile());
                String normFindingFile = cleanFilePath(finding.getTargetFile());
                if (normPatchFile.equals(normFindingFile) || normPatchFile.endsWith(normFindingFile) || normFindingFile.endsWith(normPatchFile)) {
                    return p;
                }
            }
        }
        return patches.get(0);
    }

    /**
     * Serializes the review payload to JSON string.
     */
    public String toJson(GitHubReviewPayload payload) {
        try {
            return objectMapper.writeValueAsString(payload);
        } catch (Exception e) {
            throw new RuntimeException("Failed to serialize GitHub review payload: " + e.getMessage(), e);
        }
    }

    /**
     * Exports the review payload to a JSON file.
     */
    public void exportToFile(GitHubReviewPayload payload, Path outputPath) throws IOException {
        Objects.requireNonNull(payload, "payload must not be null");
        Objects.requireNonNull(outputPath, "outputPath must not be null");

        if (outputPath.getParent() != null) {
            Files.createDirectories(outputPath.getParent());
        }
        Files.writeString(outputPath, toJson(payload));
    }

    public String determineReviewEvent(List<SecurityFinding> findings) {
        return determineReviewEvent(findings, null, 0);
    }

    public String determineReviewEvent(
            ReviewReport report,
            com.sentinelpr.core.governance.policy.PolicyEvaluationResult policyResult
    ) {
        if (report == null) return "APPROVE";
        return determineReviewEvent(report.getFindings(), policyResult, report.getSuppressedCount());
    }

    /**
     * Determines GitHub Review event:
     * <ul>
     *   <li>REQUEST_CHANGES if policy is BREACHED or any CRITICAL/HIGH findings exist</li>
     *   <li>COMMENT if non-blocking medium/low findings exist</li>
     *   <li>APPROVE if 0 active findings exist (with advisory note if baseline debt exists)</li>
     * </ul>
     */
    public String determineReviewEvent(
            List<SecurityFinding> findings,
            com.sentinelpr.core.governance.policy.PolicyEvaluationResult policyResult,
            int suppressedCount
    ) {
        if (policyResult != null && policyResult.isBreached()) {
            return "REQUEST_CHANGES";
        }
        if (findings != null) {
            for (SecurityFinding f : findings) {
                if (f.getSeverity() == Severity.CRITICAL || f.getSeverity() == Severity.HIGH) {
                    return "REQUEST_CHANGES";
                }
            }
        }
        if (findings != null && !findings.isEmpty()) {
            return "COMMENT";
        }
        return "APPROVE";
    }

    public String buildReviewSummaryMarkdown(ReviewReport report, String event) {
        return buildReviewSummaryMarkdown(report, null, event);
    }

    /**
     * Formats the overall review summary in GitHub Flavored Markdown with honest status verdicts.
     */
    public String buildReviewSummaryMarkdown(
            ReviewReport report,
            com.sentinelpr.core.governance.policy.PolicyEvaluationResult policyResult,
            String event
    ) {
        StringBuilder sb = new StringBuilder();

        sb.append("## 🛡️ SentinelPR Code & Security Review\n\n");

        boolean isPolicyBreach = (policyResult != null && policyResult.isBreached());

        if (isPolicyBreach || "REQUEST_CHANGES".equals(event)) {
            sb.append("> [!CAUTION]\n");
            if (isPolicyBreach || (policyResult != null && policyResult.getBlockedCount() > 0)) {
                sb.append("> **❌ Review Status: Changes Requested (Blocked Policy Breach)**\n");
                sb.append("> Blocking security violations or enterprise compliance policies were breached in the active pull request. Immediate remediation is required before merging.\n\n");
            } else {
                sb.append("> **❌ Review Status: Changes Requested**\n");
                sb.append("> Blocking security violations were detected in the active pull request diff. Immediate remediation is required before merging.\n\n");
            }
        } else if (report.getVulnerabilityCount() == 0 && report.getSuppressedCount() > 0) {
            sb.append("> [!WARNING]\n");
            sb.append("> **⚠️ Review Status: Approved with Existing Technical Debt**\n");
            sb.append("> Pull request introduces zero new active vulnerabilities, but accepted technical debt exists in the baseline repository snapshot. Ensure existing debt is remediated according to compliance schedules.\n\n");
        } else if ("COMMENT".equals(event)) {
            sb.append("> [!WARNING]\n");
            sb.append("> **Review Status: Warnings / Review Comments**\n");
            sb.append("> Non-blocking architectural or security observations identified. Please review suggested improvements.\n\n");
        } else {
            sb.append("> [!NOTE]\n");
            sb.append("> **✅ Review Status: Clean Approval**\n");
            sb.append("> Zero blocking security vulnerabilities identified and zero baseline technical debt present. Code passes all SentinelPR audit gates.\n\n");
        }

        // Summary Statistics Table
        sb.append("### 📊 Executive Audit Metrics\n\n");
        sb.append("| Metric | Count |\n");
        sb.append("| :--- | :--- |\n");
        sb.append(String.format("| 📁 **Files Scanned** | %d |\n", report.getScannedFileCount()));
        sb.append(String.format("| 🚨 **Active Vulnerabilities** | %d |\n", report.getVulnerabilityCount()));
        sb.append(String.format("| 🛡️ **Suppressed / Baseline** | %d |\n", report.getSuppressedCount()));
        sb.append(String.format("| ⚡ **Verified Patches Synthesized** | %d |\n", report.getPatches().size()));
        sb.append(String.format("| 🧠 **Memory Kernel Cached** | %s |\n\n", report.isCachedAudit() ? "✅ Yes" : "No"));

        // Findings Breakdown Table
        if (!report.getFindings().isEmpty()) {
            sb.append("### 🔍 Identified Vulnerabilities\n\n");
            sb.append("| Rule ID | Severity | Location | Description | Patch Status | Verified |\n");
            sb.append("| :--- | :--- | :--- | :--- | :--- | :--- |\n");

            for (SecurityFinding f : report.getFindings()) {
                UnifiedDiffPatch patch = findPatchForFinding(f, report.getPatches());
                String loc = String.format("`%s:%d-%d`", getFileName(f.getTargetFile()), f.getStartLine(), f.getEndLine());
                String patchStatus = patch != null ? patch.getStatus().name() : "N/A";
                String verifiedBadge = (patch != null && patch.isVerified()) ? "✅ Yes" : "—";

                sb.append(String.format("| `%s` | **%s** | %s | %s | %s | %s |\n",
                        f.getRule().getRuleId(),
                        f.getSeverity().name(),
                        loc,
                        escapeMarkdown(f.getDescription()),
                        patchStatus,
                        verifiedBadge
                ));
            }
            sb.append("\n");
        }

        // Suppressed Findings Section
        if (!report.getSuppressedFindings().isEmpty()) {
            sb.append("<details>\n");
            sb.append(String.format("<summary>🛡️ Suppressed & Baseline Findings (%d)</summary>\n\n", report.getSuppressedCount()));
            sb.append("| Rule ID | Type | Target | Reason |\n");
            sb.append("| :--- | :--- | :--- | :--- |\n");
            for (SuppressedFinding sf : report.getSuppressedFindings()) {
                sb.append(String.format("| `%s` | `%s` | `%s:%d` | %s |\n",
                        sf.getFinding().getRule().getRuleId(),
                        sf.getSuppressionType(),
                        getFileName(sf.getFinding().getTargetFile()),
                        sf.getFinding().getStartLine(),
                        escapeMarkdown(sf.getMatchedReason())
                ));
            }
            sb.append("\n</details>\n\n");
        }

        sb.append("---\n");
        sb.append("*Generated autonomously by **SentinelPR** powered by **Shree AI OS**.*");

        return sb.toString();
    }

    /**
     * Formats an individual inline review comment with alert badge, explanation,
     * and collapsible suggestion block.
     */
    public String buildInlineCommentMarkdown(SecurityFinding finding, UnifiedDiffPatch patch) {
        StringBuilder sb = new StringBuilder();

        // Alert Header
        if (finding.getSeverity() == Severity.CRITICAL) {
            sb.append("> [!CAUTION]\n");
            sb.append(String.format("> **%s: %s**\n\n", finding.getRule().getRuleId(), finding.getRule().getTitle()));
        } else if (finding.getSeverity() == Severity.HIGH) {
            sb.append("> [!WARNING]\n");
            sb.append(String.format("> **%s: %s**\n\n", finding.getRule().getRuleId(), finding.getRule().getTitle()));
        } else {
            sb.append("> [!NOTE]\n");
            sb.append(String.format("> **%s: %s**\n\n", finding.getRule().getRuleId(), finding.getRule().getTitle()));
        }

        sb.append(finding.getDescription()).append("\n\n");

        if (finding.getCausalRationale() != null && !finding.getCausalRationale().isBlank()) {
            sb.append("**Causal Rationale:**\n");
            sb.append(finding.getCausalRationale()).append("\n\n");
        }

        if (finding.getRemediation() != null && !finding.getRemediation().isBlank()) {
            sb.append("**Remediation Guidance:**\n");
            sb.append(finding.getRemediation()).append("\n\n");
        }

        // Code Suggestion Block
        if (patch != null) {
            String suggestionCode = extractSuggestionCode(patch);
            if (!suggestionCode.isBlank()) {
                sb.append("<details open>\n");
                sb.append(String.format("<summary>💡 <b>Suggested Remediation Patch</b> (%s)</summary>\n\n",
                        patch.isRegressionVerified() ? "AST & Regression Verified" : "AST Verified"));
                sb.append("```suggestion\n");
                sb.append(suggestionCode).append("\n");
                sb.append("```\n");
                sb.append("</details>\n");
            } else if (patch.getUnifiedDiff() != null && !patch.getUnifiedDiff().isBlank()) {
                sb.append("<details>\n");
                sb.append("<summary>💡 <b>Unified Diff Patch</b></summary>\n\n");
                sb.append("```diff\n");
                sb.append(patch.getUnifiedDiff()).append("\n");
                sb.append("```\n");
                sb.append("</details>\n");
            }
        }

        return sb.toString().trim();
    }

    /**
     * Extracts replacement lines from a unified diff patch for use in GitHub ```suggestion``` blocks.
     */
    public static String extractSuggestionCode(UnifiedDiffPatch patch) {
        if (patch == null || patch.getUnifiedDiff() == null || patch.getUnifiedDiff().isBlank()) {
            return "";
        }

        String diff = patch.getUnifiedDiff();
        String[] lines = diff.split("\\R");
        StringBuilder sb = new StringBuilder();
        boolean inHunk = false;

        for (String line : lines) {
            if (line.startsWith("@@ ")) {
                inHunk = true;
                continue;
            }
            if (inHunk) {
                if (line.startsWith("+") && !line.startsWith("+++")) {
                    sb.append(line.substring(1)).append("\n");
                } else if (line.startsWith(" ")) {
                    // Context lines in replacement
                    sb.append(line.substring(1)).append("\n");
                }
            }
        }

        String result = sb.toString().stripTrailing();
        return result;
    }

    private static String cleanFilePath(String path) {
        if (path == null) {
            return "";
        }
        String p = path.replace('\\', '/').trim();
        if (p.startsWith("/")) {
            p = p.substring(1);
        }
        return p;
    }

    private static String getFileName(String path) {
        if (path == null || path.isEmpty()) {
            return "";
        }
        String p = path.replace('\\', '/');
        int idx = p.lastIndexOf('/');
        return idx >= 0 ? p.substring(idx + 1) : p;
    }

    private static String escapeMarkdown(String str) {
        if (str == null) {
            return "";
        }
        return str.replace("|", "\\|").replace("\n", " ");
    }
}
