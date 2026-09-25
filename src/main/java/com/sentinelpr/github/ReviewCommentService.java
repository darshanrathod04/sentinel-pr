package com.sentinelpr.github;

import com.sentinelpr.core.governance.policy.PolicyEvaluationResult;
import com.sentinelpr.core.model.ReviewReport;
import com.sentinelpr.core.model.SecurityFinding;
import com.sentinelpr.core.model.Severity;
import com.sentinelpr.core.model.UnifiedDiffPatch;
import com.sentinelpr.github.model.GitHubComment;

import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.OptionalLong;

/**
 * <b>ReviewCommentService</b>
 *
 * <p>Generates structured GitHub Pull Request markdown comments matching the SentinelPR specification
 * and manages posting/updating comments via {@link GitHubApiClient} and {@link StickyCommentFinder}.</p>
 */
public class ReviewCommentService {

    private final GitHubApiClient gitHubApiClient;
    private final StickyCommentFinder stickyCommentFinder;

    public ReviewCommentService() {
        this(new GitHubApiClient(), new StickyCommentFinder());
    }

    public ReviewCommentService(GitHubApiClient gitHubApiClient, StickyCommentFinder stickyCommentFinder) {
        this.gitHubApiClient = Objects.requireNonNull(gitHubApiClient, "gitHubApiClient must not be null");
        this.stickyCommentFinder = Objects.requireNonNull(stickyCommentFinder, "stickyCommentFinder must not be null");
    }

    /**
     * Synthesizes GitHub markdown review comment from review report and policy evaluation result.
     *
     * @param report ReviewReport generated from the audit
     * @param policy optional PolicyEvaluationResult
     * @return markdown formatted comment
     */
    public String buildCommentMarkdown(ReviewReport report, PolicyEvaluationResult policy) {
        StringBuilder sb = new StringBuilder();

        sb.append(StickyCommentFinder.STICKY_MARKER).append("\n\n");
        sb.append("# 🛡 SentinelPR Security Review\n\n");

        String status = determineStatus(report, policy);
        sb.append("Status: ").append(status).append("\n\n");

        sb.append("## Findings\n\n");
        sb.append("| Severity | Rule | File |\n");
        sb.append("|----------|------|------|\n");

        List<SecurityFinding> findings = (report != null && report.getFindings() != null)
                ? report.getFindings()
                : Collections.emptyList();

        if (findings.isEmpty()) {
            sb.append("| CLEAN | NONE | Clean (0 active findings) |\n");
        } else {
            for (SecurityFinding f : findings) {
                String severity = f.getSeverity() != null ? f.getSeverity().name() : "MEDIUM";
                String ruleId = (f.getRule() != null && f.getRule().getRuleId() != null)
                        ? f.getRule().getRuleId()
                        : "SEC-UNKNOWN";
                String file = cleanFilePath(f.getTargetFile());
                if (f.getStartLine() > 0) {
                    file += ":" + f.getStartLine();
                }
                sb.append(String.format("| %s | %s | %s |\n", severity, ruleId, file));
            }
        }
        sb.append("\n");

        sb.append("## Suggested Patch\n\n");
        List<UnifiedDiffPatch> patches = (report != null && report.getPatches() != null)
                ? report.getPatches()
                : Collections.emptyList();

        StringBuilder diffBuilder = new StringBuilder();
        for (UnifiedDiffPatch p : patches) {
            if (p != null && p.getUnifiedDiff() != null && !p.getUnifiedDiff().isBlank()) {
                if (diffBuilder.length() > 0) {
                    diffBuilder.append("\n");
                }
                diffBuilder.append(p.getUnifiedDiff().trim());
            }
        }

        if (diffBuilder.length() > 0) {
            sb.append("```diff\n").append(diffBuilder).append("\n```\n\n");
        } else {
            sb.append("```diff\n# No patch required\n```\n\n");
        }

        sb.append("---\n");
        sb.append("Powered by SentinelPR + Shree AI OS\n");

        return sb.toString();
    }

    public String buildCommentMarkdown(ReviewReport report) {
        return buildCommentMarkdown(report, null);
    }

    /**
     * Posts or updates the sticky PR review comment.
     * Searches existing comments for the sticky marker. If found, updates it in place;
     * otherwise creates a new comment.
     *
     * @param repo     repository in "owner/repo" format
     * @param prNumber pull request number
     * @param report   ReviewReport generated from audit
     * @param policy   optional PolicyEvaluationResult
     * @return the created or updated GitHubComment
     */
    public GitHubComment postOrUpdateComment(
            String repo,
            int prNumber,
            ReviewReport report,
            PolicyEvaluationResult policy
    ) {
        String markdown = buildCommentMarkdown(report, policy);
        List<GitHubComment> existingComments = gitHubApiClient.getComments(repo, prNumber);
        OptionalLong stickyCommentIdOpt = stickyCommentFinder.findStickyCommentId(existingComments);

        if (stickyCommentIdOpt.isPresent()) {
            long commentId = stickyCommentIdOpt.getAsLong();
            gitHubApiClient.updateComment(repo, commentId, markdown);
            return new GitHubComment(commentId, markdown);
        } else {
            return gitHubApiClient.createComment(repo, prNumber, markdown);
        }
    }

    private String determineStatus(ReviewReport report, PolicyEvaluationResult policy) {
        if (policy != null) {
            if (policy.isBreached()
                    || policy.getStatus() == PolicyEvaluationResult.Status.BREACHED
                    || policy.getStatus() == PolicyEvaluationResult.Status.FAILED) {
                return "BLOCKED";
            }
            if (policy.getStatus() == PolicyEvaluationResult.Status.PASSED_WITH_BASELINE) {
                return "PASSED_WITH_BASELINE";
            }
            if (policy.getStatus() == PolicyEvaluationResult.Status.PASSED) {
                return "PASSED";
            }
        }

        if (report != null) {
            if (report.getFindings() != null) {
                for (SecurityFinding f : report.getFindings()) {
                    if (f.getSeverity() == Severity.CRITICAL || f.getSeverity() == Severity.HIGH) {
                        return "BLOCKED";
                    }
                }
                if (!report.getFindings().isEmpty()) {
                    return "BLOCKED";
                }
            }
            if (report.getSuppressedCount() > 0) {
                return "PASSED_WITH_BASELINE";
            }
        }

        return "PASSED";
    }

    private String cleanFilePath(String path) {
        if (path == null) return "";
        return path.replace('\\', '/');
    }

    public GitHubApiClient getGitHubApiClient() {
        return gitHubApiClient;
    }

    public StickyCommentFinder getStickyCommentFinder() {
        return stickyCommentFinder;
    }
}
