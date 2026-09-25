package com.sentinelpr.github;

import com.sentinelpr.github.model.GitHubComment;

import java.util.List;
import java.util.Optional;
import java.util.OptionalLong;

/**
 * <b>StickyCommentFinder</b>
 *
 * <p>Identifies existing SentinelPR review comments on pull requests using a hidden HTML comment marker.
 * This guarantees idempotency and prevents bot review comment spam across multiple workflow runs.</p>
 */
public class StickyCommentFinder {

    public static final String STICKY_MARKER = "<!-- sentinel-pr-review -->";

    /**
     * Searches a list of GitHub comments for the first comment containing the SentinelPR marker
     * and returns its ID.
     *
     * @param comments list of PR comments
     * @return OptionalLong containing the comment ID if found, otherwise empty
     */
    public OptionalLong findStickyCommentId(List<GitHubComment> comments) {
        return findStickyComment(comments)
                .map(c -> OptionalLong.of(c.getId()))
                .orElseGet(OptionalLong::empty);
    }

    /**
     * Searches a list of GitHub comments for the first comment containing the SentinelPR marker.
     *
     * @param comments list of PR comments
     * @return Optional containing the GitHubComment if found, otherwise empty
     */
    public Optional<GitHubComment> findStickyComment(List<GitHubComment> comments) {
        if (comments == null || comments.isEmpty()) {
            return Optional.empty();
        }
        for (GitHubComment comment : comments) {
            if (comment != null && comment.getBody() != null && comment.getBody().contains(STICKY_MARKER)) {
                return Optional.of(comment);
            }
        }
        return Optional.empty();
    }
}
