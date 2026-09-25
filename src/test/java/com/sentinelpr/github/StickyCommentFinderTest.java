package com.sentinelpr.github;

import com.sentinelpr.github.model.GitHubComment;
import com.sentinelpr.github.model.GitHubUser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.OptionalLong;

import static org.junit.jupiter.api.Assertions.*;

/**
 * <b>StickyCommentFinderTest</b>
 *
 * <p>Unit tests for {@link StickyCommentFinder} verifying sticky comment detection
 * by HTML marker without comment duplication.</p>
 */
class StickyCommentFinderTest {

    private StickyCommentFinder finder;

    @BeforeEach
    void setUp() {
        finder = new StickyCommentFinder();
    }

    @Test
    @DisplayName("Returns comment ID when sticky marker is present in comment body")
    void testFindStickyCommentIdPresent() {
        GitHubComment regularComment = new GitHubComment(101L, "Looks good to me!");
        GitHubComment stickyComment = new GitHubComment(102L,
                "<!-- sentinel-pr-review -->\n# 🛡 SentinelPR Security Review\nStatus: BLOCKED");
        GitHubComment otherComment = new GitHubComment(103L, "Thanks for the review!");

        List<GitHubComment> comments = List.of(regularComment, stickyComment, otherComment);

        OptionalLong result = finder.findStickyCommentId(comments);

        assertTrue(result.isPresent(), "Must find sticky comment ID");
        assertEquals(102L, result.getAsLong());
    }

    @Test
    @DisplayName("Returns empty when no comments contain the sticky marker")
    void testFindStickyCommentIdAbsent() {
        GitHubComment c1 = new GitHubComment(201L, "Some regular feedback.");
        GitHubComment c2 = new GitHubComment(202L, "CI checks passed successfully.");

        List<GitHubComment> comments = List.of(c1, c2);

        OptionalLong result = finder.findStickyCommentId(comments);

        assertTrue(result.isEmpty(), "Must be empty when marker is absent");
    }

    @Test
    @DisplayName("Returns first matching comment ID when multiple sticky comments exist")
    void testFindStickyCommentIdMultiple() {
        GitHubComment olderSticky = new GitHubComment(301L, "<!-- sentinel-pr-review -->\nOlder review");
        GitHubComment newerSticky = new GitHubComment(302L, "<!-- sentinel-pr-review -->\nNewer review");

        List<GitHubComment> comments = List.of(olderSticky, newerSticky);

        OptionalLong result = finder.findStickyCommentId(comments);

        assertTrue(result.isPresent());
        assertEquals(301L, result.getAsLong(), "Must return the first matching sticky comment");
    }

    @Test
    @DisplayName("Safely handles null and empty comment lists")
    void testFindStickyCommentIdNullOrEmpty() {
        assertTrue(finder.findStickyCommentId(null).isEmpty());
        assertTrue(finder.findStickyCommentId(Collections.emptyList()).isEmpty());
    }

    @Test
    @DisplayName("findStickyComment returns the complete GitHubComment instance")
    void testFindStickyCommentObject() {
        GitHubUser botUser = new GitHubUser(1L, "github-actions[bot]", null, "Bot");
        GitHubComment stickyComment = new GitHubComment(
                401L,
                "<!-- sentinel-pr-review -->\nReview payload",
                "https://github.com/owner/repo/pull/1#issuecomment-401",
                "https://api.github.com/repos/owner/repo/issues/comments/401",
                botUser,
                "2026-09-25T10:00:00Z",
                "2026-09-25T10:00:00Z"
        );

        Optional<GitHubComment> found = finder.findStickyComment(List.of(stickyComment));

        assertTrue(found.isPresent());
        assertEquals(401L, found.get().getId());
        assertEquals(botUser, found.get().getUser());
        assertEquals("https://github.com/owner/repo/pull/1#issuecomment-401", found.get().getHtmlUrl());
    }
}
