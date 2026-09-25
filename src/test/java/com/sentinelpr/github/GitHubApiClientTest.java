package com.sentinelpr.github;

import com.sentinelpr.github.model.GitHubComment;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * <b>GitHubApiClientTest</b>
 *
 * <p>Unit tests for {@link GitHubApiClient} verifying HTTP request paths, required headers,
 * JSON serialization/deserialization, and error handling with mocked HTTP responses.</p>
 */
class GitHubApiClientTest {

    private HttpClient mockHttpClient;
    private HttpResponse<String> mockHttpResponse;
    private GitHubApiClient client;

    private static final String TEST_TOKEN = "ghp_testToken1234567890";
    private static final String REPO = "darshanrathod04/sentinel-pr";
    private static final int PR_NUMBER = 42;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() {
        mockHttpClient = mock(HttpClient.class);
        mockHttpResponse = mock(HttpResponse.class);
        client = new GitHubApiClient(TEST_TOKEN, "https://api.github.com", mockHttpClient);
    }

    @Test
    @DisplayName("getComments sends GET request with required headers and deserializes comments")
    @SuppressWarnings("unchecked")
    void testGetCommentsSuccess() throws IOException, InterruptedException {
        String jsonResponse = """
                [
                  {
                    "id": 1001,
                    "body": "First PR comment",
                    "html_url": "https://github.com/darshanrathod04/sentinel-pr/pull/42#issuecomment-1001",
                    "user": {
                      "id": 10,
                      "login": "octocat",
                      "type": "User"
                    }
                  },
                  {
                    "id": 1002,
                    "body": "<!-- sentinel-pr-review -->\\n# Review",
                    "html_url": "https://github.com/darshanrathod04/sentinel-pr/pull/42#issuecomment-1002",
                    "user": {
                      "id": 20,
                      "login": "sentinelpr[bot]",
                      "type": "Bot"
                    }
                  }
                ]
                """;

        when(mockHttpResponse.statusCode()).thenReturn(200);
        when(mockHttpResponse.body()).thenReturn(jsonResponse);
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockHttpResponse);

        List<GitHubComment> comments = client.getComments(REPO, PR_NUMBER);

        assertNotNull(comments);
        assertEquals(2, comments.size());
        assertEquals(1001L, comments.get(0).getId());
        assertEquals("First PR comment", comments.get(0).getBody());
        assertEquals("octocat", comments.get(0).getUser().getLogin());
        assertEquals(1002L, comments.get(1).getId());

        // Verify request URI, method, and headers
        ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
        verify(mockHttpClient).send(captor.capture(), any());
        HttpRequest request = captor.getValue();

        assertEquals("GET", request.method());
        assertEquals("https://api.github.com/repos/darshanrathod04/sentinel-pr/issues/42/comments", request.uri().toString());
        assertEquals("Bearer " + TEST_TOKEN, request.headers().firstValue("Authorization").orElse(null));
        assertEquals("application/vnd.github+json", request.headers().firstValue("Accept").orElse(null));
        assertEquals("2022-11-28", request.headers().firstValue("X-GitHub-Api-Version").orElse(null));
    }

    @Test
    @DisplayName("createComment sends POST request with JSON payload and returns created comment")
    @SuppressWarnings("unchecked")
    void testCreateCommentSuccess() throws IOException, InterruptedException {
        String commentBody = "<!-- sentinel-pr-review -->\n# 🛡 SentinelPR Security Review\nStatus: BLOCKED";
        String jsonResponse = """
                {
                  "id": 2001,
                  "body": "<!-- sentinel-pr-review -->\\n# 🛡 SentinelPR Security Review\\nStatus: BLOCKED",
                  "html_url": "https://github.com/darshanrathod04/sentinel-pr/pull/42#issuecomment-2001"
                }
                """;

        when(mockHttpResponse.statusCode()).thenReturn(201);
        when(mockHttpResponse.body()).thenReturn(jsonResponse);
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockHttpResponse);

        GitHubComment created = client.createComment(REPO, PR_NUMBER, commentBody);

        assertNotNull(created);
        assertEquals(2001L, created.getId());
        assertTrue(created.getBody().contains("Status: BLOCKED"));

        ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
        verify(mockHttpClient).send(captor.capture(), any());
        HttpRequest request = captor.getValue();

        assertEquals("POST", request.method());
        assertEquals("https://api.github.com/repos/darshanrathod04/sentinel-pr/issues/42/comments", request.uri().toString());
        assertEquals("Bearer " + TEST_TOKEN, request.headers().firstValue("Authorization").orElse(null));
        assertEquals("application/vnd.github+json", request.headers().firstValue("Accept").orElse(null));
        assertEquals("2022-11-28", request.headers().firstValue("X-GitHub-Api-Version").orElse(null));
        assertEquals("application/json", request.headers().firstValue("Content-Type").orElse(null));
    }

    @Test
    @DisplayName("updateComment sends PATCH request with new body to the comment resource")
    @SuppressWarnings("unchecked")
    void testUpdateCommentSuccess() throws IOException, InterruptedException {
        long commentId = 2001L;
        String updatedBody = "<!-- sentinel-pr-review -->\n# 🛡 SentinelPR Security Review\nStatus: PASSED";

        when(mockHttpResponse.statusCode()).thenReturn(200);
        when(mockHttpResponse.body()).thenReturn("{}");
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockHttpResponse);

        assertDoesNotThrow(() -> client.updateComment(REPO, commentId, updatedBody));

        ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
        verify(mockHttpClient).send(captor.capture(), any());
        HttpRequest request = captor.getValue();

        assertEquals("PATCH", request.method());
        assertEquals("https://api.github.com/repos/darshanrathod04/sentinel-pr/issues/comments/2001", request.uri().toString());
        assertEquals("Bearer " + TEST_TOKEN, request.headers().firstValue("Authorization").orElse(null));
        assertEquals("application/vnd.github+json", request.headers().firstValue("Accept").orElse(null));
        assertEquals("2022-11-28", request.headers().firstValue("X-GitHub-Api-Version").orElse(null));
        assertEquals("application/json", request.headers().firstValue("Content-Type").orElse(null));
    }

    @Test
    @DisplayName("Throws RuntimeException on GitHub API error response status")
    @SuppressWarnings("unchecked")
    void testApiErrorResponseHandling() throws IOException, InterruptedException {
        when(mockHttpResponse.statusCode()).thenReturn(404);
        when(mockHttpResponse.body()).thenReturn("{\"message\": \"Not Found\"}");
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockHttpResponse);

        RuntimeException ex = assertThrows(RuntimeException.class, () -> client.getComments(REPO, 9999));
        assertTrue(ex.getMessage().contains("404"), "Exception message must include status code: " + ex.getMessage());
    }

    @Test
    @DisplayName("Normalizes repository input strings with leading/trailing slashes or URLs")
    @SuppressWarnings("unchecked")
    void testNormalizeRepo() throws IOException, InterruptedException {
        when(mockHttpResponse.statusCode()).thenReturn(200);
        when(mockHttpResponse.body()).thenReturn("[]");
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockHttpResponse);

        client.getComments("https://github.com/owner/my-repo.git", 1);

        ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
        verify(mockHttpClient).send(captor.capture(), any());
        assertEquals("https://api.github.com/repos/owner/my-repo/issues/1/comments", captor.getValue().uri().toString());
    }
}
