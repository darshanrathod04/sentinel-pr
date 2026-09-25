package com.sentinelpr.github;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sentinelpr.github.model.GitHubComment;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * <b>GitHubApiClient</b>
 *
 * <p>Lightweight HTTP client for GitHub REST API interactions using standard Java 21 {@link HttpClient}.</p>
 *
 * <p>Requirements enforced:</p>
 * <ul>
 *   <li>Reads token from {@code GITHUB_TOKEN} environment variable by default</li>
 *   <li>Base URL: {@code https://api.github.com}</li>
 *   <li>Headers: {@code Authorization: Bearer <TOKEN>}, {@code Accept: application/vnd.github+json},
 *       {@code X-GitHub-Api-Version: 2022-11-28}</li>
 *   <li>Zero external GitHub SDK dependencies</li>
 * </ul>
 */
public class GitHubApiClient {

    public static final String DEFAULT_BASE_URL = "https://api.github.com";
    public static final String API_VERSION = "2022-11-28";
    public static final String ACCEPT_HEADER = "application/vnd.github+json";

    private final String token;
    private final String baseUrl;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;

    public GitHubApiClient() {
        this(resolveDefaultToken(), DEFAULT_BASE_URL, defaultHttpClient());
    }

    public GitHubApiClient(String token) {
        this(token, DEFAULT_BASE_URL, defaultHttpClient());
    }

    public GitHubApiClient(String token, String baseUrl) {
        this(token, baseUrl, defaultHttpClient());
    }

    public GitHubApiClient(String token, String baseUrl, HttpClient httpClient) {
        this.token = (token != null && !token.isBlank()) ? token.trim() : null;
        this.baseUrl = normalizeBaseUrl(baseUrl != null ? baseUrl : DEFAULT_BASE_URL);
        this.httpClient = Objects.requireNonNull(httpClient, "httpClient must not be null");
        this.objectMapper = new ObjectMapper();
    }

    private static String resolveDefaultToken() {
        String token = System.getenv("GITHUB_TOKEN");
        if (token == null || token.isBlank()) {
            token = System.getProperty("github.token");
        }
        return token;
    }

    private static HttpClient defaultHttpClient() {
        return HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(15))
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
    }

    private static String normalizeBaseUrl(String url) {
        String trimmed = url.trim();
        while (trimmed.endsWith("/")) {
            trimmed = trimmed.substring(0, trimmed.length() - 1);
        }
        return trimmed;
    }

    private String normalizeRepo(String repo) {
        if (repo == null || repo.isBlank()) {
            throw new IllegalArgumentException("Repository must not be null or blank");
        }
        String cleaned = repo.trim();
        if (cleaned.startsWith("https://github.com/")) {
            cleaned = cleaned.substring("https://github.com/".length());
        } else if (cleaned.startsWith("http://github.com/")) {
            cleaned = cleaned.substring("http://github.com/".length());
        }
        if (cleaned.endsWith(".git")) {
            cleaned = cleaned.substring(0, cleaned.length() - 4);
        }
        while (cleaned.startsWith("/")) {
            cleaned = cleaned.substring(1);
        }
        while (cleaned.endsWith("/")) {
            cleaned = cleaned.substring(0, cleaned.length() - 1);
        }
        return cleaned;
    }

    private HttpRequest.Builder newRequestBuilder(String path) {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + path))
                .header("Accept", ACCEPT_HEADER)
                .header("X-GitHub-Api-Version", API_VERSION)
                .header("User-Agent", "SentinelPR-Bot");

        if (token != null && !token.isBlank()) {
            builder.header("Authorization", "Bearer " + token);
        }
        return builder;
    }

    /**
     * Retrieves all comments on a pull request issue thread.
     *
     * @param repo     repository in "owner/repo" format
     * @param prNumber pull request number
     * @return list of GitHub comments
     */
    public List<GitHubComment> getComments(String repo, int prNumber) {
        String cleanRepo = normalizeRepo(repo);
        String path = String.format("/repos/%s/issues/%d/comments", cleanRepo, prNumber);

        HttpRequest request = newRequestBuilder(path)
                .GET()
                .build();

        try {
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            int status = response.statusCode();
            if (status >= 200 && status < 300) {
                String responseBody = response.body();
                if (responseBody == null || responseBody.isBlank()) {
                    return Collections.emptyList();
                }
                return objectMapper.readValue(responseBody, new TypeReference<List<GitHubComment>>() {});
            } else {
                throw new RuntimeException(String.format(
                        "GitHub API GET comments failed [%d]: %s", status, response.body()));
            }
        } catch (IOException e) {
            throw new RuntimeException("Network error fetching GitHub PR comments: " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("Interrupted while fetching GitHub PR comments", e);
        }
    }

    /**
     * Creates a new comment on a pull request issue thread.
     *
     * @param repo     repository in "owner/repo" format
     * @param prNumber pull request number
     * @param body     markdown comment body
     * @return created GitHubComment
     */
    public GitHubComment createComment(String repo, int prNumber, String body) {
        Objects.requireNonNull(body, "Comment body must not be null");
        String cleanRepo = normalizeRepo(repo);
        String path = String.format("/repos/%s/issues/%d/comments", cleanRepo, prNumber);

        try {
            String jsonPayload = objectMapper.writeValueAsString(Map.of("body", body));
            HttpRequest request = newRequestBuilder(path)
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(jsonPayload))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            int status = response.statusCode();
            if (status == 201 || status == 200) {
                return objectMapper.readValue(response.body(), GitHubComment.class);
            } else {
                throw new RuntimeException(String.format(
                        "GitHub API POST comment failed [%d]: %s", status, response.body()));
            }
        } catch (IOException e) {
            throw new RuntimeException("Network error creating GitHub PR comment: " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("Interrupted while creating GitHub PR comment", e);
        }
    }

    /**
     * Updates an existing comment by ID on a pull request.
     *
     * @param repo      repository in "owner/repo" format
     * @param commentId comment ID to update
     * @param body      new markdown comment body
     */
    public void updateComment(String repo, long commentId, String body) {
        Objects.requireNonNull(body, "Comment body must not be null");
        String cleanRepo = normalizeRepo(repo);
        String path = String.format("/repos/%s/issues/comments/%d", cleanRepo, commentId);

        try {
            String jsonPayload = objectMapper.writeValueAsString(Map.of("body", body));
            HttpRequest request = newRequestBuilder(path)
                    .header("Content-Type", "application/json")
                    .method("PATCH", HttpRequest.BodyPublishers.ofString(jsonPayload))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            int status = response.statusCode();
            if (status < 200 || status >= 300) {
                throw new RuntimeException(String.format(
                        "GitHub API PATCH comment failed [%d]: %s", status, response.body()));
            }
        } catch (IOException e) {
            throw new RuntimeException("Network error updating GitHub PR comment: " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("Interrupted while updating GitHub PR comment", e);
        }
    }

    public String getToken() {
        return token;
    }

    public String getBaseUrl() {
        return baseUrl;
    }

    public HttpClient getHttpClient() {
        return httpClient;
    }
}
