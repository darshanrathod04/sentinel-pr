package com.sentinelpr.github.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Objects;

/**
 * <b>GitHubComment</b>
 *
 * <p>Represents a GitHub Pull Request / Issue comment.</p>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class GitHubComment {

    @JsonProperty("id")
    private long id;

    @JsonProperty("body")
    private String body;

    @JsonProperty("html_url")
    private String htmlUrl;

    @JsonProperty("url")
    private String url;

    @JsonProperty("user")
    private GitHubUser user;

    @JsonProperty("created_at")
    private String createdAt;

    @JsonProperty("updated_at")
    private String updatedAt;

    public GitHubComment() {
    }

    public GitHubComment(long id, String body) {
        this(id, body, null, null, null, null, null);
    }

    public GitHubComment(long id, String body, String htmlUrl, String url, GitHubUser user, String createdAt, String updatedAt) {
        this.id = id;
        this.body = body;
        this.htmlUrl = htmlUrl;
        this.url = url;
        this.user = user;
        this.createdAt = createdAt;
        this.updatedAt = updatedAt;
    }

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public String getBody() {
        return body;
    }

    public void setBody(String body) {
        this.body = body;
    }

    public String getHtmlUrl() {
        return htmlUrl;
    }

    public void setHtmlUrl(String htmlUrl) {
        this.htmlUrl = htmlUrl;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public GitHubUser getUser() {
        return user;
    }

    public void setUser(GitHubUser user) {
        this.user = user;
    }

    public String getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(String createdAt) {
        this.createdAt = createdAt;
    }

    public String getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(String updatedAt) {
        this.updatedAt = updatedAt;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof GitHubComment that)) return false;
        return id == that.id;
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }

    @Override
    public String toString() {
        return "GitHubComment{" +
                "id=" + id +
                ", body='" + (body != null ? (body.length() > 30 ? body.substring(0, 30) + "..." : body) : "") + '\'' +
                ", htmlUrl='" + htmlUrl + '\'' +
                '}';
    }
}
