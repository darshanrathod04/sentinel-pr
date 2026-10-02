package com.sentinelpr.benchmark.cases.arch002.vulnerable;

public class UserEntity {

    private Long id;
    private String username;

    public UserEntity(Long id, String username) {
        this.id = id;
        this.username = username;
    }

    public Long getId() {
        return id;
    }

    public String getUsername() {
        return username;
    }
}
