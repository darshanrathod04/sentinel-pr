package com.sentinelpr.benchmark.cases.arch002.safe;

public class UserDto {

    private Long id;
    private String username;

    public UserDto(Long id, String username) {
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
