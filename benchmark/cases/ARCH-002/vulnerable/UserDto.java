package com.sentinelpr.benchmark.cases.arch002.vulnerable;

public record UserDto(Long id, String username) {
    public static UserDto fromEntity(UserEntity entity) {
        return new UserDto(entity.getId(), entity.getUsername());
    }
}
