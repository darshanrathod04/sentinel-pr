package com.sentinelpr.benchmark.realistic.arch002_01;

public record CustomerDto(Long id, String name, String email) {
    public static CustomerDto fromEntity(CustomerEntity entity) {
        return new CustomerDto(entity.getId(), entity.getName(), entity.getEmail());
    }
}
