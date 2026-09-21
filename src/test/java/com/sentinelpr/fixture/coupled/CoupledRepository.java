package com.sentinelpr.fixture.coupled;

import org.springframework.stereotype.Repository;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Repository providing access to UserEntity records.
 */
@Repository
public class CoupledRepository {

    private final Map<String, UserEntity> storage = new HashMap<>();

    public CoupledRepository() {
        storage.put("usr-001", new UserEntity("usr-001", "dev-lead", "lead@company.com", "hash123", "ADMIN"));
    }

    public Optional<UserEntity> findById(String id) {
        return Optional.ofNullable(storage.get(id));
    }

    public UserEntity save(UserEntity user) {
        if (user != null && user.getId() != null) {
            storage.put(user.getId(), user);
        }
        return user;
    }
}
