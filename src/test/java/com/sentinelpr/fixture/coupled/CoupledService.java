package com.sentinelpr.fixture.coupled;

import org.springframework.stereotype.Service;

import java.util.Random;

/**
 * Service component coupled with CoupledRepository and consumed by CoupledController.
 */
@Service
public class CoupledService {

    private final CoupledRepository repository;

    public CoupledService(CoupledRepository repository) {
        this.repository = repository;
    }

    // ARCH-003: Direct System.currentTimeMillis() and Random in business service
    public long recordAuditTimestamp() {
        long current = System.currentTimeMillis();
        Random rnd = new Random();
        return current + rnd.nextInt(100);
    }

    // Provider method returning UserEntity directly
    public UserEntity getUser(String id) {
        return repository.findById(id).orElse(null);
    }

    // SEC-001: Fail-open security block
    public boolean checkUserAuthorization(String userId) {
        try {
            if (userId == null) {
                throw new NullPointerException("User ID must not be null");
            }
            return userId.startsWith("admin-");
        } catch (NullPointerException e) {
            // VULNERABLE: Fail-open returns true
            return true;
        }
    }
}
