package com.sentinelpr.fixture.coupled;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST Controller endpoint consuming CoupledService and exposing UserEntity.
 */
@RestController
public class CoupledController {

    private final CoupledService coupledService;

    public CoupledController(CoupledService coupledService) {
        this.coupledService = coupledService;
    }

    // ARCH-002: Leaky abstraction exposing database UserEntity in endpoint
    @GetMapping("/api/v1/users/{id}")
    public UserEntity getUser(@PathVariable("id") String id) {
        return coupledService.getUser(id);
    }

    @GetMapping("/api/v1/auth/check/{id}")
    public boolean authorizeUser(@PathVariable("id") String userId) {
        return coupledService.checkUserAuthorization(userId);
    }
}
