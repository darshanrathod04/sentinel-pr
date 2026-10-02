package com.sentinelpr.benchmark.cases.arch002.vulnerable;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LeakyUserController {

    // INTENTIONAL VULNERABILITY: Endpoint returns database UserEntity directly
    @GetMapping("/api/v1/user")
    public UserEntity getUserProfile() {
        return new UserEntity(1L, "Alice");
    }
}
