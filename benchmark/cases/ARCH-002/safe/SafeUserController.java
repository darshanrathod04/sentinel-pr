package com.sentinelpr.benchmark.cases.arch002.safe;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SafeUserController {

    // SAFE: Endpoint returns encapsulated UserDto
    @GetMapping("/api/v1/user")
    public UserDto getUserProfile() {
        return new UserDto(1L, "Alice");
    }
}
