package com.sentinelpr.benchmark.realistic.sec001_01;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AccessGateController {

    private final TokenAuthenticationService authService;

    public AccessGateController(TokenAuthenticationService authService) {
        this.authService = authService;
    }

    @GetMapping("/api/gate/check")
    public boolean checkGateAccess(@RequestParam("token") String token) {
        return authService.authenticateToken(token);
    }
}
