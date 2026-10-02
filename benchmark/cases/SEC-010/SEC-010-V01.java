package com.sentinelpr.benchmark.cases.sec010;

import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
// INTENTIONAL VULNERABILITY: Wildcard CORS origin allows arbitrary domains
@CrossOrigin(origins = "*")
public class Sec010PermissiveCorsVulnerable {

    @GetMapping("/api/accounts")
    public String getAccounts() {
        return "sensitive-account-data";
    }
}
