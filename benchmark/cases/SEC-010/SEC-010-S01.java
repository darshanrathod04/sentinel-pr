package com.sentinelpr.benchmark.cases.sec010;

import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
// SAFE: Explicit trusted origin whitelist
@CrossOrigin(origins = "https://app.example.com")
public class Sec010PermissiveCorsSafe {

    @GetMapping("/api/accounts")
    public String getAccounts() {
        return "sensitive-account-data";
    }
}
