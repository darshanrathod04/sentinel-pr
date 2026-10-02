package com.sentinelpr.benchmark.realistic.arch002_01;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CustomerProfileController {

    @GetMapping("/api/customers/{id}")
    public CustomerEntity getCustomerProfile(@PathVariable Long id) {
        return new CustomerEntity(id, "Jane Doe", "jane@example.com");
    }
}
