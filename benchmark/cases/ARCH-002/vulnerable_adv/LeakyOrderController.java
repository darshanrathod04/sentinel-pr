package com.sentinelpr.benchmark.cases.arch002.vulnerable_adv;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LeakyOrderController {

    // ADVERSARIAL VULNERABILITY: Endpoint leaks OrderEntity domain model
    @GetMapping("/api/v1/orders/recent")
    public OrderEntity getRecentOrder() {
        return new OrderEntity(101L, "SKU-9900");
    }
}
