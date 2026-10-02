package com.sentinelpr.benchmark.cases.arch002.safe_adv;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SafeOrderController {

    // SAFE: Encapsulated DTO return type
    @GetMapping("/api/v1/orders/recent")
    public OrderDto getRecentOrder() {
        return new OrderDto(101L, "SKU-9900");
    }
}
