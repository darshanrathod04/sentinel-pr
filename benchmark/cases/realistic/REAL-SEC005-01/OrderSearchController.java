package com.sentinelpr.benchmark.realistic.sec005_01;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import java.util.List;

@RestController
public class OrderSearchController {

    private final OrderSearchService searchService;

    public OrderSearchController(OrderSearchService searchService) {
        this.searchService = searchService;
    }

    @GetMapping("/api/orders/search")
    public List<String> searchOrders(@RequestParam("customerId") String customerId) {
        if (customerId == null || customerId.isBlank()) {
            return List.of();
        }
        return searchService.findOrdersByCustomer(customerId);
    }
}
