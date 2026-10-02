package com.sentinelpr.benchmark.realistic.sec005_03;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class InventoryQueryController {

    private final InventoryQueryService queryService;

    public InventoryQueryController(InventoryQueryService queryService) {
        this.queryService = queryService;
    }

    @GetMapping("/api/inventory/check")
    public int checkStock(@RequestParam("sku") String sku) {
        return queryService.getStockCount(sku);
    }
}
