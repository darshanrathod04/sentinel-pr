package com.sentinelpr.benchmark.realistic.sec005_03;

import org.springframework.stereotype.Service;

@Service
public class InventoryQueryService {

    private final InventoryQueryHelper queryHelper;

    public InventoryQueryService(InventoryQueryHelper queryHelper) {
        this.queryHelper = queryHelper;
    }

    public int getStockCount(String sku) {
        return queryHelper.retrieveCountForSku(sku);
    }
}
