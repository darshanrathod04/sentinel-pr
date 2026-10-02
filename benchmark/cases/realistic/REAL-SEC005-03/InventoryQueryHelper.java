package com.sentinelpr.benchmark.realistic.sec005_03;

import org.springframework.stereotype.Component;

@Component
public class InventoryQueryHelper {

    private final InventoryRepository repository;

    public InventoryQueryHelper(InventoryRepository repository) {
        this.repository = repository;
    }

    public int retrieveCountForSku(String sku) {
        return repository.findItemBySku(sku);
    }
}
