package com.sentinelpr.benchmark.cases.arch002.vulnerable_adv;

public class OrderEntity {

    private Long orderId;
    private String sku;

    public OrderEntity(Long orderId, String sku) {
        this.orderId = orderId;
        this.sku = sku;
    }

    public Long getOrderId() {
        return orderId;
    }

    public String getSku() {
        return sku;
    }
}
