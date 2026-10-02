package com.sentinelpr.benchmark.cases.arch002.vulnerable_adv;

public record OrderDto(Long orderId, String sku) {
    public static OrderDto fromEntity(OrderEntity entity) {
        return new OrderDto(entity.getOrderId(), entity.getSku());
    }
}
