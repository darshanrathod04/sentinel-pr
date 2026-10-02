package com.sentinelpr.benchmark.realistic.arch001_01;

import org.springframework.stereotype.Service;

@Service
public class OrderFulfillmentService {

    private final CustomerBillingService billingService;

    public OrderFulfillmentService(CustomerBillingService billingService) {
        this.billingService = billingService;
    }

    public boolean fulfillOrder(String orderId) {
        return billingService.chargeCustomerForOrder(orderId);
    }
}
