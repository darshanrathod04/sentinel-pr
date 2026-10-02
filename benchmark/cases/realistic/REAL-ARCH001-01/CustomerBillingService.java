package com.sentinelpr.benchmark.realistic.arch001_01;

import org.springframework.stereotype.Service;

@Service
public class CustomerBillingService {

    private final OrderFulfillmentService fulfillmentService;

    public CustomerBillingService(OrderFulfillmentService fulfillmentService) {
        this.fulfillmentService = fulfillmentService;
    }

    public boolean chargeCustomerForOrder(String orderId) {
        return fulfillmentService != null;
    }
}
