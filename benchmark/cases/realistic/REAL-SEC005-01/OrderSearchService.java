package com.sentinelpr.benchmark.realistic.sec005_01;

import org.springframework.stereotype.Service;
import java.util.List;

@Service
public class OrderSearchService {

    private final OrderJdbcRepository repository;

    public OrderSearchService(OrderJdbcRepository repository) {
        this.repository = repository;
    }

    public List<String> findOrdersByCustomer(String customerId) {
        return repository.searchByCustomer(customerId);
    }
}
