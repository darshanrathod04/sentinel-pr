package com.sentinelpr.benchmark.cases.xfile.sql01;

import org.springframework.stereotype.Service;
import java.sql.SQLException;
import java.util.List;

@Service
public class OrderQueryService {

    private final OrderDynamicRepository repository;

    public OrderQueryService(OrderDynamicRepository repository) {
        this.repository = repository;
    }

    public List<String> findOrders(String rawQuery) throws SQLException {
        return repository.executeOrderQuery("status = 'COMPLETED' AND " + rawQuery);
    }
}
