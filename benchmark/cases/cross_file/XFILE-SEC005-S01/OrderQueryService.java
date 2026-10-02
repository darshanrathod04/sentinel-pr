package com.sentinelpr.benchmark.cases.xfile.sql01_safe;

import org.springframework.stereotype.Service;
import java.sql.SQLException;
import java.util.List;

@Service
public class OrderQueryService {

    private final OrderDynamicRepository repository;

    public OrderQueryService(OrderDynamicRepository repository) {
        this.repository = repository;
    }

    public List<String> findOrdersByPreset(String preset) throws SQLException {
        if ("RECENT".equals(preset)) {
            return repository.executeOrderQuery("status = 'COMPLETED' AND created_at >= CURRENT_DATE - 7");
        } else if ("PRIORITY".equals(preset)) {
            return repository.executeOrderQuery("status = 'COMPLETED' AND priority_level = 'HIGH'");
        } else if ("ARCHIVED".equals(preset)) {
            return repository.executeOrderQuery("status = 'COMPLETED' AND is_archived = 1");
        }
        return List.of();
    }
}
