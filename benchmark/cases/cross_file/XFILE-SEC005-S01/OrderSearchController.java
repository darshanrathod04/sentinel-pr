package com.sentinelpr.benchmark.cases.xfile.sql01_safe;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import java.sql.SQLException;
import java.util.List;

@RestController
public class OrderSearchController {

    private final OrderQueryService queryService;

    public OrderSearchController(OrderQueryService queryService) {
        this.queryService = queryService;
    }

    @GetMapping("/api/v2/orders/search")
    public List<String> searchOrders(@RequestParam("preset") String preset) throws SQLException {
        return queryService.findOrdersByPreset(preset);
    }
}
