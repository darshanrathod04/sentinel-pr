package com.sentinelpr.benchmark.realistic.sec008_01;

import java.sql.Connection;
import java.sql.SQLException;

public class PaymentGatewayClient {

    private final PaymentGatewayConfig config;

    public PaymentGatewayClient(PaymentGatewayConfig config) {
        this.config = config;
    }

    public boolean checkConnectionHealth() {
        try (Connection conn = config.getPaymentConnection()) {
            return conn != null && !conn.isClosed();
        } catch (SQLException e) {
            return false;
        }
    }
}
