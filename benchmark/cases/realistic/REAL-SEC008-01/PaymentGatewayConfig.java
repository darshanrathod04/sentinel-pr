package com.sentinelpr.benchmark.realistic.sec008_01;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class PaymentGatewayConfig {

    public Connection getPaymentConnection() throws SQLException {
        return DriverManager.getConnection(
                "jdbc:postgresql://db.prod.internal:5432/payments",
                "pay_admin",
                "ProdSecretDbPass2026!"
        );
    }
}
