package com.sentinelpr.benchmark.cases.sec001;

public class AdvSec001NonSecurityFallbackSafe {

    public double calculateShippingCost(double weightKg) {
        try {
            if (weightKg <= 0) {
                throw new IllegalArgumentException("Weight must be positive");
            }
            return weightKg * 4.5;
        } catch (Exception e) {
            // SAFE: Legitimate business calculation fallback
            return 15.0;
        }
    }
}
