package com.sentinelpr.benchmark.cases.arch003;

import org.springframework.stereotype.Service;

@Service
public class AdvArch003MathRandomVulnerable {

    public double calculateDynamicDiscount() {
        // ADVERSARIAL VULNERABILITY: Direct Math.random() invocation in Spring @Service
        return Math.random() * 0.15;
    }
}
