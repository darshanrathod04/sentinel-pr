package com.sentinelpr.benchmark.cases.arch001.vulnerable;

import org.springframework.stereotype.Service;

@Service
public class CyclicServiceA {

    // INTENTIONAL VULNERABILITY: Cyclic dependency with CyclicServiceB
    private CyclicServiceB serviceB;

    public void setServiceB(CyclicServiceB serviceB) {
        this.serviceB = serviceB;
    }

    public void processA() {
        if (serviceB != null) {
            serviceB.processB();
        }
    }
}
