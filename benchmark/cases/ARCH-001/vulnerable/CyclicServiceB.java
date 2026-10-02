package com.sentinelpr.benchmark.cases.arch001.vulnerable;

import org.springframework.stereotype.Service;

@Service
public class CyclicServiceB {

    // INTENTIONAL VULNERABILITY: Cyclic dependency back to CyclicServiceA
    private CyclicServiceA serviceA;

    public void setServiceA(CyclicServiceA serviceA) {
        this.serviceA = serviceA;
    }

    public void processB() {
        if (serviceA != null) {
            serviceA.processA();
        }
    }
}
