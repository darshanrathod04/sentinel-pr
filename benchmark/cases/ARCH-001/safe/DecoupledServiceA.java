package com.sentinelpr.benchmark.cases.arch001.safe;

import org.springframework.stereotype.Service;

@Service
public class DecoupledServiceA {

    private DecoupledServiceB serviceB;

    public void setServiceB(DecoupledServiceB serviceB) {
        this.serviceB = serviceB;
    }

    public void processA() {
        if (serviceB != null) {
            serviceB.processB();
        }
    }
}
