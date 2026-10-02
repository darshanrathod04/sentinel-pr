package com.sentinelpr.benchmark.cases.arch001.safe;

import org.springframework.stereotype.Service;

@Service
public class DecoupledServiceB {

    // SAFE: Unidirectional design; zero dependency on DecoupledServiceA
    public void processB() {
        System.out.println("Processing business logic independently");
    }
}
