package com.sentinelpr.fixture.coupled.cyclic;

public class CyclicComponentB {

    private CyclicComponentA componentA;

    public void setComponentA(CyclicComponentA componentA) {
        this.componentA = componentA;
    }

    public void processB() {
        if (componentA != null) {
            componentA.processA();
        }
    }
}
