package com.sentinelpr.fixture.coupled.cyclic;

public class CyclicComponentA {

    private CyclicComponentB componentB;

    public void setComponentB(CyclicComponentB componentB) {
        this.componentB = componentB;
    }

    public void processA() {
        if (componentB != null) {
            componentB.processB();
        }
    }
}
