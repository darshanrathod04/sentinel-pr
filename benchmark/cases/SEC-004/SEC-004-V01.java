package com.sentinelpr.benchmark.cases.sec004;

import java.io.IOException;

public class Sec004SubprocessVulnerable {

    public void executeCommand(String argument) throws IOException {
        // INTENTIONAL VULNERABILITY: Un-isolated Runtime.exec call
        Runtime.getRuntime().exec("sh -c /opt/scripts/run.sh " + argument);
    }
}
