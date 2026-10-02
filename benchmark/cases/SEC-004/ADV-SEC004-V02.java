package com.sentinelpr.benchmark.cases.sec004;

import java.io.IOException;

public class AdvSec004SubprocessArrayVulnerable {

    public void runUserScript(String scriptName, String userArg) throws IOException {
        String[] cmd = new String[]{"/bin/bash", scriptName, userArg};
        // ADVERSARIAL VULNERABILITY: Runtime.getRuntime().exec invoked without isolation
        Runtime.getRuntime().exec(cmd);
    }
}
