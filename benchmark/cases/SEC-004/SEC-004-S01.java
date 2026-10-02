package com.sentinelpr.benchmark.cases.sec004;

import java.io.IOException;

public class Sec004SubprocessSafe {

    public Process executeCommand(String argument) throws IOException {
        // SAFE: ProcessBuilder with tokenized argument array
        ProcessBuilder processBuilder = new ProcessBuilder("/opt/scripts/run.sh", argument);
        return processBuilder.start();
    }
}
