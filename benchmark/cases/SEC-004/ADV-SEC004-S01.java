package com.sentinelpr.benchmark.cases.sec004;

import java.io.File;
import java.io.IOException;
import java.util.List;

public class AdvSec004ProcessBuilderSafe {

    public Process executeFixedSystemCheck() throws IOException {
        // SAFE: ProcessBuilder with fixed, isolated argument list without shell invocation
        ProcessBuilder pb = new ProcessBuilder(List.of("/usr/bin/uptime"));
        pb.directory(new File("/tmp"));
        return pb.start();
    }
}
