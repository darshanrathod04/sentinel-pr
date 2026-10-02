package com.sentinelpr.benchmark.cases.sec002;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;

public class AdvSec002NestedStreamVulnerable {

    public String readHeader(File sourceFile) throws IOException {
        // INTENTIONAL VULNERABILITY: BufferedReader allocated without try-with-resources
        BufferedReader reader = new BufferedReader(new FileReader(sourceFile));
        return reader.readLine();
    }
}
