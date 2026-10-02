package com.sentinelpr.benchmark.cases.sec006;

import java.io.File;
import java.io.IOException;

public class Sec006PathTraversalVulnerable {

    public File resolveReport(File baseDir, String reportName) throws IOException {
        // INTENTIONAL VULNERABILITY: Unvalidated path construction from dynamic parameter
        File file = new File(baseDir, reportName);
        return file;
    }
}
