package com.sentinelpr.benchmark.cases.sec006;

import java.io.File;

public class Sec006PathTraversalSafe {

    public File resolveReport(File baseDir, String reportName) {
        // SAFE: Strict path normalization and directory containment check
        File file = new File(baseDir, reportName);
        if (!file.toPath().normalize().startsWith(baseDir.toPath().normalize())) {
            throw new SecurityException("Directory traversal attempt detected: " + reportName);
        }
        return file;
    }
}
