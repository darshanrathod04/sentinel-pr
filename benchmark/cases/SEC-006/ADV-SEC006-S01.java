package com.sentinelpr.benchmark.cases.sec006;

import java.io.File;
import java.io.IOException;

public class AdvSec006SafeContainmentCheckSafe {

    public File getSafeReport(File baseDir, String reportName) throws IOException {
        // SAFE: Strict normalization and containment verification against baseDir
        File file = new File(baseDir, reportName).getCanonicalFile();
        if (!file.toPath().startsWith(baseDir.toPath().normalize())) {
            throw new SecurityException("Path traversal attempt detected");
        }
        return file;
    }
}
