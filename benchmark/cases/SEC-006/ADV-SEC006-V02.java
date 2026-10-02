package com.sentinelpr.benchmark.cases.sec006;

import java.io.File;
import java.io.IOException;

public class AdvSec006WindowsTraversalVulnerable {

    public File readExport(File rootDirectory, String exportFileName) throws IOException {
        // INTENTIONAL VULNERABILITY: Windows-style directory traversal through dynamic export file
        File targetFile = new File(rootDirectory, exportFileName);
        return targetFile;
    }
}
