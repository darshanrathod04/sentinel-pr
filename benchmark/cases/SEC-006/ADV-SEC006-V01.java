package com.sentinelpr.benchmark.cases.sec006;

import java.io.File;
import java.io.IOException;

public class AdvSec006UnixTraversalVulnerable {

    public File accessDocument(File storageDir, String documentKey) throws IOException {
        // INTENTIONAL VULNERABILITY: User-provided document key concatenated without containment validation
        File file = new File(storageDir, documentKey);
        return file;
    }
}
