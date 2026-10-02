package com.sentinelpr.benchmark.cases.sec006;

import java.io.File;
import java.io.IOException;

public class AdvSec006EncodedTraversalVulnerable {

    public File retrieveAttachment(File baseFolder, String attachmentPath) throws IOException {
        // INTENTIONAL VULNERABILITY: Raw attachment path resolved against base folder
        File resolvedFile = new File(baseFolder, attachmentPath);
        return resolvedFile;
    }
}
