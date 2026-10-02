package com.sentinelpr.benchmark.cases.sec002;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

public class AdvSec002SimpleUnclosedVulnerable {

    public void writePayload(File destinationFile, byte[] data) throws IOException {
        // INTENTIONAL VULNERABILITY: FileOutputStream opened without try-with-resources
        FileOutputStream fos = new FileOutputStream(destinationFile);
        fos.write(data);
        fos.flush();
    }
}
