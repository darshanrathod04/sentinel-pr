package com.sentinelpr.benchmark.cases.sec002;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

public class AdvSec002MultiResourceVulnerable {

    public void copyData(File source, File destination) throws IOException {
        // INTENTIONAL VULNERABILITY: Streams instantiated without try-with-resources
        FileInputStream inStream = new FileInputStream(source);
        FileOutputStream outStream = new FileOutputStream(destination);
        byte[] buffer = new byte[1024];
        int read;
        while ((read = inStream.read(buffer)) != -1) {
            outStream.write(buffer, 0, read);
        }
    }
}
