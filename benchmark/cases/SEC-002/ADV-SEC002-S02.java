package com.sentinelpr.benchmark.cases.sec002;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

public class AdvSec002MultiTryWithResourcesSafe {

    public void transferFile(File src, File dest) throws IOException {
        // SAFE: Multiple resources managed by try-with-resources statement
        try (FileInputStream in = new FileInputStream(src);
             FileOutputStream out = new FileOutputStream(dest)) {
            byte[] buf = new byte[2048];
            int n;
            while ((n = in.read(buf)) > 0) {
                out.write(buf, 0, n);
            }
        }
    }
}
