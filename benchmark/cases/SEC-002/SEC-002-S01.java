package com.sentinelpr.benchmark.cases.sec002;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

public class Sec002UnclosedStreamSafe {

    public int countBytes(File file) throws IOException {
        // SAFE: Stream enclosed in try-with-resources
        try (FileInputStream fis = new FileInputStream(file)) {
            int total = 0;
            int b;
            while ((b = fis.read()) != -1) {
                total++;
            }
            return total;
        }
    }
}
