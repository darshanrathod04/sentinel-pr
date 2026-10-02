package com.sentinelpr.benchmark.cases.sec002;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

public class AdvSec002TryFinallySafe {

    public int countBytes(File file) throws IOException {
        // SAFE: Stream closed deterministically in finally block
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(file);
            int total = 0;
            int b;
            while ((b = fis.read()) != -1) {
                total++;
            }
            return total;
        } finally {
            if (fis != null) {
                fis.close();
            }
        }
    }
}
