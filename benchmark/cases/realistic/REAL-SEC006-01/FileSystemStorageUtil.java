package com.sentinelpr.benchmark.realistic.sec006_01;

import java.io.File;
import java.io.IOException;

public class FileSystemStorageUtil {

    private final File baseDir = new File("/var/app/documents");

    public File resolveDocumentFile(String fileName) throws IOException {
        File file = new File(baseDir, fileName);
        return file;
    }
}
