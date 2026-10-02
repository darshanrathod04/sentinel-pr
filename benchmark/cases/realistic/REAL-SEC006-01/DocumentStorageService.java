package com.sentinelpr.benchmark.realistic.sec006_01;

import org.springframework.stereotype.Service;
import java.io.File;
import java.io.IOException;

@Service
public class DocumentStorageService {

    private final FileSystemStorageUtil storageUtil;

    public DocumentStorageService(FileSystemStorageUtil storageUtil) {
        this.storageUtil = storageUtil;
    }

    public File retrieveDocument(String fileName) throws IOException {
        return storageUtil.resolveDocumentFile(fileName);
    }
}
