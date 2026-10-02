package com.sentinelpr.benchmark.realistic.sec006_03;

import org.springframework.stereotype.Service;
import java.io.File;
import java.io.IOException;

@Service
public class AssetDeliveryService {

    private final File baseDir = new File("/var/app/assets");

    public File loadAsset(String assetName) throws IOException {
        File file = new File(baseDir, assetName);
        return file;
    }
}
