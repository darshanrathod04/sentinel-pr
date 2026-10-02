package com.sentinelpr.benchmark.realistic.sec006_03;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

@RestController
public class AssetDeliveryController {

    private final AssetDeliveryService assetService;

    public AssetDeliveryController(AssetDeliveryService assetService) {
        this.assetService = assetService;
    }

    @GetMapping("/api/assets/load")
    public String loadAsset(@RequestParam("assetName") String assetName) throws IOException {
        File file = assetService.loadAsset(assetName);
        FileInputStream fis = new FileInputStream(file);
        byte[] bytes = fis.readAllBytes();
        return new String(bytes);
    }
}
