package com.sentinelpr.benchmark.realistic.arch002_02;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ProductCatalogController {

    @GetMapping("/api/products/{sku}")
    public ProductDto getProduct(@PathVariable String sku) {
        return new ProductDto(sku, "Enterprise Server", 1999.99);
    }
}
