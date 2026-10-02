package com.sentinelpr.benchmark.cases.sec006;

import java.io.File;

public class AdvSec006FixedResourceSafe {

    public File getStaticSystemConfig() {
        // SAFE: Hardcoded static application asset path
        return new File("/etc/sentinel/defaults.conf");
    }
}
