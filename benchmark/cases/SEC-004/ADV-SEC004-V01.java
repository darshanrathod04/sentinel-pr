package com.sentinelpr.benchmark.cases.sec004;

import java.io.IOException;

public class AdvSec004SubprocessConcatVulnerable {

    public void launchBackup(String tenantIdentifier) throws IOException {
        // ADVERSARIAL VULNERABILITY: Runtime.exec with concatenated tenant identifier
        Runtime.getRuntime().exec("sh /usr/local/bin/backup-tenant.sh " + tenantIdentifier);
    }
}
