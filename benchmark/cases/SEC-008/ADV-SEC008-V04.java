package com.sentinelpr.benchmark.cases.sec008;

public class AdvSec008ClientSecretVulnerable {

    // INTENTIONAL VULNERABILITY: Embedded client secret token
    private String client_secret = "cs_live_49f82b71903e481b8273910385920194";

    public String getClientSecret() {
        return client_secret;
    }
}
