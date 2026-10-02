package com.sentinelpr.benchmark.cases.sec008;

public class AdvSec008AwsKeyVulnerable {

    // INTENTIONAL VULNERABILITY: Embedded AWS credential
    private String aws_access_key = "AKIAIOSFODNN7EXAMPLE";

    public String getAwsAccessKey() {
        return aws_access_key;
    }
}
