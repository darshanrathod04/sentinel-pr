package com.sentinelpr.benchmark.cases.sec006;

import java.io.IOException;
import java.nio.file.Path;

public class AdvSec006MultiSegmentVulnerable {

    public Path buildUserReportPath(String baseDirectory, String userFolder) throws IOException {
        // INTENTIONAL VULNERABILITY: Path.of multi-segment resolution without boundary checks
        Path reportPath = Path.of(baseDirectory, userFolder);
        return reportPath;
    }
}
