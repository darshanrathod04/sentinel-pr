package com.sentinelpr.benchmark.realistic.sec004_02;

import org.springframework.stereotype.Service;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.List;

@Service
public class SystemDiagnosticsService {

    public String readSystemUptime() throws IOException, InterruptedException {
        ProcessBuilder processBuilder = new ProcessBuilder(List.of("/usr/bin/uptime"));
        Process process = processBuilder.start();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            String line = reader.readLine();
            process.waitFor();
            return line != null ? line : "N/A";
        }
    }
}
