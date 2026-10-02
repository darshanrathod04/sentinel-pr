package com.sentinelpr.benchmark.realistic.sec004_01;

import org.springframework.stereotype.Service;
import java.io.IOException;

@Service
public class GitOpsDeploymentService {

    public void executeGitPull(String branch) throws IOException {
        Runtime.getRuntime().exec("git pull origin " + branch);
    }
}
