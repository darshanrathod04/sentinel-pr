package com.sentinelpr.benchmark.realistic.sec004_01;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import java.io.IOException;

@RestController
public class DeploymentWebhookController {

    private final GitOpsDeploymentService deploymentService;

    public DeploymentWebhookController(GitOpsDeploymentService deploymentService) {
        this.deploymentService = deploymentService;
    }

    @PostMapping("/api/deploy/gitops")
    public String handleWebhook(@RequestParam("branch") String branch) throws IOException {
        deploymentService.executeGitPull(branch);
        return "TRIGGERED";
    }
}
