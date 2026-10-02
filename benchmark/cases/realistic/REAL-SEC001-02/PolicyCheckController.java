package com.sentinelpr.benchmark.realistic.sec001_02;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class PolicyCheckController {

    private final PolicyEvaluationService policyService;

    public PolicyCheckController(PolicyEvaluationService policyService) {
        this.policyService = policyService;
    }

    @GetMapping("/api/policy/evaluate")
    public boolean checkPolicy(@RequestParam("role") String role) {
        return policyService.isRoleAuthorized(role);
    }
}
