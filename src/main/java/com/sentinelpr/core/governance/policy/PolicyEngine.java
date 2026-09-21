package com.sentinelpr.core.governance.policy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.sentinelpr.core.model.ReviewReport;
import com.sentinelpr.core.model.SecurityFinding;
import com.sentinelpr.core.model.Severity;
import com.sentinelpr.core.model.UnifiedDiffPatch;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * <b>PolicyEngine</b>
 *
 * <p>Deterministic enterprise governance engine enforcing security defect thresholds,
 * blocked rules, and patch verification requirements.</p>
 */
public class PolicyEngine {

    private final ObjectMapper objectMapper;

    public PolicyEngine() {
        this.objectMapper = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .enable(SerializationFeature.INDENT_OUTPUT);
    }

    public PolicyEngine(ObjectMapper objectMapper) {
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper must not be null");
    }

    /**
     * Evaluates a security review report against an enterprise policy.
     */
    public PolicyEvaluationResult evaluate(ReviewReport report, SentinelPolicy policy) {
        Objects.requireNonNull(report, "report must not be null");
        SentinelPolicy effectivePolicy = policy != null ? policy : SentinelPolicy.createDefaultStrictPolicy();

        int criticalCount = 0;
        int highCount = 0;
        int mediumCount = 0;
        int lowCount = 0;
        int blockedCount = 0;

        List<String> violations = new ArrayList<>();

        // Priority 1: Check blockedRules FIRST across ALL findings (active AND suppressed/baseline debt)
        // Policy Supremacy: Blocked rules CANNOT be suppressed by baseline debt.
        for (SecurityFinding f : report.getFindings()) {
            String ruleId = f.getRule().getRuleId();
            if (effectivePolicy.getBlockedRules().contains(ruleId)) {
                blockedCount++;
                violations.add(String.format(
                        "Policy breach: Finding violates strictly blocked rule [%s] in %s (lines %d-%d): %s (BLOCKED_BY_POLICY)",
                        ruleId, f.getTargetFile(), f.getStartLine(), f.getEndLine(), f.getDescription()
                ));
            }
        }

        for (com.sentinelpr.core.model.SuppressedFinding sf : report.getSuppressedFindings()) {
            SecurityFinding f = sf.getFinding();
            String ruleId = f.getRule().getRuleId();
            if (effectivePolicy.getBlockedRules().contains(ruleId)) {
                blockedCount++;
                violations.add(String.format(
                        "Policy breach: Finding present in baseline debt violates strictly blocked rule [%s] in %s (lines %d-%d): %s (BLOCKED_BY_POLICY: Baseline cannot suppress blocked rules)",
                        ruleId, f.getTargetFile(), f.getStartLine(), f.getEndLine(), f.getDescription()
                ));
            }
        }

        // Priority 2: Severity defect counts on active findings
        for (SecurityFinding f : report.getFindings()) {
            Severity sev = f.getSeverity();
            if (sev == Severity.CRITICAL) {
                criticalCount++;
            } else if (sev == Severity.HIGH) {
                highCount++;
            } else if (sev == Severity.MEDIUM) {
                mediumCount++;
            } else if (sev == Severity.LOW || sev == Severity.INFO) {
                lowCount++;
            }
        }

        // Check Critical threshold
        if (effectivePolicy.getMaxAllowedCritical() >= 0 && criticalCount > effectivePolicy.getMaxAllowedCritical()) {
            violations.add(String.format(
                    "Policy breach: Found %d CRITICAL finding(s), maximum allowed by '%s' is %d.",
                    criticalCount, effectivePolicy.getPolicyName(), effectivePolicy.getMaxAllowedCritical()
            ));
        }

        // Check High threshold
        if (effectivePolicy.getMaxAllowedHigh() >= 0 && highCount > effectivePolicy.getMaxAllowedHigh()) {
            violations.add(String.format(
                    "Policy breach: Found %d HIGH finding(s), maximum allowed by '%s' is %d.",
                    highCount, effectivePolicy.getPolicyName(), effectivePolicy.getMaxAllowedHigh()
            ));
        }

        // Check Medium threshold
        if (effectivePolicy.getMaxAllowedMedium() >= 0 && mediumCount > effectivePolicy.getMaxAllowedMedium()) {
            violations.add(String.format(
                    "Policy breach: Found %d MEDIUM finding(s), maximum allowed by '%s' is %d.",
                    mediumCount, effectivePolicy.getPolicyName(), effectivePolicy.getMaxAllowedMedium()
            ));
        }

        // Check Unverified Patches
        int unverifiedPatchCount = 0;
        if (effectivePolicy.isFailOnUnverifiedPatch()) {
            for (UnifiedDiffPatch patch : report.getPatches()) {
                if (!patch.isVerified() || patch.getStatus() != UnifiedDiffPatch.Status.SUCCESS) {
                    unverifiedPatchCount++;
                    violations.add(String.format(
                            "Policy breach: Synthesized patch for finding [%s] (rule %s) is unverified or failed: %s",
                            patch.getFindingId(), patch.getRuleId(), patch.getVerificationMessage()
                    ));
                }
            }
        }

        if (violations.isEmpty()) {
            if (report.getSuppressedCount() > 0) {
                String summary = String.format(
                        "Enterprise policy '%s' PASSED WITH BASELINE. Zero new active defects; %d technical debt item(s) accepted in baseline.",
                        effectivePolicy.getPolicyName(), report.getSuppressedCount()
                );
                return PolicyEvaluationResult.passedWithBaseline(
                        effectivePolicy.getPolicyName(),
                        criticalCount,
                        highCount,
                        mediumCount,
                        report.getSuppressedCount(),
                        summary
                );
            } else {
                String summary = String.format(
                        "Enterprise policy '%s' PASSED. All defect counts and rules are within permitted thresholds.",
                        effectivePolicy.getPolicyName()
                );
                return PolicyEvaluationResult.passed(
                        effectivePolicy.getPolicyName(),
                        criticalCount,
                        highCount,
                        mediumCount,
                        summary
                );
            }
        } else {
            String summary = String.format(
                    "Enterprise policy '%s' BREACHED with %d violation(s) (%d blocked by policy). Audit gate failed.",
                    effectivePolicy.getPolicyName(),
                    violations.size(),
                    blockedCount
            );
            return PolicyEvaluationResult.breached(
                    effectivePolicy.getPolicyName(),
                    violations,
                    criticalCount,
                    highCount,
                    mediumCount,
                    unverifiedPatchCount,
                    blockedCount,
                    summary
            );
        }
    }

    /**
     * Loads a policy from disk.
     */
    public SentinelPolicy loadPolicy(Path policyPath) throws IOException {
        Objects.requireNonNull(policyPath, "policyPath must not be null");
        if (!Files.exists(policyPath)) {
            throw new IllegalArgumentException("Policy configuration file not found: " + policyPath);
        }
        return objectMapper.readValue(policyPath.toFile(), SentinelPolicy.class);
    }

    /**
     * Loads a policy from JSON string.
     */
    public SentinelPolicy loadPolicyFromString(String json) {
        try {
            return objectMapper.readValue(json, SentinelPolicy.class);
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse policy configuration: " + e.getMessage(), e);
        }
    }
}
