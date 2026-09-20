package com.sentinelpr.core.governance.policy;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * <b>SentinelPolicy</b>
 *
 * <p>Enterprise compliance and audit policy definition.</p>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class SentinelPolicy {

    public static final String DEFAULT_POLICY_NAME = "Enterprise-Strict-Security-Policy";
    public static final String DEFAULT_VERSION = "1.0";

    private final String policyName;
    private final String version;
    private final int maxAllowedCritical;
    private final int maxAllowedHigh;
    private final int maxAllowedMedium;
    private final int maxAllowedLow;
    private final boolean failOnUnverifiedPatch;
    private final List<String> blockedRules;
    private final List<String> requiredTags;

    public SentinelPolicy() {
        this(DEFAULT_POLICY_NAME, DEFAULT_VERSION, 0, 0, -1, -1, true, List.of(), List.of("OWASP-TOP-10"));
    }

    @JsonCreator
    public SentinelPolicy(
            @JsonProperty("policyName") String policyName,
            @JsonProperty("version") String version,
            @JsonProperty("maxAllowedCritical") Integer maxAllowedCritical,
            @JsonProperty("maxAllowedHigh") Integer maxAllowedHigh,
            @JsonProperty("maxAllowedMedium") Integer maxAllowedMedium,
            @JsonProperty("maxAllowedLow") Integer maxAllowedLow,
            @JsonProperty("failOnUnverifiedPatch") Boolean failOnUnverifiedPatch,
            @JsonProperty("blockedRules") List<String> blockedRules,
            @JsonProperty("requiredTags") List<String> requiredTags
    ) {
        this.policyName = policyName != null ? policyName : DEFAULT_POLICY_NAME;
        this.version = version != null ? version : DEFAULT_VERSION;
        this.maxAllowedCritical = maxAllowedCritical != null ? maxAllowedCritical : 0;
        this.maxAllowedHigh = maxAllowedHigh != null ? maxAllowedHigh : 0;
        this.maxAllowedMedium = maxAllowedMedium != null ? maxAllowedMedium : -1;
        this.maxAllowedLow = maxAllowedLow != null ? maxAllowedLow : -1;
        this.failOnUnverifiedPatch = failOnUnverifiedPatch != null ? failOnUnverifiedPatch : true;
        this.blockedRules = blockedRules != null ? Collections.unmodifiableList(new ArrayList<>(blockedRules)) : List.of();
        this.requiredTags = requiredTags != null ? Collections.unmodifiableList(new ArrayList<>(requiredTags)) : List.of();
    }

    public static SentinelPolicy createDefaultStrictPolicy() {
        return new SentinelPolicy();
    }

    public static SentinelPolicy createPermissivePolicy() {
        return new SentinelPolicy("Permissive-Dev-Policy", "1.0", 10, 10, 20, 50, false, List.of(), List.of());
    }

    public String getPolicyName() {
        return policyName;
    }

    public String getVersion() {
        return version;
    }

    public int getMaxAllowedCritical() {
        return maxAllowedCritical;
    }

    public int getMaxAllowedHigh() {
        return maxAllowedHigh;
    }

    public int getMaxAllowedMedium() {
        return maxAllowedMedium;
    }

    public int getMaxAllowedLow() {
        return maxAllowedLow;
    }

    public boolean isFailOnUnverifiedPatch() {
        return failOnUnverifiedPatch;
    }

    public List<String> getBlockedRules() {
        return blockedRules;
    }

    public List<String> getRequiredTags() {
        return requiredTags;
    }
}
