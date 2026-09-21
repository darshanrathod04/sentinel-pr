package com.sentinelpr.core.analysis.causal;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * <b>CausalChain</b>
 *
 * <p>Structured representation of a multi-hop causal reasoning chain explaining
 * how a root trigger propagates into a weaponizable exploit scenario and business impact.</p>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CausalChain {

    public enum BlastRadius {
        LOCAL_METHOD,
        SERVICE_COMPONENT,
        TENANT_DATA,
        SYSTEM_WIDE
    }

    private final String trigger;
    private final String rootCauseElement;
    private final List<String> propagationHops;
    private final String exploitVector;
    private final String businessImpact;
    private final BlastRadius blastRadius;
    private final boolean activelyReachable;

    @JsonCreator
    public CausalChain(
            @JsonProperty("trigger") String trigger,
            @JsonProperty("rootCauseElement") String rootCauseElement,
            @JsonProperty("propagationHops") List<String> propagationHops,
            @JsonProperty("exploitVector") String exploitVector,
            @JsonProperty("businessImpact") String businessImpact,
            @JsonProperty("blastRadius") BlastRadius blastRadius,
            @JsonProperty("activelyReachable") boolean activelyReachable
    ) {
        this.trigger = trigger != null ? trigger : "Untrusted User Input / Unverified State";
        this.rootCauseElement = rootCauseElement != null ? rootCauseElement : "Unknown AST Element";
        this.propagationHops = propagationHops != null
                ? Collections.unmodifiableList(new ArrayList<>(propagationHops))
                : List.of();
        this.exploitVector = exploitVector != null ? exploitVector : "";
        this.businessImpact = businessImpact != null ? businessImpact : "";
        this.blastRadius = blastRadius != null ? blastRadius : BlastRadius.SERVICE_COMPONENT;
        this.activelyReachable = activelyReachable;
    }

    public static Builder builder() {
        return new Builder();
    }

    public String getTrigger() {
        return trigger;
    }

    public String getRootCauseElement() {
        return rootCauseElement;
    }

    public List<String> getPropagationHops() {
        return propagationHops;
    }

    public String getExploitVector() {
        return exploitVector;
    }

    public String getBusinessImpact() {
        return businessImpact;
    }

    public BlastRadius getBlastRadius() {
        return blastRadius;
    }

    public boolean isActivelyReachable() {
        return activelyReachable;
    }

    @Override
    public String toString() {
        return "CausalChain{" +
                "trigger='" + trigger + '\'' +
                ", rootCauseElement='" + rootCauseElement + '\'' +
                ", hops=" + propagationHops.size() +
                ", blastRadius=" + blastRadius +
                ", activelyReachable=" + activelyReachable +
                '}';
    }

    public static class Builder {
        private String trigger;
        private String rootCauseElement;
        private final List<String> propagationHops = new ArrayList<>();
        private String exploitVector;
        private String businessImpact;
        private BlastRadius blastRadius = BlastRadius.SERVICE_COMPONENT;
        private boolean activelyReachable = false;

        public Builder trigger(String trigger) {
            this.trigger = trigger;
            return this;
        }

        public Builder rootCauseElement(String rootCauseElement) {
            this.rootCauseElement = rootCauseElement;
            return this;
        }

        public Builder addHop(String hop) {
            if (hop != null && !hop.isBlank()) {
                this.propagationHops.add(hop);
            }
            return this;
        }

        public Builder propagationHops(List<String> hops) {
            this.propagationHops.clear();
            if (hops != null) {
                this.propagationHops.addAll(hops);
            }
            return this;
        }

        public Builder exploitVector(String exploitVector) {
            this.exploitVector = exploitVector;
            return this;
        }

        public Builder businessImpact(String businessImpact) {
            this.businessImpact = businessImpact;
            return this;
        }

        public Builder blastRadius(BlastRadius blastRadius) {
            this.blastRadius = blastRadius;
            return this;
        }

        public Builder activelyReachable(boolean activelyReachable) {
            this.activelyReachable = activelyReachable;
            return this;
        }

        public CausalChain build() {
            return new CausalChain(trigger, rootCauseElement, propagationHops, exploitVector, businessImpact, blastRadius, activelyReachable);
        }
    }
}
