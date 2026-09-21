package com.sentinelpr.core.model;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.Objects;

/**
 * A concrete security or architectural violation detected during AST inspection and reasoning.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class SecurityFinding {

    private final String id;
    private final SecurityRule rule;
    private final Severity severity;
    private final String targetFile;
    private final String className;
    private final String methodName;
    private final int startLine;
    private final int endLine;
    private final String vulnerableSnippet;
    private final String description;
    private final String causalRationale;
    private final String remediation;
    private final double confidence;
    private final com.sentinelpr.core.analysis.causal.CausalChain causalChain;
    private final ExploitabilityIndex exploitabilityIndex;

    public SecurityFinding(
            String id,
            SecurityRule rule,
            Severity severity,
            String targetFile,
            String className,
            String methodName,
            int startLine,
            int endLine,
            String vulnerableSnippet,
            String description,
            String causalRationale,
            String remediation,
            double confidence
    ) {
        this(id, rule, severity, targetFile, className, methodName, startLine, endLine, vulnerableSnippet, description, causalRationale, remediation, confidence, null, null);
    }

    public SecurityFinding(
            String id,
            SecurityRule rule,
            Severity severity,
            String targetFile,
            String className,
            String methodName,
            int startLine,
            int endLine,
            String vulnerableSnippet,
            String description,
            String causalRationale,
            String remediation,
            double confidence,
            com.sentinelpr.core.analysis.causal.CausalChain causalChain,
            ExploitabilityIndex exploitabilityIndex
    ) {
        this.id = Objects.requireNonNull(id, "id must not be null");
        this.rule = Objects.requireNonNull(rule, "rule must not be null");
        this.severity = severity != null ? severity : rule.getSeverity();
        this.targetFile = targetFile != null ? targetFile : "";
        this.className = className != null ? className : "";
        this.methodName = methodName != null ? methodName : "";
        this.startLine = startLine;
        this.endLine = endLine;
        this.vulnerableSnippet = vulnerableSnippet != null ? vulnerableSnippet : "";
        this.description = description != null ? description : rule.getExplanation();
        this.causalRationale = causalRationale != null ? causalRationale : "";
        this.remediation = remediation != null ? remediation : "";
        this.confidence = confidence;
        this.causalChain = causalChain;
        this.exploitabilityIndex = exploitabilityIndex;
    }

    public String getId() {
        return id;
    }

    public SecurityRule getRule() {
        return rule;
    }

    public Severity getSeverity() {
        return severity;
    }

    public String getTargetFile() {
        return targetFile;
    }

    public String getClassName() {
        return className;
    }

    public String getMethodName() {
        return methodName;
    }

    public int getStartLine() {
        return startLine;
    }

    public int getEndLine() {
        return endLine;
    }

    public String getVulnerableSnippet() {
        return vulnerableSnippet;
    }

    public String getDescription() {
        return description;
    }

    public String getCausalRationale() {
        return causalRationale;
    }

    public String getRemediation() {
        return remediation;
    }

    public double getConfidence() {
        return confidence;
    }

    public com.sentinelpr.core.analysis.causal.CausalChain getCausalChain() {
        return causalChain;
    }

    public ExploitabilityIndex getExploitabilityIndex() {
        return exploitabilityIndex;
    }

    public SecurityFinding withCausalChain(com.sentinelpr.core.analysis.causal.CausalChain chain) {
        return new SecurityFinding(
                this.id, this.rule, this.severity, this.targetFile, this.className, this.methodName,
                this.startLine, this.endLine, this.vulnerableSnippet, this.description,
                this.causalRationale, this.remediation, this.confidence, chain, this.exploitabilityIndex
        );
    }

    public SecurityFinding withCalibratedConfidence(double calibratedConfidence, ExploitabilityIndex index) {
        return new SecurityFinding(
                this.id, this.rule, this.severity, this.targetFile, this.className, this.methodName,
                this.startLine, this.endLine, this.vulnerableSnippet, this.description,
                this.causalRationale, this.remediation, calibratedConfidence, this.causalChain, index
        );
    }

    public SecurityFinding withExploitabilityIndex(ExploitabilityIndex index) {
        return new SecurityFinding(
                this.id, this.rule, this.severity, this.targetFile, this.className, this.methodName,
                this.startLine, this.endLine, this.vulnerableSnippet, this.description,
                this.causalRationale, this.remediation, this.confidence, this.causalChain, index
        );
    }

    @Override
    public String toString() {
        return "SecurityFinding{" +
                "id='" + id + '\'' +
                ", rule=" + rule.getRuleId() +
                ", severity=" + severity +
                ", targetFile='" + targetFile + '\'' +
                ", line=" + startLine + "-" + endLine +
                ", description='" + description + '\'' +
                ", confidence=" + confidence +
                (exploitabilityIndex != null ? ", exploitability=" + exploitabilityIndex : "") +
                '}';
    }
}
