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

    @Override
    public String toString() {
        return "SecurityFinding{" +
                "id='" + id + '\'' +
                ", rule=" + rule.getRuleId() +
                ", severity=" + severity +
                ", targetFile='" + targetFile + '\'' +
                ", line=" + startLine + "-" + endLine +
                ", description='" + description + '\'' +
                '}';
    }
}
