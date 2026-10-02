package com.sentinelpr.benchmark.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.Collections;
import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public class BenchmarkCase {

    private String caseId;
    private String ruleId;
    private String caseType; // VULNERABLE or SAFE
    private String description;
    private List<String> fixturePaths = Collections.emptyList();
    private String primaryFixturePath;
    private String entryPointFixturePath;
    private String remediationFixturePath;
    private boolean crossFileEvaluation;
    private BenchmarkGroundTruth groundTruth;
    private CompilationExpectation compilationExpectation;
    private String suite; // CANONICAL, ADVERSARIAL, REALISTIC, or CROSS_FILE
    private String notes;

    public BenchmarkCase() {}

    public String getSuite() {
        if (suite != null && !suite.isBlank()) {
            return suite;
        }
        if (caseId != null) {
            if (caseId.startsWith("ADV-")) {
                return "ADVERSARIAL";
            }
            if (caseId.startsWith("REAL-")) {
                return "REALISTIC";
            }
            if (caseId.startsWith("XFILE-")) {
                return "CROSS_FILE";
            }
        }
        return "CANONICAL";
    }

    public void setSuite(String suite) {
        this.suite = suite;
    }

    public boolean isCanonical() {
        return "CANONICAL".equalsIgnoreCase(getSuite());
    }

    public boolean isAdversarial() {
        return "ADVERSARIAL".equalsIgnoreCase(getSuite());
    }

    public boolean isRealistic() {
        return "REALISTIC".equalsIgnoreCase(getSuite());
    }

    public boolean isCrossFile() {
        return "CROSS_FILE".equalsIgnoreCase(getSuite()) || crossFileEvaluation;
    }

    public String getCaseId() {
        return caseId;
    }

    public void setCaseId(String caseId) {
        this.caseId = caseId;
    }

    public String getRuleId() {
        return ruleId;
    }

    public String getTargetRuleId() {
        return ruleId;
    }

    public void setRuleId(String ruleId) {
        this.ruleId = ruleId;
    }

    public String getCaseType() {
        return caseType;
    }

    public void setCaseType(String caseType) {
        this.caseType = caseType;
    }

    public boolean isVulnerable() {
        return "VULNERABLE".equalsIgnoreCase(caseType);
    }

    public boolean isSafe() {
        return "SAFE".equalsIgnoreCase(caseType);
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public List<String> getFixturePaths() {
        return fixturePaths != null ? fixturePaths : Collections.emptyList();
    }

    public void setFixturePaths(List<String> fixturePaths) {
        this.fixturePaths = fixturePaths;
    }

    public String getPrimaryFixturePath() {
        if (primaryFixturePath != null && !primaryFixturePath.isBlank()) {
            return primaryFixturePath;
        }
        return (fixturePaths != null && !fixturePaths.isEmpty()) ? fixturePaths.get(0) : "";
    }

    public void setPrimaryFixturePath(String primaryFixturePath) {
        this.primaryFixturePath = primaryFixturePath;
    }

    public String getEntryPointFixturePath() {
        if (entryPointFixturePath != null && !entryPointFixturePath.isBlank()) {
            return entryPointFixturePath;
        }
        return getPrimaryFixturePath();
    }

    public void setEntryPointFixturePath(String entryPointFixturePath) {
        this.entryPointFixturePath = entryPointFixturePath;
    }

    public String getRemediationFixturePath() {
        if (remediationFixturePath != null && !remediationFixturePath.isBlank()) {
            return remediationFixturePath;
        }
        return getPrimaryFixturePath();
    }

    public void setRemediationFixturePath(String remediationFixturePath) {
        this.remediationFixturePath = remediationFixturePath;
    }

    public boolean isCrossFileEvaluation() {
        return crossFileEvaluation || isCrossFile();
    }

    public void setCrossFileEvaluation(boolean crossFileEvaluation) {
        this.crossFileEvaluation = crossFileEvaluation;
    }

    public BenchmarkGroundTruth getGroundTruth() {
        return groundTruth;
    }

    public void setGroundTruth(BenchmarkGroundTruth groundTruth) {
        this.groundTruth = groundTruth;
    }

    public CompilationExpectation getCompilationExpectation() {
        return compilationExpectation;
    }

    public void setCompilationExpectation(CompilationExpectation compilationExpectation) {
        this.compilationExpectation = compilationExpectation;
    }

    public String getNotes() {
        return notes;
    }

    public void setNotes(String notes) {
        this.notes = notes;
    }
}
