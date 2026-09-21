package com.sentinelpr.core.analysis.calibration;

import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.sentinelpr.core.analysis.DataflowTracker;
import com.sentinelpr.core.model.ExploitabilityIndex;
import com.sentinelpr.core.model.InspectedSource;
import com.sentinelpr.core.model.SecurityFinding;
import com.sentinelpr.core.model.Severity;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * <b>ConfidenceCalibrator</b>
 *
 * <p>Implements a deterministic 4-factor scoring model replacing static heuristic confidence
 * with calibrated confidence [0.0 - 1.0] and an {@link ExploitabilityIndex}:</p>
 * <ol>
 *   <li><b>Taint path continuity (0.35)</b>: Dataflow continuity from untrusted input to sink.</li>
 *   <li><b>AST precision / Rule fidelity (0.30)</b>: Structural AST determinism of the rule match.</li>
 *   <li><b>Absence of defensive sanitizers (0.20)</b>: Absence of validation, null guards, or encoding.</li>
 *   <li><b>Public API exposure / Reachability (0.15)</b>: Exposure via public controllers or public APIs.</li>
 * </ol>
 *
 * <p>Findings below the confidence threshold (default &lt; 0.70) are classified as
 * {@code LOW_CONFIDENCE_HEURISTIC} rather than active PR blockers.</p>
 */
public class ConfidenceCalibrator {

    public static final double DEFAULT_MIN_CONFIDENCE_THRESHOLD = 0.70;
    public static final String LOW_CONFIDENCE_SUPPRESSION_TYPE = "LOW_CONFIDENCE_HEURISTIC";

    public static final double WEIGHT_TAINT_PATH = 0.35;
    public static final double WEIGHT_AST_PRECISION = 0.30;
    public static final double WEIGHT_ABSENCE_OF_SANITIZERS = 0.20;
    public static final double WEIGHT_PUBLIC_REACHABILITY = 0.15;

    private final double minConfidenceThreshold;
    private final DataflowTracker dataflowTracker;

    public ConfidenceCalibrator() {
        this(DEFAULT_MIN_CONFIDENCE_THRESHOLD, new DataflowTracker());
    }

    public ConfidenceCalibrator(double minConfidenceThreshold) {
        this(minConfidenceThreshold, new DataflowTracker());
    }

    public ConfidenceCalibrator(double minConfidenceThreshold, DataflowTracker dataflowTracker) {
        this.minConfidenceThreshold = minConfidenceThreshold;
        this.dataflowTracker = Objects.requireNonNull(dataflowTracker, "dataflowTracker must not be null");
    }

    public static class CalibrationResult {
        private final double score;
        private final ExploitabilityIndex exploitabilityIndex;
        private final boolean meetsThreshold;
        private final Map<String, Double> factorScores;
        private final Map<String, Double> weightedContributions;

        public CalibrationResult(
                double score,
                ExploitabilityIndex exploitabilityIndex,
                boolean meetsThreshold,
                Map<String, Double> factorScores,
                Map<String, Double> weightedContributions
        ) {
            this.score = score;
            this.exploitabilityIndex = exploitabilityIndex;
            this.meetsThreshold = meetsThreshold;
            this.factorScores = Collections.unmodifiableMap(new LinkedHashMap<>(factorScores));
            this.weightedContributions = Collections.unmodifiableMap(new LinkedHashMap<>(weightedContributions));
        }

        public double getScore() {
            return score;
        }

        public ExploitabilityIndex getExploitabilityIndex() {
            return exploitabilityIndex;
        }

        public boolean isMeetsThreshold() {
            return meetsThreshold;
        }

        public boolean isLowConfidence() {
            return !meetsThreshold;
        }

        public Map<String, Double> getFactorScores() {
            return factorScores;
        }

        public Map<String, Double> getWeightedContributions() {
            return weightedContributions;
        }
    }

    /**
     * Calibrates confidence and assigns exploitability index for a discovered finding.
     */
    public CalibrationResult calibrate(SecurityFinding finding, InspectedSource source) {
        Objects.requireNonNull(finding, "finding must not be null");

        double taintScore = evaluateTaintContinuity(finding, source);
        double astScore = evaluateAstPrecision(finding, source);
        double sanitizerScore = evaluateAbsenceOfSanitizers(finding, source);
        double reachabilityScore = evaluateReachability(finding, source);

        double taintWeighted = taintScore * WEIGHT_TAINT_PATH;
        double astWeighted = astScore * WEIGHT_AST_PRECISION;
        double sanitizerWeighted = sanitizerScore * WEIGHT_ABSENCE_OF_SANITIZERS;
        double reachabilityWeighted = reachabilityScore * WEIGHT_PUBLIC_REACHABILITY;

        double totalScore = Math.min(1.0, Math.max(0.0, taintWeighted + astWeighted + sanitizerWeighted + reachabilityWeighted));
        // Round to 2 decimal places
        totalScore = Math.round(totalScore * 100.0) / 100.0;

        ExploitabilityIndex index = determineExploitabilityIndex(totalScore, finding.getSeverity());
        boolean meetsThreshold = totalScore >= minConfidenceThreshold;

        Map<String, Double> factors = new LinkedHashMap<>();
        factors.put("taintPathContinuity", taintScore);
        factors.put("astPrecision", astScore);
        factors.put("absenceOfSanitizers", sanitizerScore);
        factors.put("publicReachability", reachabilityScore);

        Map<String, Double> contributions = new LinkedHashMap<>();
        contributions.put("taintPathContinuity", taintWeighted);
        contributions.put("astPrecision", astWeighted);
        contributions.put("absenceOfSanitizers", sanitizerWeighted);
        contributions.put("publicReachability", reachabilityWeighted);

        return new CalibrationResult(totalScore, index, meetsThreshold, factors, contributions);
    }

    /**
     * Enriches a finding with calibrated confidence and exploitability index.
     */
    public SecurityFinding enrichWithCalibration(SecurityFinding finding, InspectedSource source) {
        CalibrationResult result = calibrate(finding, source);
        return finding.withCalibratedConfidence(result.getScore(), result.getExploitabilityIndex());
    }

    public ExploitabilityIndex determineExploitabilityIndex(double score, Severity severity) {
        if (score >= 0.88 || (severity == Severity.CRITICAL && score >= 0.80)) {
            return ExploitabilityIndex.CRITICAL;
        } else if (score >= 0.75 || (severity == Severity.HIGH && score >= 0.70)) {
            return ExploitabilityIndex.HIGH;
        } else if (score >= 0.60) {
            return ExploitabilityIndex.MEDIUM;
        } else if (score >= 0.40) {
            return ExploitabilityIndex.LOW;
        } else {
            return ExploitabilityIndex.VERY_LOW;
        }
    }

    private double evaluateTaintContinuity(SecurityFinding finding, InspectedSource source) {
        if (source == null) {
            return 0.50;
        }

        String ruleId = finding.getRule().getRuleId();
        // Taint-centric rules
        if (ruleId.contains("SQL-INJECTION") || ruleId.contains("PATH-TRAVERSAL")
                || ruleId.contains("UNISOLATED-SUBPROCESS") || ruleId.contains("INSECURE-DESERIALIZATION")) {
            boolean hasTaintFlow = source.getMethods().stream()
                    .filter(m -> m.getNameAsString().equals(finding.getMethodName()))
                    .anyMatch(m -> {
                        return m.getParameters().stream().anyMatch(p -> {
                            String type = p.getTypeAsString();
                            return type.contains("String") || type.contains("Request") || type.contains("InputStream");
                        });
                    });
            if (hasTaintFlow) {
                return 1.0;
            }
            if (finding.getConfidence() < 0.60
                    || (finding.getDescription() != null && finding.getDescription().toLowerCase().contains("heuristic"))) {
                return 0.30;
            }
            return 0.45;
        }

        // Structural security rules (Fail-Open, Unclosed Stream, Volatile, CORS, CSRF, Secrets, Arch)
        if (finding.getVulnerableSnippet() != null && !finding.getVulnerableSnippet().isBlank()) {
            return 0.95;
        }

        return 0.70;
    }

    private double evaluateAstPrecision(SecurityFinding finding, InspectedSource source) {
        // If the finding itself is explicitly heuristic or low confidence:
        if (finding.getConfidence() < 0.60
                || (finding.getDescription() != null && finding.getDescription().toLowerCase().contains("heuristic"))) {
            return 0.40;
        }

        // If source is present and method name is specified, verify method exists in AST
        if (source != null && finding.getMethodName() != null && !finding.getMethodName().isBlank()) {
            boolean methodExists = source.getMethods().stream()
                    .anyMatch(m -> m.getNameAsString().equals(finding.getMethodName()));
            if (!methodExists) {
                return 0.50; // Method symbol not found in AST
            }
        }

        // High fidelity AST matches
        if (finding.getVulnerableSnippet() != null && finding.getStartLine() > 0) {
            return 1.0;
        }
        return 0.75;
    }

    private double evaluateAbsenceOfSanitizers(SecurityFinding finding, InspectedSource source) {
        // Inspect snippet directly for defensive sanitizers or escape logic
        if (finding.getVulnerableSnippet() != null) {
            String snippet = finding.getVulnerableSnippet();
            boolean snippetHasSanitizers = snippet.contains(".replaceAll")
                    || snippet.contains(".replace")
                    || snippet.contains("Objects.requireNonNull")
                    || snippet.contains("isValid")
                    || snippet.contains("sanitize")
                    || snippet.contains("escape");
            if (snippetHasSanitizers) {
                return 0.20; // Defensive sanitization present, lower exploitability
            }
        }

        if (source != null && finding.getMethodName() != null) {
            MethodDeclaration method = source.getMethods().stream()
                    .filter(m -> m.getNameAsString().equals(finding.getMethodName()))
                    .findFirst()
                    .orElse(null);

            if (method != null) {
                String body = method.getBody().map(Object::toString).orElse("");
                boolean hasSanitizers = body.contains(".replaceAll")
                        || body.contains(".replace")
                        || body.contains("Objects.requireNonNull")
                        || body.contains("isValid")
                        || body.contains("sanitize")
                        || body.contains("escape");

                if (hasSanitizers) {
                    return 0.20; // Sanitizers present in method body
                }
            }
        }

        return 1.0; // No sanitizers present, high exploitability
    }

    private double evaluateReachability(SecurityFinding finding, InspectedSource source) {
        String methodName = finding.getMethodName();

        // If method name indicates private scope or internal helper
        if (methodName != null && (methodName.toLowerCase().contains("private") || methodName.toLowerCase().contains("internal"))) {
            return 0.15;
        }

        if (source == null) {
            return 0.60;
        }

        // Check if class is a Controller or RestController
        boolean isController = source.getClassDeclarations().stream().anyMatch(c ->
                c.getAnnotations().stream().anyMatch(a -> {
                    String name = a.getNameAsString();
                    return name.contains("RestController") || name.contains("Controller") || name.contains("RequestMapping");
                })
        );

        if (isController) {
            return 1.0; // Directly exposed HTTP endpoint
        }

        // Check method visibility in AST
        if (methodName != null) {
            MethodDeclaration method = source.getMethods().stream()
                    .filter(m -> m.getNameAsString().equals(methodName))
                    .findFirst()
                    .orElse(null);

            if (method != null) {
                if (method.isPublic()) {
                    return 0.85;
                } else if (method.isProtected()) {
                    return 0.60;
                } else if (method.isPrivate()) {
                    return 0.15;
                }
            }
        }

        return 0.65;
    }

    public double getMinConfidenceThreshold() {
        return minConfidenceThreshold;
    }
}
