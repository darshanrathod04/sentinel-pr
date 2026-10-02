package com.sentinelpr.benchmark.engine;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.sentinelpr.client.SentinelClient;
import com.sentinelpr.core.model.InspectedSource;
import com.sentinelpr.core.model.SecurityFinding;
import com.sentinelpr.core.service.CodeInspectionService;
import com.sentinelpr.core.service.RuleEvaluationService;
import com.sentinelpr.benchmark.model.*;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.*;

public class BenchmarkEngine {

    private final SentinelClient client;
    private final CodeInspectionService inspectionService;
    private final RuleEvaluationService evaluationService;
    private final InMemoryCompilationVerifier compilationVerifier;
    private final RemediationBenchmarkEvaluator remediationEvaluator;
    private final ConfusionMatrixCalculator matrixCalculator;
    private final ObjectMapper objectMapper;

    public BenchmarkEngine() {
        this(SentinelClient.getInstance());
    }

    public BenchmarkEngine(SentinelClient client) {
        this.client = Objects.requireNonNull(client, "client must not be null");
        this.inspectionService = new CodeInspectionService(client);
        this.evaluationService = new RuleEvaluationService(client);
        this.compilationVerifier = new InMemoryCompilationVerifier();
        this.remediationEvaluator = new RemediationBenchmarkEvaluator(client, this.compilationVerifier);
        this.matrixCalculator = new ConfusionMatrixCalculator();

        this.objectMapper = new ObjectMapper();
        this.objectMapper.enable(SerializationFeature.INDENT_OUTPUT);
    }

    public List<BenchmarkCase> loadCatalog(Path catalogPath) throws IOException {
        if (!Files.exists(catalogPath)) {
            throw new IllegalArgumentException("Benchmark ground truth catalog file not found: " + catalogPath.toAbsolutePath());
        }
        byte[] bytes = Files.readAllBytes(catalogPath);
        return objectMapper.readValue(bytes, new TypeReference<List<BenchmarkCase>>() {});
    }

    public BenchmarkReport runBenchmark() throws IOException {
        Path defaultPath = Path.of("benchmark/ground-truth/ground-truth-catalog.json");
        return runBenchmark(defaultPath);
    }

    public BenchmarkReport runBenchmark(Path catalogPath) throws IOException {
        long suiteStartTime = System.nanoTime();
        List<BenchmarkCase> cases = loadCatalog(catalogPath);

        List<BenchmarkExecutionResult> results = new ArrayList<>();
        for (BenchmarkCase bCase : cases) {
            BenchmarkExecutionResult res = executeCase(bCase);
            results.add(res);
        }

        long suiteEndTime = System.nanoTime();
        double totalDurationMs = (suiteEndTime - suiteStartTime) / 1_000_000.0;

        List<BenchmarkExecutionResult> canonicalResults = results.stream()
                .filter(r -> r.getBenchmarkCase().isCanonical())
                .toList();

        List<BenchmarkExecutionResult> adversarialResults = results.stream()
                .filter(r -> r.getBenchmarkCase().isAdversarial())
                .toList();

        List<BenchmarkExecutionResult> realisticResults = results.stream()
                .filter(r -> r.getBenchmarkCase().isRealistic())
                .toList();

        List<BenchmarkExecutionResult> crossFileResults = results.stream()
                .filter(r -> r.getBenchmarkCase().isCrossFile())
                .toList();

        double canonicalDurationMs = canonicalResults.stream()
                .mapToDouble(BenchmarkExecutionResult::getTotalDurationMs)
                .sum();

        double adversarialDurationMs = adversarialResults.stream()
                .mapToDouble(BenchmarkExecutionResult::getTotalDurationMs)
                .sum();

        double realisticDurationMs = realisticResults.stream()
                .mapToDouble(BenchmarkExecutionResult::getTotalDurationMs)
                .sum();

        double crossFileDurationMs = crossFileResults.stream()
                .mapToDouble(BenchmarkExecutionResult::getTotalDurationMs)
                .sum();

        BenchmarkSummary combinedSummary = matrixCalculator.computeSummary(results, totalDurationMs);
        BenchmarkSummary canonicalSummary = matrixCalculator.computeSummary(canonicalResults, canonicalDurationMs);
        BenchmarkSummary adversarialSummary = matrixCalculator.computeSummary(adversarialResults, adversarialDurationMs);
        BenchmarkSummary realisticSummary = matrixCalculator.computeSummary(realisticResults, realisticDurationMs);
        BenchmarkSummary crossFileSummary = crossFileResults.isEmpty() ? null :
                matrixCalculator.computeSummary(crossFileResults, crossFileDurationMs);

        Map<String, ConfusionMatrix> perRuleMetrics = matrixCalculator.computePerRuleMetrics(results);
        Map<String, RuleRemediationStats> perRuleRemediation = matrixCalculator.computePerRuleRemediation(results);

        Map<String, String> environment = new LinkedHashMap<>();
        environment.put("os.name", System.getProperty("os.name"));
        environment.put("os.arch", System.getProperty("os.arch"));
        environment.put("java.version", System.getProperty("java.version"));
        environment.put("java.vendor", System.getProperty("java.vendor"));
        environment.put("availableProcessors", String.valueOf(Runtime.getRuntime().availableProcessors()));
        environment.put("maxMemoryMb", String.valueOf(Runtime.getRuntime().maxMemory() / (1024 * 1024)));

        return new BenchmarkReport(
                "1.2.0",
                Instant.now().toString(),
                environment,
                canonicalSummary,
                adversarialSummary,
                realisticSummary,
                crossFileSummary,
                combinedSummary,
                perRuleMetrics,
                perRuleRemediation,
                results
        );
    }

    public BenchmarkExecutionResult executeCase(BenchmarkCase bCase) {
        BenchmarkExecutionResult result = new BenchmarkExecutionResult();
        result.setCaseId(bCase.getCaseId());
        result.setRuleId(bCase.getTargetRuleId());
        result.setCaseType(bCase.getCaseType());
        result.setBenchmarkCase(bCase);

        long t0 = System.nanoTime();

        // 1. Inspect all fixtures associated with the case
        List<InspectedSource> allSources = new ArrayList<>();
        InspectedSource primarySource = null;
        InspectedSource entrySource = null;
        InspectedSource remediationSource = null;

        for (String pathStr : bCase.getFixturePaths()) {
            try {
                Path path = Path.of(pathStr);
                InspectedSource is = inspectionService.inspectFile(path);
                allSources.add(is);
                String normPath = pathStr.replace('\\', '/');
                String normPrimary = bCase.getPrimaryFixturePath().replace('\\', '/');
                if (normPath.equalsIgnoreCase(normPrimary)) {
                    primarySource = is;
                }
                String normEntry = bCase.getEntryPointFixturePath().replace('\\', '/');
                if (normPath.equalsIgnoreCase(normEntry)) {
                    entrySource = is;
                }
                String normRemediation = bCase.getRemediationFixturePath().replace('\\', '/');
                if (normPath.equalsIgnoreCase(normRemediation)) {
                    remediationSource = is;
                }
            } catch (Exception e) {
                result.getDiagnostics().add("Failed to inspect file " + pathStr + ": " + e.getMessage());
            }
        }

        if (primarySource == null && !allSources.isEmpty()) {
            primarySource = allSources.get(0);
        }
        if (entrySource == null) {
            entrySource = primarySource;
        }
        if (remediationSource == null) {
            remediationSource = primarySource;
        }

        long t1 = System.nanoTime();
        result.setInspectionDurationNs(t1 - t0);

        if (primarySource == null) {
            result.setClassification("ERROR");
            result.setDetectionSuccess(false);
            result.setDetectionMismatch("No inspected primary source available for " + bCase.getCaseId());
            result.setTotalDurationNs(System.nanoTime() - t0);
            return result;
        }

        // 2. Original compilation check (if expected)
        if (bCase.getCompilationExpectation() != null && bCase.getCompilationExpectation().isOriginalCompiles()) {
            List<String> rawCodes = allSources.stream().map(InspectedSource::getRawSource).toList();
            InMemoryCompilationVerifier.CompilationResult origComp = compilationVerifier.compileSources(rawCodes);
            if (!origComp.isSuccess()) {
                result.getDiagnostics().add("Original source compilation warning: " + String.join("; ", origComp.getDiagnostics()));
            }
        }

        // 3. Rule Evaluation
        long t2 = System.nanoTime();
        InspectedSource evalTarget = bCase.isCrossFile() ? entrySource : primarySource;
        List<SecurityFinding> findings = evaluationService.evaluate(evalTarget, allSources);
        long t3 = System.nanoTime();
        result.setEvaluationDurationNs(t3 - t2);

        // 4. Detection Classification
        boolean targetRuleDetected = findings.stream()
                .anyMatch(f -> f.getRule().getRuleId().equalsIgnoreCase(bCase.getTargetRuleId()));

        boolean expectedVulnerable = bCase.getGroundTruth().isExpectedFinding();

        if (expectedVulnerable) {
            if (targetRuleDetected) {
                result.setClassification("TRUE_POSITIVE");
                result.setDetectionSuccess(true);
            } else {
                result.setClassification("FALSE_NEGATIVE");
                result.setDetectionSuccess(false);
                result.setDetectionMismatch("Expected finding for " + bCase.getTargetRuleId() + " but 0 matching findings were detected");
            }
        } else {
            if (!targetRuleDetected) {
                result.setClassification("TRUE_NEGATIVE");
                result.setDetectionSuccess(true);
            } else {
                result.setClassification("FALSE_POSITIVE");
                result.setDetectionSuccess(false);
                result.setDetectionMismatch("Unexpected finding detected on safe fixture for rule " + bCase.getTargetRuleId());
            }
        }

        // 5. Remediation Evaluation (if expected)
        if (bCase.getGroundTruth().isExpectedRemediation()) {
            InspectedSource remTarget = bCase.isCrossFile() ? remediationSource : primarySource;
            RemediationEvaluationResult remResult = remediationEvaluator.evaluateRemediation(
                    bCase, remTarget, entrySource, allSources, findings);
            result.setRemediationResult(remResult);
            result.setRemediationDurationNs((long) (remResult.getRemediationDurationMs() * 1_000_000));
            result.setCompilationDurationNs((long) (remResult.getCompilationDurationMs() * 1_000_000));
        }

        long tFinal = System.nanoTime();
        result.setTotalDurationNs(tFinal - t0);

        return result;
    }
}
