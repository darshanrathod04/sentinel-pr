package com.sentinelpr.core.service;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ast.CompilationUnit;
import com.sentinelpr.client.SentinelClient;
import com.sentinelpr.core.analysis.SuppressionManager;
import com.sentinelpr.core.model.InspectedSource;
import com.sentinelpr.core.model.SecurityFinding;
import com.sentinelpr.core.model.Severity;
import com.shreeai.os.platform.kernels.project.parser.JavaAstParser;

import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * <b>PatchVerifier</b>
 *
 * <p>Performs post-patch regression verification by:</p>
 * <ol>
 *   <li>Parsing the patched source with {@link JavaAstParser} to verify AST syntax validity.</li>
 *   <li>Re-running {@link RuleEvaluationService} to ensure 0 critical vulnerabilities remain.</li>
 *   <li>Designating the composed patch as {@code regressionVerified: true}.</li>
 * </ol>
 */
public class PatchVerifier {

    private final JavaAstParser astParser;
    private final JavaParser javaParser;
    private final CodeInspectionService inspectionService;
    private final RuleEvaluationService evaluationService;
    private final SuppressionManager suppressionManager;

    public PatchVerifier(CodeInspectionService inspectionService, RuleEvaluationService evaluationService) {
        this(inspectionService, evaluationService, new SuppressionManager());
    }

    public PatchVerifier(
            CodeInspectionService inspectionService,
            RuleEvaluationService evaluationService,
            SuppressionManager suppressionManager
    ) {
        this.inspectionService = Objects.requireNonNull(inspectionService, "inspectionService must not be null");
        this.evaluationService = Objects.requireNonNull(evaluationService, "evaluationService must not be null");
        this.suppressionManager = Objects.requireNonNull(suppressionManager, "suppressionManager must not be null");
        this.astParser = new JavaAstParser();
        ParserConfiguration config = new ParserConfiguration();
        config.setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_21);
        this.javaParser = new JavaParser(config);
    }

    public PatchVerifier(SentinelClient client) {
        this(new CodeInspectionService(client), new RuleEvaluationService(client), new SuppressionManager());
    }

    /**
     * Verifies AST validity and checks for regression on the patched source.
     */
    public PatchVerificationResult verify(String patchedSource, String simPath) {
        if (patchedSource == null || patchedSource.isBlank()) {
            return new PatchVerificationResult(false, false, Collections.emptyList(), "Patched source is empty");
        }

        String pathStr = (simPath != null && !simPath.isBlank()) ? simPath : "PatchedService.java";

        // 1. Verify with JavaAstParser (Shree AI OS Project Kernel parser)
        try {
            astParser.parse(patchedSource, pathStr);
        } catch (Exception e) {
            return new PatchVerificationResult(false, false, Collections.emptyList(),
                    "JavaAstParser syntax verification failed: " + e.getMessage());
        }

        // 2. Verify with JavaParser for Java 21 LTS AST compilation unit
        Optional<CompilationUnit> cuResult = javaParser.parse(patchedSource).getResult();
        if (cuResult.isEmpty()) {
            return new PatchVerificationResult(false, false, Collections.emptyList(),
                    "JavaParser AST verification failed: invalid Java 21 syntax");
        }

        // 3. Re-run inspection and rule evaluation on patched code
        InspectedSource inspected;
        try {
            inspected = inspectionService.inspectSourceCode(patchedSource, pathStr);
        } catch (Exception e) {
            return new PatchVerificationResult(true, false, Collections.emptyList(),
                    "Failed to re-inspect patched source: " + e.getMessage());
        }

        List<SecurityFinding> rawRemaining = evaluationService.evaluate(inspected);

        // Filter out suppressed findings
        List<SecurityFinding> activeRemaining = rawRemaining.stream()
                .filter(f -> !suppressionManager.evaluateSuppression(f, inspected, null).isSuppressed())
                .toList();

        // 4. Assert 0 active critical security vulnerabilities remain
        long criticalRemaining = activeRemaining.stream()
                .filter(f -> f.getSeverity() == Severity.CRITICAL)
                .count();

        boolean regressionVerified = (criticalRemaining == 0);
        String message = regressionVerified
                ? String.format("AST syntax verified (Java 21 LTS) & regression verification PASSED (0 critical findings remain, %d non-critical)", activeRemaining.size())
                : String.format("Regression verification FAILED: %d critical vulnerabilities remain unresolved: %s", criticalRemaining, activeRemaining);

        return new PatchVerificationResult(true, regressionVerified, activeRemaining, message);
    }
}
