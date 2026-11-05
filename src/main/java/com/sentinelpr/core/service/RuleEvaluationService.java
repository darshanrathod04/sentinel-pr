package com.sentinelpr.core.service;

import com.sentinelpr.client.SentinelClient;
import com.sentinelpr.core.model.InspectedSource;
import com.sentinelpr.core.model.SecurityFinding;
import com.sentinelpr.core.model.SecurityRule;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * <b>RuleEvaluationService</b>
 *
 * <p>Evaluates AST rules using {@code client.reasoning()}:</p>
 * <ul>
 *   <li>Fail-open security blocks (e.g. catching NPE and granting access / returning true)</li>
 *   <li>Unclosed I/O streams or un-isolated subprocess calls</li>
 *   <li>Volatile compound operations without atomics</li>
 * </ul>
 */
@Service
public class RuleEvaluationService {

    private final SentinelClient client;
    private final com.sentinelpr.core.analysis.architecture.ArchitectureReviewEngine architectureEngine;
    private final com.sentinelpr.core.analysis.multilang.MultiLanguageAnalysisEngine multiLanguageEngine;

    public RuleEvaluationService() {
        this(SentinelClient.getInstance(), new com.sentinelpr.core.analysis.architecture.ArchitectureReviewEngine(), new com.sentinelpr.core.analysis.multilang.MultiLanguageAnalysisEngine());
    }

    public RuleEvaluationService(SentinelClient client) {
        this(client, new com.sentinelpr.core.analysis.architecture.ArchitectureReviewEngine(), new com.sentinelpr.core.analysis.multilang.MultiLanguageAnalysisEngine());
    }

    public RuleEvaluationService(SentinelClient client, com.sentinelpr.core.analysis.architecture.ArchitectureReviewEngine architectureEngine) {
        this(client, architectureEngine, new com.sentinelpr.core.analysis.multilang.MultiLanguageAnalysisEngine());
    }

    public RuleEvaluationService(
            SentinelClient client,
            com.sentinelpr.core.analysis.architecture.ArchitectureReviewEngine architectureEngine,
            com.sentinelpr.core.analysis.multilang.MultiLanguageAnalysisEngine multiLanguageEngine
    ) {
        this.client = Objects.requireNonNull(client, "client must not be null");
        this.architectureEngine = Objects.requireNonNull(architectureEngine, "architectureEngine must not be null");
        this.multiLanguageEngine = Objects.requireNonNull(multiLanguageEngine, "multiLanguageEngine must not be null");
    }

    /**
     * Evaluates all security and architectural rules on the inspected source.
     */
    public List<SecurityFinding> evaluate(InspectedSource inspectedSource) {
        return evaluate(inspectedSource, List.of(inspectedSource));
    }

    /**
     * Evaluates all security and architectural rules on the inspected source with project context.
     */
    public List<SecurityFinding> evaluate(InspectedSource inspectedSource, List<InspectedSource> allSources) {
        Objects.requireNonNull(inspectedSource, "inspectedSource must not be null");
        if (inspectedSource.getLanguage() != com.sentinelpr.core.model.SourceLanguage.JAVA) {
            return multiLanguageEngine.evaluate(inspectedSource, allSources);
        }
        List<SecurityFinding> findings = new ArrayList<>(client.reasoning().evaluateAll(inspectedSource, allSources));
        findings.addAll(architectureEngine.evaluate(inspectedSource, allSources != null ? allSources : List.of(inspectedSource)));
        return findings;
    }

    /**
     * Evaluates a specific rule on the inspected source.
     */
    public List<SecurityFinding> evaluateRule(InspectedSource inspectedSource, SecurityRule rule) {
        Objects.requireNonNull(inspectedSource, "inspectedSource must not be null");
        Objects.requireNonNull(rule, "rule must not be null");

        if (inspectedSource.getLanguage() != com.sentinelpr.core.model.SourceLanguage.JAVA) {
            return multiLanguageEngine.evaluate(inspectedSource, List.of(inspectedSource)).stream()
                    .filter(f -> f.getRule() == rule)
                    .toList();
        }

        return switch (rule) {
            case FAIL_OPEN_SECURITY -> client.reasoning().evaluateFailOpenSecurity(inspectedSource);
            case UNCLOSED_IO_STREAM -> client.reasoning().evaluateUnclosedIoStreams(inspectedSource);
            case VOLATILE_COMPOUND_OP -> client.reasoning().evaluateVolatileCompoundOps(inspectedSource);
            case UNISOLATED_SUBPROCESS -> client.reasoning().evaluateSubprocessCalls(inspectedSource);
            case SQL_INJECTION -> client.reasoning().evaluateSqlInjection(inspectedSource);
            case PATH_TRAVERSAL -> client.reasoning().evaluatePathTraversal(inspectedSource);
            case INSECURE_DESERIALIZATION -> client.reasoning().evaluateInsecureDeserialization(inspectedSource);
            case HARDCODED_SECRET -> client.reasoning().evaluateHardcodedSecrets(inspectedSource);
            case SPRING_SECURITY_CSRF_DISABLED -> client.reasoning().evaluateSpringCsrfDisabled(inspectedSource);
            case SPRING_PERMISSIVE_CORS -> client.reasoning().evaluateSpringPermissiveCors(inspectedSource);
            case XXE_INJECTION -> client.reasoning().evaluateXxeInjection(inspectedSource);
            case SSRF -> client.reasoning().evaluateSsrf(inspectedSource);
            case JWT_NONE_ALGORITHM -> client.reasoning().evaluateJwtNoneAlgorithm(inspectedSource);
            case LOG_INJECTION -> client.reasoning().evaluateLogInjection(inspectedSource);
            case LDAP_INJECTION -> client.reasoning().evaluateLdapInjection(inspectedSource);
            case XPATH_INJECTION -> client.reasoning().evaluateXpathInjection(inspectedSource);
            case OPEN_REDIRECT -> client.reasoning().evaluateOpenRedirect(inspectedSource);
            case WEAK_CRYPTO -> client.reasoning().evaluateWeakCrypto(inspectedSource);
            case INSECURE_RANDOM -> client.reasoning().evaluateInsecureRandom(inspectedSource);
            case XSS -> client.reasoning().evaluateXss(inspectedSource);
            case ARCH_CYCLIC_DEPENDENCY -> architectureEngine.evaluateCyclicDependencies(inspectedSource, List.of(inspectedSource));
            case ARCH_LEAKY_ABSTRACTION -> architectureEngine.evaluateLeakyAbstractions(inspectedSource);
            case ARCH_NON_DETERMINISTIC_CALL -> architectureEngine.evaluateNonDeterministicCalls(inspectedSource);
        };
    }

    /**
     * Evaluates multiple sources in batch with cross-file architectural analysis.
     */
    public List<SecurityFinding> evaluateAll(List<InspectedSource> sources) {
        if (sources == null || sources.isEmpty()) {
            return Collections.emptyList();
        }
        List<SecurityFinding> allFindings = new ArrayList<>();
        for (InspectedSource source : sources) {
            allFindings.addAll(evaluate(source, sources));
        }
        return allFindings;
    }

    public com.sentinelpr.core.analysis.architecture.ArchitectureReviewEngine getArchitectureEngine() {
        return architectureEngine;
    }
}
