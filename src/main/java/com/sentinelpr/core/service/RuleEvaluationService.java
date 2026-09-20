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

    public RuleEvaluationService() {
        this(SentinelClient.getInstance());
    }

    public RuleEvaluationService(SentinelClient client) {
        this.client = Objects.requireNonNull(client, "client must not be null");
    }

    /**
     * Evaluates all security and architectural rules on the inspected source.
     */
    public List<SecurityFinding> evaluate(InspectedSource inspectedSource) {
        Objects.requireNonNull(inspectedSource, "inspectedSource must not be null");
        return client.reasoning().evaluateAll(inspectedSource);
    }

    /**
     * Evaluates a specific rule on the inspected source.
     */
    public List<SecurityFinding> evaluateRule(InspectedSource inspectedSource, SecurityRule rule) {
        Objects.requireNonNull(inspectedSource, "inspectedSource must not be null");
        Objects.requireNonNull(rule, "rule must not be null");

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
        };
    }

    /**
     * Evaluates multiple sources in batch.
     */
    public List<SecurityFinding> evaluateAll(List<InspectedSource> sources) {
        if (sources == null || sources.isEmpty()) {
            return Collections.emptyList();
        }
        List<SecurityFinding> allFindings = new ArrayList<>();
        for (InspectedSource source : sources) {
            allFindings.addAll(evaluate(source));
        }
        return allFindings;
    }
}
