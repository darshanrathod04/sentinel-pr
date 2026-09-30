package com.sentinelpr.core.remediation;

import com.sentinelpr.core.model.SecurityRule;

import java.util.EnumMap;
import java.util.Map;
import java.util.Objects;

/**
 * <b>RemediationTemplateRegistry</b>
 *
 * <p>Central registry managing rule-specific {@link RemediationStrategy} implementations.</p>
 * <p>Avoids giant monolithic if/else blocks and provides a clean deterministic remediation dispatch mechanism.</p>
 */
public class RemediationTemplateRegistry {

    private static final RemediationTemplateRegistry INSTANCE = new RemediationTemplateRegistry();

    private final Map<SecurityRule, RemediationStrategy> strategyMap = new EnumMap<>(SecurityRule.class);

    public RemediationTemplateRegistry() {
        registerDefaults();
    }

    public static RemediationTemplateRegistry getInstance() {
        return INSTANCE;
    }

    private void registerDefaults() {
        registerStrategy(new SqlInjectionRemediationStrategy());
        registerStrategy(new HardcodedSecretRemediationStrategy());
        registerStrategy(new FailOpenRemediationStrategy());
        registerStrategy(new UnclosedStreamRemediationStrategy());
        registerStrategy(new VolatileCompoundRemediationStrategy());
        registerStrategy(new SubprocessRemediationStrategy());
        registerStrategy(new PathTraversalRemediationStrategy());
        registerStrategy(new InsecureDeserializationRemediationStrategy());
        registerStrategy(new SpringCsrfRemediationStrategy());
        registerStrategy(new PermissiveCorsRemediationStrategy());
        registerStrategy(new LeakyAbstractionRemediationStrategy());
    }

    public void registerStrategy(RemediationStrategy strategy) {
        Objects.requireNonNull(strategy, "strategy must not be null");
        strategyMap.put(strategy.getSupportedRule(), strategy);
    }

    public RemediationStrategy getStrategy(SecurityRule rule) {
        return strategyMap.get(rule);
    }

    public boolean hasStrategy(SecurityRule rule) {
        return strategyMap.containsKey(rule);
    }
}
