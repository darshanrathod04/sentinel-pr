package com.sentinelpr.core.remediation;

import com.sentinelpr.core.model.InspectedSource;
import com.sentinelpr.core.model.SecurityFinding;
import com.sentinelpr.core.model.SecurityRule;

/**
 * <b>RemediationStrategy</b>
 *
 * <p>Strategy contract for rule-specific automated patch synthesis.</p>
 */
public interface RemediationStrategy {

    /**
     * The security rule supported by this strategy.
     */
    SecurityRule getSupportedRule();

    /**
     * Synthesizes a patch for the given finding within the source code.
     *
     * @param source          current in-memory source code
     * @param finding         the security finding being remediated
     * @param inspectedSource original parsed source model
     * @param context         remediation execution context
     * @return RemediationResult containing patched source or unapplied status
     */
    RemediationResult remediate(
            String source,
            SecurityFinding finding,
            InspectedSource inspectedSource,
            RemediationContext context
    );
}
