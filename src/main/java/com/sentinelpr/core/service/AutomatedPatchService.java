package com.sentinelpr.core.service;

import com.sentinelpr.client.SentinelClient;
import com.sentinelpr.core.model.InspectedSource;
import com.sentinelpr.core.model.SecurityFinding;
import com.sentinelpr.core.model.UnifiedDiffPatch;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * <b>AutomatedPatchService</b>
 *
 * <p>Coordinates atomic patch composition and regression verification across detected security findings.</p>
 */
@Service
public class AutomatedPatchService {

    private final SentinelClient client;
    private final PatchComposer patchComposer;
    private final PatchVerifier patchVerifier;

    public AutomatedPatchService() {
        this(SentinelClient.getInstance());
    }

    public AutomatedPatchService(SentinelClient client) {
        this.client = Objects.requireNonNull(client, "client must not be null");
        this.patchVerifier = new PatchVerifier(new CodeInspectionService(client), new RuleEvaluationService(client));
        this.patchComposer = new PatchComposer(client.developer(), this.patchVerifier);
    }

    public AutomatedPatchService(SentinelClient client, PatchComposer patchComposer, PatchVerifier patchVerifier) {
        this.client = Objects.requireNonNull(client, "client must not be null");
        this.patchComposer = Objects.requireNonNull(patchComposer, "patchComposer must not be null");
        this.patchVerifier = Objects.requireNonNull(patchVerifier, "patchVerifier must not be null");
    }

    /**
     * Synthesizes an AST-compliant unified diff patch for a single security finding.
     */
    public UnifiedDiffPatch generatePatch(InspectedSource source, SecurityFinding finding) {
        Objects.requireNonNull(source, "source must not be null");
        Objects.requireNonNull(finding, "finding must not be null");
        return patchComposer.compose(source, List.of(finding));
    }

    /**
     * Composes all verified AST transformations sequentially to a single in-memory compilation unit,
     * producing ONE unified diff per file with post-patch regression verification.
     */
    public List<UnifiedDiffPatch> generatePatches(InspectedSource source, List<SecurityFinding> findings) {
        Objects.requireNonNull(source, "source must not be null");
        if (findings == null || findings.isEmpty()) {
            return Collections.emptyList();
        }

        UnifiedDiffPatch composed = patchComposer.compose(source, findings);
        return composed != null ? List.of(composed) : Collections.emptyList();
    }

    /**
     * Composes multiple patches into a single verified unified diff patch.
     */
    public UnifiedDiffPatch composePatches(InspectedSource source, List<SecurityFinding> findings) {
        return patchComposer.compose(source, findings);
    }

    /**
     * Validates that the patched source satisfies Java 21 compilation syntax.
     */
    public boolean verifyPatch(String patchedSource) {
        return patchVerifier.verify(patchedSource, "PatchedSource.java").isSyntaxValid();
    }

    public PatchComposer getPatchComposer() {
        return patchComposer;
    }

    public PatchVerifier getPatchVerifier() {
        return patchVerifier;
    }
}
