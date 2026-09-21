package com.sentinelpr.core.analysis.causal;

import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.sentinelpr.client.SentinelClient;
import com.sentinelpr.core.analysis.causal.CausalChain.BlastRadius;
import com.sentinelpr.core.model.InspectedSource;
import com.sentinelpr.core.model.SecurityFinding;
import com.sentinelpr.core.model.SecurityRule;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * <b>CausalAnalysisEngine</b>
 *
 * <p>Deep cognitive root-cause engine building multi-hop causal chains:
 * {@code Trigger -> Propagation -> Exploit Scenario -> Business Impact}.</p>
 *
 * <p>Differentiates theoretical flaws from weaponizable code paths based on AST semantics,
 * caller context, and exposure level.</p>
 */
public class CausalAnalysisEngine {

    private final SentinelClient client;

    public CausalAnalysisEngine() {
        this(SentinelClient.getInstance());
    }

    public CausalAnalysisEngine(SentinelClient client) {
        this.client = Objects.requireNonNull(client, "client must not be null");
    }

    /**
     * Builds a structured {@link CausalChain} for a discovered security or architectural finding.
     */
    public CausalChain analyzeCausalChain(SecurityFinding finding, InspectedSource source) {
        return analyzeCausalChain(finding, source, List.of());
    }

    /**
     * Builds a structured {@link CausalChain} with project-wide caller context awareness.
     */
    public CausalChain analyzeCausalChain(
            SecurityFinding finding,
            InspectedSource source,
            List<InspectedSource> allProjectSources
    ) {
        Objects.requireNonNull(finding, "finding must not be null");

        boolean activelyReachable = determineReachability(finding, source, allProjectSources);
        SecurityRule rule = finding.getRule();

        CausalChain.Builder builder = CausalChain.builder()
                .activelyReachable(activelyReachable);

        if (rule == SecurityRule.FAIL_OPEN_SECURITY) {
            buildFailOpenChain(builder, finding);
        } else if (rule == SecurityRule.SQL_INJECTION) {
            buildSqlInjectionChain(builder, finding);
        } else if (rule == SecurityRule.PATH_TRAVERSAL) {
            buildPathTraversalChain(builder, finding);
        } else if (rule == SecurityRule.UNCLOSED_IO_STREAM) {
            buildUnclosedStreamChain(builder, finding);
        } else if (rule == SecurityRule.VOLATILE_COMPOUND_OP) {
            buildVolatileCompoundChain(builder, finding);
        } else if (rule == SecurityRule.UNISOLATED_SUBPROCESS) {
            buildSubprocessChain(builder, finding);
        } else if (rule == SecurityRule.INSECURE_DESERIALIZATION) {
            buildDeserializationChain(builder, finding);
        } else if (rule == SecurityRule.HARDCODED_SECRET) {
            buildHardcodedSecretChain(builder, finding);
        } else if (rule == SecurityRule.SPRING_SECURITY_CSRF_DISABLED) {
            buildCsrfChain(builder, finding);
        } else if (rule == SecurityRule.SPRING_PERMISSIVE_CORS) {
            buildCorsChain(builder, finding);
        } else if (rule == SecurityRule.ARCH_LEAKY_ABSTRACTION) {
            buildLeakyAbstractionChain(builder, finding);
        } else if (rule == SecurityRule.ARCH_NON_DETERMINISTIC_CALL) {
            buildNonDeterministicChain(builder, finding);
        } else if (rule == SecurityRule.ARCH_CYCLIC_DEPENDENCY) {
            buildCyclicDependencyChain(builder, finding);
        } else {
            buildGenericChain(builder, finding);
        }

        return builder.build();
    }

    /**
     * Enriches a finding by synthesizing and attaching a {@link CausalChain}.
     */
    public SecurityFinding enrichFinding(SecurityFinding finding, InspectedSource source) {
        CausalChain chain = analyzeCausalChain(finding, source);
        return finding.withCausalChain(chain);
    }

    private boolean determineReachability(
            SecurityFinding finding,
            InspectedSource source,
            List<InspectedSource> allProjectSources
    ) {
        if (source == null) {
            return false;
        }

        // Direct controller exposure
        boolean isControllerClass = source.getClassDeclarations().stream().anyMatch(c ->
                c.getAnnotations().stream().anyMatch(a -> {
                    String name = a.getNameAsString();
                    return name.contains("RestController") || name.contains("Controller");
                })
        );
        if (isControllerClass) {
            return true;
        }

        String methodName = finding.getMethodName();
        MethodDeclaration method = source.getMethods().stream()
                .filter(m -> m.getNameAsString().equals(methodName))
                .findFirst()
                .orElse(null);

        if (method != null && method.isPublic()) {
            // Check if invoked by any controller in the project
            if (allProjectSources != null && !allProjectSources.isEmpty()) {
                String className = source.getPrimaryClassName();
                for (InspectedSource ps : allProjectSources) {
                    boolean psController = ps.getClassDeclarations().stream().anyMatch(c ->
                            c.getAnnotations().stream().anyMatch(a -> a.getNameAsString().contains("Controller"))
                    );
                    if (psController) {
                        String raw = ps.getRawSource();
                        if (raw.contains(className) || raw.contains(methodName)) {
                            return true;
                        }
                    }
                }
            }
            return true;
        }

        return false;
    }

    private void buildFailOpenChain(CausalChain.Builder builder, SecurityFinding finding) {
        builder.trigger("Untrusted invocation with null, malformed, or missing authorization payload")
                .rootCauseElement("CatchClause with access grant at lines " + finding.getStartLine() + "-" + finding.getEndLine())
                .addHop("1. Caller invokes '" + finding.getMethodName() + "' with an invalid or unexpected security context.")
                .addHop("2. Internal inspection triggers an unhandled exception (e.g. NullPointerException).")
                .addHop("3. The fail-open catch block intercepts the exception and executes 'return true;'.")
                .addHop("4. The authorization gate mistakenly grants access instead of denying it.")
                .exploitVector("Attacker intentionally triggers an exception (e.g. omitting token headers) to bypass authentication or access controls.")
                .businessImpact("Unauthorized access to restricted enterprise APIs, privilege escalation, and breach of tenant isolation.")
                .blastRadius(BlastRadius.TENANT_DATA);
    }

    private void buildSqlInjectionChain(CausalChain.Builder builder, SecurityFinding finding) {
        builder.trigger("Untrusted parameter passed into data-access layer")
                .rootCauseElement("Raw SQL concatenation at lines " + finding.getStartLine() + "-" + finding.getEndLine())
                .addHop("1. Method parameter receives unvalidated string input from API caller.")
                .addHop("2. Input is concatenated directly into SQL command string without parameterized placeholders (?).")
                .addHop("3. SQL sink executes command against persistence store.")
                .addHop("4. Database query engine parses attacker-supplied SQL clauses.")
                .exploitVector("Attacker injects SQL payloads (e.g., `' OR '1'='1'`) to extract sensitive rows or modify database state.")
                .businessImpact("Complete database compromise, data exfiltration, or loss of data integrity.")
                .blastRadius(BlastRadius.TENANT_DATA);
    }

    private void buildPathTraversalChain(CausalChain.Builder builder, SecurityFinding finding) {
        builder.trigger("Untrusted file path or filename parameter")
                .rootCauseElement("Unchecked File/Path instantiation at lines " + finding.getStartLine() + "-" + finding.getEndLine())
                .addHop("1. User provides relative path payload with '../' sequence.")
                .addHop("2. Path is concatenated into File / Path object without canonicalization (.normalize()).")
                .addHop("3. File system resolves path outside the intended base directory.")
                .addHop("4. Sensitive system or tenant file is accessed or overwritten.")
                .exploitVector("Attacker supplies traversal sequences (`../../etc/passwd`) to access files outside root storage.")
                .businessImpact("Arbitrary file read or write, potential host takeover, and credential leakage.")
                .blastRadius(BlastRadius.SYSTEM_WIDE);
    }

    private void buildUnclosedStreamChain(CausalChain.Builder builder, SecurityFinding finding) {
        builder.trigger("High-frequency file or network resource access under concurrent load")
                .rootCauseElement("Stream allocation missing try-with-resources at line " + finding.getStartLine())
                .addHop("1. Method instantiates I/O stream (e.g. FileInputStream) without try-with-resources.")
                .addHop("2. Stream is consumed; if an error occurs or GC is delayed, file descriptor remains allocated.")
                .addHop("3. Operating system file descriptor table steadily accumulates open handles.")
                .addHop("4. Process exhausts available file descriptors (EMFILE / Too many open files).")
                .exploitVector("Adversary generates repetitive traffic or causes early exceptions to induce file descriptor exhaustion.")
                .businessImpact("Service degradation, intermittent socket drops, and total Denial of Service.")
                .blastRadius(BlastRadius.SERVICE_COMPONENT);
    }

    private void buildVolatileCompoundChain(CausalChain.Builder builder, SecurityFinding finding) {
        builder.trigger("Concurrent multi-threaded mutations on shared state")
                .rootCauseElement("Compound mutation on volatile field at line " + finding.getStartLine())
                .addHop("1. Field is declared 'volatile' providing memory visibility but not mutual exclusion.")
                .addHop("2. Multiple worker threads concurrently execute read-modify-write operation (e.g. counter++).")
                .addHop("3. Thread interleaving causes lost updates (non-atomic increment/decrement).")
                .addHop("4. Application state, rate-limits, or billing counters become corrupted.")
                .exploitVector("High concurrent load triggers race condition leading to state inconsistency or rate-limit bypass.")
                .businessImpact("State corruption, incorrect transaction accounting, and concurrency failure.")
                .blastRadius(BlastRadius.SERVICE_COMPONENT);
    }

    private void buildSubprocessChain(CausalChain.Builder builder, SecurityFinding finding) {
        builder.trigger("Untrusted input passed to OS command execution")
                .rootCauseElement("Runtime.exec / ProcessBuilder invocation at line " + finding.getStartLine())
                .addHop("1. Method receives shell command arguments containing user-controlled characters.")
                .addHop("2. Command is executed via shell sub-process without argument tokenization.")
                .addHop("3. OS shell executes injected command chaining operators (; | &).")
                .addHop("4. Attacker gains interactive command execution on the host machine.")
                .exploitVector("Attacker appends command separators to execute arbitrary binaries under the application's UID.")
                .businessImpact("Complete host takeover, lateral movement across cluster, and infrastructure compromise.")
                .blastRadius(BlastRadius.SYSTEM_WIDE);
    }

    private void buildDeserializationChain(CausalChain.Builder builder, SecurityFinding finding) {
        builder.trigger("Untrusted serialized byte stream supplied over network or storage")
                .rootCauseElement("ObjectInputStream.readObject() call at line " + finding.getStartLine())
                .addHop("1. Application reads serialized Java objects without class filtering.")
                .addHop("2. Serialized payload instantiates gadget chains present on the classpath.")
                .addHop("3. Gadget chain execution invokes arbitrary Java methods during deserialization.")
                .addHop("4. Payload triggers remote code execution before object type validation completes.")
                .exploitVector("Attacker crafts serialized gadget payload to execute remote commands upon deserialization.")
                .businessImpact("Remote code execution, complete service takeover, and total confidentiality loss.")
                .blastRadius(BlastRadius.SYSTEM_WIDE);
    }

    private void buildHardcodedSecretChain(CausalChain.Builder builder, SecurityFinding finding) {
        builder.trigger("Static secret token or credential committed to version control")
                .rootCauseElement("High-entropy literal at lines " + finding.getStartLine() + "-" + finding.getEndLine())
                .addHop("1. Developer hardcodes API key, private key, or credential into source code.")
                .addHop("2. Secret is persisted across git commit logs and build artifacts.")
                .addHop("3. Unauthorized entity inspects repository history or decompiled binary.")
                .addHop("4. Extracted credential grants direct access to third-party or cloud services.")
                .exploitVector("Unauthorized actors search git logs or public artifacts to harvest credentials.")
                .businessImpact("Unauthorized access to cloud infrastructure, external billing charges, and data breach.")
                .blastRadius(BlastRadius.TENANT_DATA);
    }

    private void buildCsrfChain(CausalChain.Builder builder, SecurityFinding finding) {
        builder.trigger("Cross-site request executed from victim browser")
                .rootCauseElement("CSRF disabled without stateless session management at line " + finding.getStartLine())
                .addHop("1. Application explicitly disables CSRF protection in SecurityFilterChain.")
                .addHop("2. State-changing requests rely on ambient cookie session authentication.")
                .addHop("3. Attacker lures authenticated user to malicious third-party webpage.")
                .addHop("4. Browser dispatches forged state-changing request carrying session cookie.")
                .exploitVector("Attacker hosts malicious page that automatically submits transactions on behalf of logged-in users.")
                .businessImpact("Unauthorized state changes, account takeover, or unwanted financial transactions.")
                .blastRadius(BlastRadius.TENANT_DATA);
    }

    private void buildCorsChain(CausalChain.Builder builder, SecurityFinding finding) {
        builder.trigger("Cross-origin fetch initiated by third-party browser origin")
                .rootCauseElement("Wildcard CORS origin '*' at line " + finding.getStartLine())
                .addHop("1. Endpoint allows arbitrary origins ('*') in Access-Control-Allow-Origin.")
                .addHop("2. Malicious website scripts make cross-origin XHR/Fetch requests to this API.")
                .addHop("3. Server accepts cross-origin request and returns sensitive business response.")
                .addHop("4. Attacker script reads and exfiltrates the response payload.")
                .exploitVector("Malicious web page executes client-side fetch requests to read private user responses.")
                .businessImpact("Information disclosure and cross-origin data leakage.")
                .blastRadius(BlastRadius.SERVICE_COMPONENT);
    }

    private void buildLeakyAbstractionChain(CausalChain.Builder builder, SecurityFinding finding) {
        builder.trigger("Public API endpoint directly exposes database persistence entity")
                .rootCauseElement("Direct entity exposure in method at line " + finding.getStartLine())
                .addHop("1. Controller method returns or accepts raw database @Entity instead of decoupled DTO.")
                .addHop("2. Internal schema columns, audit fields, and relationship graphs are exposed over HTTP.")
                .addHop("3. API clients bind to internal database representations, creating tight coupling.")
                .addHop("4. Callers can exploit over-posting / mass-assignment by modifying internal entity fields.")
                .exploitVector("Adversary submits JSON payloads with additional internal entity fields (e.g. role, isAdmin) to alter sensitive columns.")
                .businessImpact("Mass assignment vulnerabilities, internal schema exposure, and fragile architectural coupling.")
                .blastRadius(BlastRadius.SERVICE_COMPONENT);
    }

    private void buildNonDeterministicChain(CausalChain.Builder builder, SecurityFinding finding) {
        builder.trigger("Business service invocation relying on unmockable system state")
                .rootCauseElement("System.currentTimeMillis() or Random call at line " + finding.getStartLine())
                .addHop("1. Business service method invokes global system time or unseeded random generator.")
                .addHop("2. Method behavior cannot be frozen, simulated, or deterministically tested across environments.")
                .addHop("3. Test suites suffer from intermittent flakiness depending on execution clock.")
                .addHop("4. Time-dependent edge cases (leap seconds, timezone shifts) remain unverified.")
                .exploitVector("Timing discrepancies and pseudo-random predictability in business workflows.")
                .businessImpact("Flaky CI/CD test pipelines, non-deterministic bugs, and race conditions in financial or auditing calculations.")
                .blastRadius(BlastRadius.LOCAL_METHOD);
    }

    private void buildCyclicDependencyChain(CausalChain.Builder builder, SecurityFinding finding) {
        builder.trigger("Cyclic cross-referencing between architectural modules")
                .rootCauseElement("Bidirectional package/class dependency at line " + finding.getStartLine())
                .addHop("1. Component A directly depends on and imports Component B.")
                .addHop("2. Component B reciprocally depends on and imports Component A.")
                .addHop("3. Layered architectural hierarchy is broken, forming a tightly coupled cycle.")
                .addHop("4. Classes cannot be refactored, tested in isolation, or extracted into standalone modules.")
                .exploitVector("Circular initialization deadlocks, memory leaks, and high cognitive overhead for developers.")
                .businessImpact("Architectural decay, inability to modularize codebase, and higher defect rates during changes.")
                .blastRadius(BlastRadius.LOCAL_METHOD);
    }

    private void buildGenericChain(CausalChain.Builder builder, SecurityFinding finding) {
        builder.trigger("Unverified execution condition")
                .rootCauseElement(finding.getDescription())
                .addHop("1. Flow enters method '" + finding.getMethodName() + "'.")
                .addHop("2. Rule '" + finding.getRule().getRuleId() + "' triggered on lines " + finding.getStartLine() + "-" + finding.getEndLine() + ".")
                .addHop("3. Flaw leads to potential violation of operational security constraints.")
                .exploitVector(finding.getCausalRationale())
                .businessImpact(finding.getRemediation())
                .blastRadius(BlastRadius.SERVICE_COMPONENT);
    }
}
