package com.sentinelpr.client;

import com.shreeai.os.platform.sdk.DiagnosticsSDK;
import com.shreeai.os.platform.sdk.ExecutionSDK;
import com.shreeai.os.platform.sdk.IdentitySDK;
import com.shreeai.os.platform.sdk.KnowledgeSDK;
import com.shreeai.os.platform.sdk.MemorySDK;
import com.shreeai.os.platform.sdk.PlanningSDK;
import com.shreeai.os.platform.sdk.ReflectionSDK;
import com.shreeai.os.platform.sdk.SDKResponse;
import com.shreeai.os.platform.sdk.SettingsSDK;
import com.shreeai.os.platform.sdk.ShreeAI;
import com.shreeai.os.platform.sdk.ShreeClient;
import com.shreeai.os.platform.sdk.events.EventManager;
import com.shreeai.os.platform.services.ProviderType;

import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

/**
 * <b>SentinelClient</b>
 *
 * <p>Singleton bootstrap and cognitive facade for SentinelPR, built on top of the
 * Shree AI OS 10-SDK surface.</p>
 *
 * <p>Supports Google Gemini via BYOK with seamless in-memory fallback.</p>
 */
public final class SentinelClient {

    private static final AtomicReference<SentinelClient> INSTANCE = new AtomicReference<>();

    private final ShreeAI shreeAi;
    private final ShreeClient shreeClient;
    private final ProjectFacade project;
    private final ReasoningFacade reasoning;
    private final DeveloperFacade developer;
    private final MemorySDK memory;

    private SentinelClient(ShreeAI shreeAi) {
        this.shreeAi = Objects.requireNonNull(shreeAi, "shreeAi must not be null");
        this.shreeClient = shreeAi.client();
        this.project = new ProjectFacade(shreeAi.project());
        this.reasoning = new ReasoningFacade(shreeAi);
        this.developer = new DeveloperFacade(shreeAi);
        this.memory = shreeAi.memory();
    }

    /**
     * Retrieves the active singleton instance, initializing with default/environment configuration
     * if not already bootstrapped.
     */
    public static SentinelClient getInstance() {
        SentinelClient existing = INSTANCE.get();
        if (existing != null) {
            return existing;
        }

        synchronized (SentinelClient.class) {
            if (INSTANCE.get() == null) {
                INSTANCE.set(bootstrap(null));
            }
            return INSTANCE.get();
        }
    }

    /**
     * Bootstraps a new SentinelClient instance using ShreeAI.builder().apiKey(...).build().
     *
     * @param explicitApiKey optional explicit API key (falls back to SHREE_API_KEY or "local")
     * @return configured SentinelClient
     */
    public static SentinelClient bootstrap(String explicitApiKey) {
        String apiKey = explicitApiKey;
        if (apiKey == null || apiKey.isBlank()) {
            apiKey = System.getenv("SHREE_API_KEY");
        }
        if (apiKey == null || apiKey.isBlank()) {
            apiKey = "local";
        }

        // Bootstrap the Shree AI OS runtime and 10-SDK surface
        ShreeAI ai = ShreeAI.builder()
                .apiKey(apiKey)
                .build();

        // BYOK configuration for Gemini (gemini-3.6-flash / default provider) with fallback
        String geminiApiKey = System.getenv("GEMINI_API_KEY");
        if (geminiApiKey != null && !geminiApiKey.isBlank()) {
            try {
                ai.settings().configureApiKey(ProviderType.GEMINI, geminiApiKey);
                System.out.println("[SentinelPR] BYOK Gemini provider configured successfully.");
            } catch (Exception e) {
                System.out.println("[SentinelPR] Note: Falling back to in-memory LLM provider (" + e.getMessage() + ")");
            }
        } else {
            System.out.println("[SentinelPR] No GEMINI_API_KEY provided; operating in deterministic in-memory provider mode.");
        }

        SentinelClient client = new SentinelClient(ai);
        INSTANCE.set(client);
        return client;
    }

    /**
     * Resets the singleton instance (useful in isolated test suites).
     */
    public static void reset() {
        INSTANCE.set(null);
    }

    // ─── 10-SDK Facades ────────────────────────────────────────────────────────

    /**
     * Project intelligence & AST parsing facade (client.project()).
     */
    public ProjectFacade project() {
        return project;
    }

    /**
     * Cognitive reasoning and AST rule evaluation facade (client.reasoning()).
     */
    public ReasoningFacade reasoning() {
        return reasoning;
    }

    /**
     * Patch synthesis and code generation facade (client.developer()).
     */
    public DeveloperFacade developer() {
        return developer;
    }

    /**
     * Memory Kernel facade (client.memory()).
     */
    public MemorySDK memory() {
        return memory;
    }

    /**
     * Identity Kernel facade.
     */
    public IdentitySDK identity() {
        return shreeAi.identity();
    }

    /**
     * Knowledge Kernel facade.
     */
    public KnowledgeSDK knowledge() {
        return shreeAi.knowledge();
    }

    /**
     * Planning Kernel facade.
     */
    public PlanningSDK planning() {
        return shreeAi.planning();
    }

    /**
     * Execution Kernel facade.
     */
    public ExecutionSDK execution() {
        return shreeAi.execution();
    }

    /**
     * Reflection Kernel facade.
     */
    public ReflectionSDK reflection() {
        return shreeAi.reflection();
    }

    /**
     * BYOK Settings SDK facade.
     */
    public SettingsSDK settings() {
        return shreeAi.settings();
    }

    /**
     * Platform Diagnostics facade.
     */
    public DiagnosticsSDK diagnostics() {
        return shreeAi.diagnostics();
    }

    /**
     * Runtime Event Bus Manager.
     */
    public EventManager events() {
        return shreeAi.events();
    }

    /**
     * Returns underlying ShreeAI instance.
     */
    public ShreeAI shreeAI() {
        return shreeAi;
    }

    /**
     * Returns underlying ShreeClient instance.
     */
    public ShreeClient shreeClient() {
        return shreeClient;
    }

    /**
     * Direct chat through the Shree AI OS LLM router.
     */
    public SDKResponse chat(String message) {
        return shreeAi.chat(message);
    }
}
