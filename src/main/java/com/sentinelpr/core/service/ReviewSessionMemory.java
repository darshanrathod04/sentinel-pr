package com.sentinelpr.core.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.sentinelpr.client.SentinelClient;
import com.sentinelpr.core.model.ReviewReport;
import com.sentinelpr.core.model.SecurityFinding;
import com.shreeai.os.platform.sdk.MemorySDK;
import com.shreeai.os.platform.sdk.SDKResponse;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * <b>ReviewSessionMemory</b>
 *
 * <p>Uses {@code client.memory()} to store previous audit runs and avoid duplicate rule evaluations.</p>
 */
@Service
public class ReviewSessionMemory {

    private final SentinelClient client;
    private final MemorySDK memorySdk;
    private final ObjectMapper objectMapper;
    private final Map<String, ReviewReport> fastSessionCache = new ConcurrentHashMap<>();

    public ReviewSessionMemory() {
        this(SentinelClient.getInstance());
    }

    public ReviewSessionMemory(SentinelClient client) {
        this.client = Objects.requireNonNull(client, "client must not be null");
        this.memorySdk = client.memory();
        this.objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());
    }

    /**
     * Computes the SHA-256 fingerprint of the source text.
     */
    public String computeFingerprint(String source) {
        if (source == null) return "";
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(source.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            return Integer.toHexString(source.hashCode());
        }
    }

    /**
     * Checks if a previous audit run exists for this content fingerprint.
     */
    public boolean hasPreviousAudit(String fingerprint) {
        if (fingerprint == null || fingerprint.isBlank()) {
            return false;
        }

        if (fastSessionCache.containsKey(fingerprint)) {
            return true;
        }

        try {
            SDKResponse response = memorySdk.recall("AUDIT:" + fingerprint);
            if (response != null && response.answer() != null && !response.answer().isBlank()) {
                return !response.answer().contains("not found");
            }
        } catch (Exception e) {
            // Memory recall fallback
        }

        return false;
    }

    /**
     * Retrieves the previous audit report for this fingerprint, if available.
     */
    public ReviewReport getPreviousAudit(String fingerprint) {
        if (fingerprint == null) return null;
        return fastSessionCache.get(fingerprint);
    }

    /**
     * Stores an audit run in the Memory Kernel and fast session cache.
     */
    public void recordAuditRun(String fingerprint, ReviewReport report) {
        Objects.requireNonNull(fingerprint, "fingerprint must not be null");
        Objects.requireNonNull(report, "report must not be null");

        fastSessionCache.put(fingerprint, report);

        try {
            String title = "AUDIT:" + fingerprint;
            String content = String.format(
                    "Target: %s | Violations: %d | Status: %s | ScannedAt: %s",
                    report.getTargetPath(),
                    report.getVulnerabilityCount(),
                    report.getStatus(),
                    report.getTimestamp()
            );

            memorySdk.store(title, content);
            System.out.println("[SentinelPR:Memory] Recorded audit session into Memory Kernel for " + fingerprint.substring(0, Math.min(12, fingerprint.length())));
        } catch (Exception e) {
            System.out.println("[SentinelPR:Memory] Note: Memory kernel persistence: " + e.getMessage());
        }
    }

    /**
     * Clears session cache.
     */
    public void clearCache() {
        fastSessionCache.clear();
    }
}
