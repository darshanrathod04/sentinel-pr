package com.sentinelpr.core.remediation;

import com.sentinelpr.core.model.SecurityFinding;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * <b>RemediationContext</b>
 *
 * <p>Execution context passed to {@link RemediationStrategy} implementations during patch synthesis.</p>
 */
public class RemediationContext {

    private final String targetFilePath;
    private final List<SecurityFinding> allFindings;
    private final Map<String, Object> attributes;

    public RemediationContext(String targetFilePath, List<SecurityFinding> allFindings) {
        this(targetFilePath, allFindings, new HashMap<>());
    }

    public RemediationContext(String targetFilePath, List<SecurityFinding> allFindings, Map<String, Object> attributes) {
        this.targetFilePath = targetFilePath != null ? targetFilePath : "UnknownSource.java";
        this.allFindings = allFindings != null ? Collections.unmodifiableList(allFindings) : List.of();
        this.attributes = attributes != null ? new HashMap<>(attributes) : new HashMap<>();
    }

    public String getTargetFilePath() {
        return targetFilePath;
    }

    public List<SecurityFinding> getAllFindings() {
        return allFindings;
    }

    public Map<String, Object> getAttributes() {
        return Collections.unmodifiableMap(attributes);
    }

    public Object getAttribute(String key) {
        return attributes.get(key);
    }

    public void setAttribute(String key, Object value) {
        attributes.put(key, value);
    }
}
