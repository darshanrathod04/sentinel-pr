package com.sentinelpr.core.export.sarif;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.sentinelpr.core.model.ReviewReport;
import com.sentinelpr.core.model.SecurityFinding;
import com.sentinelpr.core.model.SecurityRule;
import com.sentinelpr.core.model.Severity;
import com.sentinelpr.core.model.UnifiedDiffPatch;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * <b>SarifReportGenerator</b>
 *
 * <p>Generates OASIS SARIF v2.1.0 compliant reports for consumption by GitHub Code Scanning,
 * GitLab SAST, SonarQube, and IDE analyzers.</p>
 */
public class SarifReportGenerator {

    public static final String SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json";
    public static final String SARIF_VERSION = "2.1.0";
    public static final String TOOL_NAME = "SentinelPR";
    public static final String TOOL_VERSION = "1.0.0";
    public static final String TOOL_INFO_URI = "https://github.com/darshanrathod04/sentinel-pr";

    private static final Pattern CWE_PATTERN = Pattern.compile("CWE-(\\d+)");

    private final ObjectMapper objectMapper;

    public SarifReportGenerator() {
        this.objectMapper = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .enable(SerializationFeature.INDENT_OUTPUT);
    }

    public SarifReportGenerator(ObjectMapper objectMapper) {
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper must not be null");
    }

    /**
     * Converts a {@link ReviewReport} into a SARIF v2.1.0 compliant JSON string.
     */
    public String generateSarifJson(ReviewReport report) {
        Objects.requireNonNull(report, "report must not be null");
        Map<String, Object> sarifMap = buildSarifModel(report);
        try {
            return objectMapper.writeValueAsString(sarifMap);
        } catch (Exception e) {
            throw new RuntimeException("Failed to serialize SARIF report: " + e.getMessage(), e);
        }
    }

    /**
     * Exports the SARIF report directly to the given destination file.
     */
    public void exportToFile(ReviewReport report, Path outputPath) throws IOException {
        Objects.requireNonNull(report, "report must not be null");
        Objects.requireNonNull(outputPath, "outputPath must not be null");

        if (outputPath.getParent() != null) {
            Files.createDirectories(outputPath.getParent());
        }
        String sarifJson = generateSarifJson(report);
        Files.writeString(outputPath, sarifJson);
    }

    /**
     * Builds the structured Map representation corresponding to the SARIF 2.1.0 schema.
     */
    public Map<String, Object> buildSarifModel(ReviewReport report) {
        Map<String, Object> root = new LinkedHashMap<>();
        root.put("$schema", SARIF_SCHEMA);
        root.put("version", SARIF_VERSION);

        List<Map<String, Object>> runs = new ArrayList<>();
        runs.add(buildRun(report));
        root.put("runs", runs);

        return root;
    }

    private Map<String, Object> buildRun(ReviewReport report) {
        Map<String, Object> run = new LinkedHashMap<>();

        // Tool Driver & Rules Catalog
        Map<String, Object> tool = new LinkedHashMap<>();
        Map<String, Object> driver = new LinkedHashMap<>();
        driver.put("name", TOOL_NAME);
        driver.put("version", TOOL_VERSION);
        driver.put("informationUri", TOOL_INFO_URI);

        List<Map<String, Object>> rules = new ArrayList<>();
        Map<String, Integer> ruleIndexMap = new HashMap<>();

        SecurityRule[] allRules = SecurityRule.values();
        for (int i = 0; i < allRules.length; i++) {
            SecurityRule rule = allRules[i];
            ruleIndexMap.put(rule.getRuleId(), i);

            Map<String, Object> ruleObj = new LinkedHashMap<>();
            ruleObj.put("id", rule.getRuleId());
            ruleObj.put("name", sanitizeRuleName(rule.getTitle()));
            ruleObj.put("shortDescription", Map.of("text", rule.getTitle()));
            ruleObj.put("fullDescription", Map.of("text", rule.getExplanation()));

            String helpUri = resolveHelpUri(rule);
            if (helpUri != null) {
                ruleObj.put("helpUri", helpUri);
            }

            ruleObj.put("defaultConfiguration", Map.of("level", toSarifLevel(rule.getSeverity())));
            rules.add(ruleObj);
        }

        driver.put("rules", rules);
        tool.put("driver", driver);
        run.put("tool", tool);

        // Results mapping
        List<Map<String, Object>> results = new ArrayList<>();

        for (SecurityFinding finding : report.getFindings()) {
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("ruleId", finding.getRule().getRuleId());

            Integer idx = ruleIndexMap.get(finding.getRule().getRuleId());
            if (idx != null) {
                result.put("ruleIndex", idx);
            }

            result.put("level", toSarifLevel(finding.getSeverity()));
            result.put("message", Map.of("text", finding.getDescription()));

            // Physical location
            List<Map<String, Object>> locations = new ArrayList<>();
            Map<String, Object> loc = new LinkedHashMap<>();
            Map<String, Object> physicalLoc = new LinkedHashMap<>();

            String normalizedFile = normalizeUri(finding.getTargetFile());
            physicalLoc.put("artifactLocation", Map.of(
                    "uri", normalizedFile.isEmpty() ? "unknown" : normalizedFile,
                    "uriBaseId", "%SRCROOT%"
            ));

            Map<String, Object> region = new LinkedHashMap<>();
            region.put("startLine", Math.max(1, finding.getStartLine()));
            region.put("endLine", Math.max(finding.getStartLine(), finding.getEndLine()));
            if (finding.getVulnerableSnippet() != null && !finding.getVulnerableSnippet().isBlank()) {
                region.put("snippet", Map.of("text", finding.getVulnerableSnippet()));
            }
            physicalLoc.put("region", region);
            loc.put("physicalLocation", physicalLoc);
            locations.add(loc);
            result.put("locations", locations);

            // Properties / metadata
            Map<String, Object> properties = new LinkedHashMap<>();
            properties.put("causalRationale", finding.getCausalRationale());
            properties.put("remediation", finding.getRemediation());
            properties.put("confidence", finding.getConfidence());

            UnifiedDiffPatch patch = findPatchForFinding(finding, report.getPatches());
            if (patch != null) {
                properties.put("patchStatus", patch.getStatus().name());
                properties.put("patchVerified", patch.isVerified());
                properties.put("regressionVerified", patch.isRegressionVerified());
                if (patch.getUnifiedDiff() != null && !patch.getUnifiedDiff().isBlank()) {
                    properties.put("unifiedDiff", patch.getUnifiedDiff());
                }
            }
            result.put("properties", properties);

            results.add(result);
        }

        run.put("results", results);
        return run;
    }

    /**
     * Maps SentinelPR {@link Severity} to OASIS SARIF v2.1.0 severity levels:
     * <ul>
     *   <li>CRITICAL, HIGH -> "error"</li>
     *   <li>MEDIUM -> "warning"</li>
     *   <li>LOW, INFO -> "note"</li>
     * </ul>
     */
    public static String toSarifLevel(Severity severity) {
        if (severity == null) {
            return "warning";
        }
        return switch (severity) {
            case CRITICAL, HIGH -> "error";
            case MEDIUM -> "warning";
            case LOW, INFO -> "note";
        };
    }

    private static String sanitizeRuleName(String title) {
        if (title == null || title.isBlank()) {
            return "SecurityRule";
        }
        return title.replaceAll("[^a-zA-Z0-9]", "");
    }

    private static String resolveHelpUri(SecurityRule rule) {
        if (rule.getExplanation() != null) {
            Matcher m = CWE_PATTERN.matcher(rule.getExplanation());
            if (m.find()) {
                return "https://cwe.mitre.org/data/definitions/" + m.group(1) + ".html";
            }
        }
        return "https://github.com/darshanrathod04/sentinel-pr/rules/" + rule.getRuleId();
    }

    private static String normalizeUri(String path) {
        if (path == null) {
            return "";
        }
        String p = path.replace('\\', '/').trim();
        if (p.startsWith("/")) {
            p = p.substring(1);
        }
        return p;
    }

    private UnifiedDiffPatch findPatchForFinding(SecurityFinding finding, List<UnifiedDiffPatch> patches) {
        if (finding == null || patches == null || patches.isEmpty()) {
            return null;
        }
        for (UnifiedDiffPatch p : patches) {
            if (p.getFindingId() != null && (p.getFindingId().equals(finding.getId()) || p.getFindingId().contains(finding.getId()))) {
                return p;
            }
        }
        for (UnifiedDiffPatch p : patches) {
            if (p.getRuleId() != null && p.getRuleId().contains(finding.getRule().getRuleId())) {
                return p;
            }
        }
        for (UnifiedDiffPatch p : patches) {
            if (p.getTargetFile() != null && !p.getTargetFile().isBlank()) {
                String normPatchFile = normalizeUri(p.getTargetFile());
                String normFindingFile = normalizeUri(finding.getTargetFile());
                if (normPatchFile.equals(normFindingFile) || normPatchFile.endsWith(normFindingFile) || normFindingFile.endsWith(normPatchFile)) {
                    return p;
                }
            }
        }
        return patches.get(0);
    }
}
