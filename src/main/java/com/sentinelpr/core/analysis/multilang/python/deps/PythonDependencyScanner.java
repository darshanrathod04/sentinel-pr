package com.sentinelpr.core.analysis.multilang.python.deps;

import com.sentinelpr.core.model.SecurityFinding;
import com.sentinelpr.core.model.SecurityRule;
import com.sentinelpr.core.model.Severity;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * <b>PythonDependencyScanner</b>
 *
 * <p>Audits Python dependencies and lockfiles (requirements.txt, pyproject.toml, poetry.lock, Pipfile)
 * against a curated database of high-severity CVE advisories without requiring external network access.</p>
 */
public class PythonDependencyScanner {

    public record Advisory(
            String packageName,
            String maxVulnerableVersion,
            String cveId,
            Severity severity,
            String summary,
            String recommendedVersion
    ) {}

    private static final List<Advisory> ADVISORIES = List.of(
            new Advisory("urllib3", "1.26.17", "CVE-2023-45803", Severity.HIGH,
                    "urllib3 strips request body on cross-origin redirect but may leak Authorization header", "1.26.18"),
            new Advisory("requests", "2.30.0", "CVE-2023-32681", Severity.HIGH,
                    "Requests leaks Proxy-Authorization header to destination server on redirect", "2.31.0"),
            new Advisory("django", "4.2.9", "CVE-2024-24680", Severity.CRITICAL,
                    "Django potential denial of service vulnerability in intcomma filter", "4.2.10"),
            new Advisory("pyyaml", "5.3.1", "CVE-2020-14343", Severity.CRITICAL,
                    "PyYAML allows arbitrary code execution through full_load", "5.4"),
            new Advisory("cryptography", "41.0.5", "CVE-2023-49083", Severity.HIGH,
                    "cryptography NULL dereference when loading PKCS7 certificates", "41.0.6"),
            new Advisory("pillow", "10.0.0", "CVE-2023-44271", Severity.HIGH,
                    "Pillow uncontrolled resource consumption via ImageFont", "10.0.1"),
            new Advisory("sqlparse", "0.4.3", "CVE-2023-30608", Severity.HIGH,
                    "sqlparse regular expression denial of service (ReDoS)", "0.4.4"),
            new Advisory("paramiko", "2.10.0", "CVE-2022-24302", Severity.HIGH,
                    "Paramiko race condition leading to private key file disclosure", "2.10.1")
    );

    private static final Pattern REQ_LINE_PATTERN = Pattern.compile("^([a-zA-Z0-9_.-]+)\\s*(?:==|<=|~=|>=)?\\s*([0-9a-zA-Z_.-]+)?");
    private static final Pattern TOML_DEP_PATTERN = Pattern.compile("^[\\\"']?([a-zA-Z0-9_.-]+)[\\\"']?\\s*=\\s*[\\\"']?(?:[\\^~=<>]*\\s*)?([0-9a-zA-Z_.-]+)[\\\"']?");

    public List<SecurityFinding> scanFile(Path filePath) throws IOException {
        if (filePath == null || !Files.exists(filePath)) {
            return Collections.emptyList();
        }
        String content = Files.readString(filePath);
        return scanContent(content, filePath.getFileName().toString(), filePath.toString());
    }

    public List<SecurityFinding> scanContent(String content, String fileName, String fullPath) {
        if (content == null || content.isBlank() || fileName == null) {
            return Collections.emptyList();
        }

        String lowerName = fileName.toLowerCase(Locale.ROOT);
        Map<String, PinnedVersion> parsedPackages = new HashMap<>();

        if (lowerName.endsWith("requirements.txt") || lowerName.endsWith(".txt")) {
            parsedPackages = parseRequirementsTxt(content);
        } else if (lowerName.endsWith("pyproject.toml")) {
            parsedPackages = parsePyProjectToml(content);
        } else if (lowerName.endsWith("poetry.lock")) {
            parsedPackages = parsePoetryLock(content);
        } else if (lowerName.contains("pipfile")) {
            parsedPackages = parsePipfile(content);
        }

        List<SecurityFinding> findings = new ArrayList<>();
        for (Advisory advisory : ADVISORIES) {
            String pkg = advisory.packageName().toLowerCase(Locale.ROOT);
            if (parsedPackages.containsKey(pkg)) {
                PinnedVersion pinned = parsedPackages.get(pkg);
                if (isVersionVulnerable(pinned.version, advisory.maxVulnerableVersion())) {
                    findings.add(new SecurityFinding(
                            "FND-DEP-" + UUID.randomUUID().toString().substring(0, 8),
                            SecurityRule.FAIL_OPEN_SECURITY,
                            advisory.severity(),
                            fullPath,
                            fileName,
                            pkg,
                            pinned.line,
                            pinned.line,
                            pinned.rawLine,
                            "Vulnerable Dependency: " + pkg + "@" + pinned.version + " (" + advisory.cveId() + ")",
                            advisory.summary() + " (Vulnerable up to " + advisory.maxVulnerableVersion() + ").",
                            "Upgrade " + pkg + " to version " + advisory.recommendedVersion() + " or higher.",
                            0.98
                    ));
                }
            }
        }

        return findings;
    }

    private static class PinnedVersion {
        String version;
        int line;
        String rawLine;

        PinnedVersion(String version, int line, String rawLine) {
            this.version = version;
            this.line = line;
            this.rawLine = rawLine;
        }
    }

    private Map<String, PinnedVersion> parseRequirementsTxt(String content) {
        Map<String, PinnedVersion> map = new HashMap<>();
        String[] lines = content.split("\\r?\\n");
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i].trim();
            if (line.isEmpty() || line.startsWith("#") || line.startsWith("-")) continue;

            Matcher m = REQ_LINE_PATTERN.matcher(line);
            if (m.find()) {
                String pkg = m.group(1).toLowerCase(Locale.ROOT);
                String ver = m.group(2) != null ? m.group(2).trim() : "0.0.0";
                map.put(pkg, new PinnedVersion(ver, i + 1, line));
            }
        }
        return map;
    }

    private Map<String, PinnedVersion> parsePyProjectToml(String content) {
        Map<String, PinnedVersion> map = new HashMap<>();
        String[] lines = content.split("\\r?\\n");
        boolean inDeps = false;

        for (int i = 0; i < lines.length; i++) {
            String line = lines[i].trim();
            if (line.isEmpty() || line.startsWith("#")) continue;

            if (line.startsWith("[") && line.endsWith("]")) {
                inDeps = line.contains("dependencies") || line.contains("requires");
                continue;
            }

            if (line.contains("dependencies = [") || line.contains("requires = [") || line.equals("dependencies =") || line.equals("dependencies=[")) {
                inDeps = true;
                continue;
            }

            if (inDeps && line.startsWith("]")) {
                inDeps = false;
                continue;
            }

            if (inDeps) {
                String clean = line.replaceAll("[\"']", "").replaceAll(",$", "").trim();
                Matcher reqMatcher = REQ_LINE_PATTERN.matcher(clean);
                if (reqMatcher.find() && reqMatcher.group(2) != null) {
                    String pkg = reqMatcher.group(1).toLowerCase(Locale.ROOT);
                    String ver = reqMatcher.group(2).trim();
                    map.put(pkg, new PinnedVersion(ver, i + 1, line));
                    continue;
                }
                Matcher m = TOML_DEP_PATTERN.matcher(line);
                if (m.find()) {
                    String pkg = m.group(1).toLowerCase(Locale.ROOT);
                    String ver = m.group(2).trim();
                    map.put(pkg, new PinnedVersion(ver, i + 1, line));
                }
            }
        }
        return map;
    }

    private Map<String, PinnedVersion> parsePoetryLock(String content) {
        Map<String, PinnedVersion> map = new HashMap<>();
        String[] lines = content.split("\\r?\\n");
        String currentPkg = null;
        int pkgLine = 1;

        for (int i = 0; i < lines.length; i++) {
            String line = lines[i].trim();
            if (line.equals("[[package]]")) {
                currentPkg = null;
                continue;
            }
            if (line.startsWith("name =")) {
                currentPkg = line.substring(line.indexOf('=') + 1).replace("\"", "").replace("'", "").trim().toLowerCase(Locale.ROOT);
                pkgLine = i + 1;
            } else if (line.startsWith("version =") && currentPkg != null) {
                String ver = line.substring(line.indexOf('=') + 1).replace("\"", "").replace("'", "").trim();
                map.put(currentPkg, new PinnedVersion(ver, pkgLine, line));
                currentPkg = null;
            }
        }
        return map;
    }

    private Map<String, PinnedVersion> parsePipfile(String content) {
        Map<String, PinnedVersion> map = new HashMap<>();
        String[] lines = content.split("\\r?\\n");
        boolean inPackages = false;

        for (int i = 0; i < lines.length; i++) {
            String line = lines[i].trim();
            if (line.isEmpty() || line.startsWith("#")) continue;

            if (line.startsWith("[") && line.endsWith("]")) {
                inPackages = line.equals("[packages]") || line.equals("[dev-packages]");
                continue;
            }

            if (inPackages) {
                Matcher m = TOML_DEP_PATTERN.matcher(line);
                if (m.find()) {
                    String pkg = m.group(1).toLowerCase(Locale.ROOT);
                    String ver = m.group(2).trim();
                    map.put(pkg, new PinnedVersion(ver, i + 1, line));
                }
            }
        }
        return map;
    }

    public boolean isVersionVulnerable(String installedVersion, String maxVulnerableVersion) {
        if (installedVersion == null || maxVulnerableVersion == null) return false;
        // Clean leading specifiers: ==, ^, ~, <=, >=
        String cleanInstalled = installedVersion.replaceAll("^[~^=<>\\s]+", "");
        String cleanMax = maxVulnerableVersion.replaceAll("^[~^=<>\\s]+", "");

        int[] instParts = parseVersionParts(cleanInstalled);
        int[] maxParts = parseVersionParts(cleanMax);

        for (int i = 0; i < Math.max(instParts.length, maxParts.length); i++) {
            int inst = i < instParts.length ? instParts[i] : 0;
            int max = i < maxParts.length ? maxParts[i] : 0;
            if (inst < max) {
                return true;
            } else if (inst > max) {
                return false;
            }
        }
        return true; // Exactly equal to max vulnerable version
    }

    private int[] parseVersionParts(String ver) {
        String[] tokens = ver.split("[.-]");
        List<Integer> parts = new ArrayList<>();
        for (String t : tokens) {
            try {
                parts.add(Integer.parseInt(t));
            } catch (NumberFormatException ignored) {
                break;
            }
        }
        return parts.stream().mapToInt(Integer::intValue).toArray();
    }
}
