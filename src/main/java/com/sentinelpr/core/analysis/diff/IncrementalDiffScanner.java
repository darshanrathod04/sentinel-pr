package com.sentinelpr.core.analysis.diff;

import com.sentinelpr.core.model.SecurityFinding;
import com.sentinelpr.core.model.SuppressedFinding;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * <b>IncrementalDiffScanner</b>
 *
 * <p>Parses unified git diffs and patch files into hunk line intervals, extracting
 * added and modified lines per file. Filters security audit findings so only vulnerabilities
 * touching active PR diff hunks trigger blocking PR reviews, while pre-existing
 * defects outside modified hunks are categorized as baseline/suppressed.</p>
 */
public class IncrementalDiffScanner {

    private static final Pattern HUNK_HEADER_PATTERN =
            Pattern.compile("^@@\\s+-(\\d+)(?:,(\\d+))?\\s+\\+(\\d+)(?:,(\\d+))?\\s+@@(.*)$");

    private static final String DIFF_BASELINE_REASON =
            "Baseline finding outside incremental PR diff range";
    private static final String DIFF_BASELINE_TYPE = "DIFF_BASELINE";

    /**
     * Represents a single modified hunk interval in a unified diff.
     */
    public static class DiffHunk {
        private final int oldStart;
        private final int oldCount;
        private final int newStart;
        private final int newCount;
        private final Set<Integer> addedLines;
        private final Set<Integer> modifiedLines;

        public DiffHunk(int oldStart, int oldCount, int newStart, int newCount, Set<Integer> addedLines, Set<Integer> modifiedLines) {
            this.oldStart = oldStart;
            this.oldCount = oldCount;
            this.newStart = newStart;
            this.newCount = newCount;
            this.addedLines = Collections.unmodifiableSet(new HashSet<>(addedLines));
            this.modifiedLines = Collections.unmodifiableSet(new HashSet<>(modifiedLines));
        }

        public int getOldStart() {
            return oldStart;
        }

        public int getOldCount() {
            return oldCount;
        }

        public int getNewStart() {
            return newStart;
        }

        public int getNewCount() {
            return newCount;
        }

        public int getNewEnd() {
            return newStart + Math.max(newCount, 1) - 1;
        }

        public Set<Integer> getAddedLines() {
            return addedLines;
        }

        public Set<Integer> getModifiedLines() {
            return modifiedLines;
        }

        /**
         * Checks if the line range [startLine, endLine] intersects this hunk's new line interval
         * or contains any added/modified lines.
         */
        public boolean touchesRange(int startLine, int endLine) {
            if (startLine <= 0 && endLine <= 0) {
                return true;
            }
            int effectiveStart = Math.max(1, startLine);
            int effectiveEnd = Math.max(effectiveStart, endLine);

            int hunkStart = newStart;
            int hunkEnd = getNewEnd();

            // Check range intersection
            boolean overlaps = effectiveStart <= hunkEnd && effectiveEnd >= hunkStart;
            if (overlaps) {
                return true;
            }

            // Check if any added/modified line falls within [effectiveStart, effectiveEnd]
            for (int line : addedLines) {
                if (line >= effectiveStart && line <= effectiveEnd) {
                    return true;
                }
            }
            for (int line : modifiedLines) {
                if (line >= effectiveStart && line <= effectiveEnd) {
                    return true;
                }
            }

            return false;
        }

        @Override
        public String toString() {
            return "DiffHunk{new=" + newStart + ".." + getNewEnd() + ", added=" + addedLines.size() + '}';
        }
    }

    /**
     * Represents unified diff information for an individual file.
     */
    public static class FileDiff {
        private final String sourcePath;
        private final String targetPath;
        private final List<DiffHunk> hunks;
        private final Set<Integer> allAddedLines;

        public FileDiff(String sourcePath, String targetPath, List<DiffHunk> hunks) {
            this.sourcePath = sourcePath != null ? sourcePath : "";
            this.targetPath = targetPath != null ? targetPath : "";
            this.hunks = Collections.unmodifiableList(new ArrayList<>(hunks));
            Set<Integer> added = new HashSet<>();
            for (DiffHunk h : hunks) {
                added.addAll(h.getAddedLines());
            }
            this.allAddedLines = Collections.unmodifiableSet(added);
        }

        public String getSourcePath() {
            return sourcePath;
        }

        public String getTargetPath() {
            return targetPath;
        }

        public List<DiffHunk> getHunks() {
            return hunks;
        }

        public Set<Integer> getAllAddedLines() {
            return allAddedLines;
        }

        /**
         * Checks if the line range [startLine, endLine] touches any hunk in this file.
         */
        public boolean touchesRange(int startLine, int endLine) {
            for (DiffHunk hunk : hunks) {
                if (hunk.touchesRange(startLine, endLine)) {
                    return true;
                }
            }
            return false;
        }

        /**
         * Matches against a query path using normalized comparison, suffix matching,
         * and filename equivalence.
         */
        public boolean matchesPath(String filePath) {
            if (filePath == null || filePath.isBlank()) {
                return false;
            }
            String normQuery = normalizePath(filePath);
            String normTarget = normalizePath(targetPath);
            String normSource = normalizePath(sourcePath);

            if (!normTarget.isEmpty()) {
                if (normTarget.equalsIgnoreCase(normQuery)
                        || normQuery.endsWith(normTarget)
                        || normTarget.endsWith(normQuery)) {
                    return true;
                }
            }

            if (!normSource.isEmpty()) {
                if (normSource.equalsIgnoreCase(normQuery)
                        || normQuery.endsWith(normSource)
                        || normSource.endsWith(normQuery)) {
                    return true;
                }
            }

            // Fallback: match by file name if one is just the filename
            String queryFileName = getFileName(normQuery);
            String targetFileName = getFileName(normTarget);
            if (!queryFileName.isEmpty() && queryFileName.equalsIgnoreCase(targetFileName)) {
                return true;
            }

            return false;
        }

        private static String normalizePath(String path) {
            if (path == null) {
                return "";
            }
            String p = path.replace('\\', '/').trim();
            if (p.startsWith("a/") || p.startsWith("b/")) {
                p = p.substring(2);
            }
            if (p.startsWith("/")) {
                p = p.substring(1);
            }
            return p;
        }

        private static String getFileName(String path) {
            if (path == null || path.isEmpty()) {
                return "";
            }
            int idx = path.lastIndexOf('/');
            return idx >= 0 ? path.substring(idx + 1) : path;
        }

        @Override
        public String toString() {
            return "FileDiff{" + targetPath + ", hunks=" + hunks.size() + ", added=" + allAddedLines.size() + '}';
        }
    }

    /**
     * Result of filtering findings through an incremental diff.
     */
    public static class DiffFilterResult {
        private final List<SecurityFinding> activeFindings;
        private final List<SuppressedFinding> baselineFindings;

        public DiffFilterResult(List<SecurityFinding> activeFindings, List<SuppressedFinding> baselineFindings) {
            this.activeFindings = Collections.unmodifiableList(new ArrayList<>(activeFindings));
            this.baselineFindings = Collections.unmodifiableList(new ArrayList<>(baselineFindings));
        }

        public List<SecurityFinding> getActiveFindings() {
            return activeFindings;
        }

        public List<SuppressedFinding> getBaselineFindings() {
            return baselineFindings;
        }

        public boolean hasActiveFindings() {
            return !activeFindings.isEmpty();
        }

        public int getActiveCount() {
            return activeFindings.size();
        }

        public int getBaselineCount() {
            return baselineFindings.size();
        }
    }

    /**
     * Parses unified diff content from a patch file.
     */
    public Map<String, FileDiff> parse(Path patchFile) throws IOException {
        Objects.requireNonNull(patchFile, "patchFile must not be null");
        return parse(Files.readString(patchFile));
    }

    /**
     * Parses unified diff text into a map of target path to {@link FileDiff}.
     */
    public Map<String, FileDiff> parse(String diffContent) {
        Map<String, FileDiff> fileDiffs = new HashMap<>();
        if (diffContent == null || diffContent.isBlank()) {
            return fileDiffs;
        }

        String[] lines = diffContent.split("\\R");
        String currentSourcePath = null;
        String currentTargetPath = null;
        List<DiffHunk> currentHunks = new ArrayList<>();

        int currentOldStart = 0;
        int currentOldCount = 0;
        int currentNewStart = 0;
        int currentNewCount = 0;
        Set<Integer> currentAddedLines = new HashSet<>();
        Set<Integer> currentModifiedLines = new HashSet<>();
        int currentNewLine = 0;
        boolean inHunk = false;

        for (String line : lines) {
            if (line.startsWith("diff --git ")) {
                // Flush previous file
                if (currentTargetPath != null) {
                    if (inHunk) {
                        currentHunks.add(new DiffHunk(currentOldStart, currentOldCount, currentNewStart, currentNewCount, currentAddedLines, currentModifiedLines));
                        inHunk = false;
                    }
                    FileDiff fd = new FileDiff(currentSourcePath, currentTargetPath, currentHunks);
                    fileDiffs.put(cleanPath(currentTargetPath), fd);
                    currentHunks = new ArrayList<>();
                }
                currentSourcePath = null;
                currentTargetPath = null;
            } else if (line.startsWith("--- ")) {
                currentSourcePath = parseFilePath(line.substring(4));
            } else if (line.startsWith("+++ ")) {
                currentTargetPath = parseFilePath(line.substring(4));
            } else if (line.startsWith("@@ ")) {
                // Flush previous hunk if any
                if (inHunk) {
                    currentHunks.add(new DiffHunk(currentOldStart, currentOldCount, currentNewStart, currentNewCount, currentAddedLines, currentModifiedLines));
                }
                Matcher matcher = HUNK_HEADER_PATTERN.matcher(line);
                if (matcher.find()) {
                    currentOldStart = Integer.parseInt(matcher.group(1));
                    currentOldCount = matcher.group(2) != null ? Integer.parseInt(matcher.group(2)) : 1;
                    currentNewStart = Integer.parseInt(matcher.group(3));
                    currentNewCount = matcher.group(4) != null ? Integer.parseInt(matcher.group(4)) : 1;
                    currentNewLine = currentNewStart;
                    currentAddedLines = new HashSet<>();
                    currentModifiedLines = new HashSet<>();
                    inHunk = true;
                }
            } else if (inHunk) {
                if (line.startsWith("+")) {
                    currentAddedLines.add(currentNewLine);
                    currentNewLine++;
                } else if (line.startsWith("-")) {
                    currentModifiedLines.add(currentNewLine);
                    // Deleted line does not increment new file line counter
                } else if (line.startsWith(" ")) {
                    currentNewLine++;
                } else if (line.startsWith("\\")) {
                    // "\ No newline at end of file"
                } else if (line.isEmpty()) {
                    currentNewLine++;
                }
            }
        }

        // Flush last hunk and file
        if (inHunk) {
            currentHunks.add(new DiffHunk(currentOldStart, currentOldCount, currentNewStart, currentNewCount, currentAddedLines, currentModifiedLines));
        }
        if (currentTargetPath != null) {
            FileDiff fd = new FileDiff(currentSourcePath, currentTargetPath, currentHunks);
            fileDiffs.put(cleanPath(currentTargetPath), fd);
        } else if (currentSourcePath != null) {
            FileDiff fd = new FileDiff(currentSourcePath, currentSourcePath, currentHunks);
            fileDiffs.put(cleanPath(currentSourcePath), fd);
        }

        return fileDiffs;
    }

    /**
     * Checks whether a security finding touches the active diff hunks for its file.
     */
    public boolean isFindingInDiff(SecurityFinding finding, Map<String, FileDiff> fileDiffs) {
        if (finding == null || fileDiffs == null || fileDiffs.isEmpty()) {
            return false;
        }

        FileDiff matchingDiff = findMatchingFileDiff(finding.getTargetFile(), fileDiffs);
        if (matchingDiff == null) {
            // File not modified in diff at all
            return false;
        }

        return matchingDiff.touchesRange(finding.getStartLine(), finding.getEndLine());
    }

    /**
     * Filters a list of findings against the parsed diff. Findings touching modified hunks
     * remain active; findings outside diff hunks are returned as suppressed baseline findings.
     */
    public DiffFilterResult filterFindings(List<SecurityFinding> findings, Map<String, FileDiff> fileDiffs) {
        if (fileDiffs == null || fileDiffs.isEmpty()) {
            // If no diff provided or diff is empty, all findings remain active
            return new DiffFilterResult(findings, List.of());
        }

        List<SecurityFinding> active = new ArrayList<>();
        List<SuppressedFinding> baseline = new ArrayList<>();

        for (SecurityFinding finding : findings) {
            if (isFindingInDiff(finding, fileDiffs)) {
                active.add(finding);
            } else {
                baseline.add(new SuppressedFinding(finding, DIFF_BASELINE_REASON, DIFF_BASELINE_TYPE));
            }
        }

        return new DiffFilterResult(active, baseline);
    }

    /**
     * Filters findings for a specific file against parsed diffs.
     */
    public DiffFilterResult filterFindingsForFile(List<SecurityFinding> findings, String filePath, Map<String, FileDiff> fileDiffs) {
        if (fileDiffs == null || fileDiffs.isEmpty()) {
            return new DiffFilterResult(findings, List.of());
        }

        FileDiff fileDiff = findMatchingFileDiff(filePath, fileDiffs);
        if (fileDiff == null) {
            // File was not modified in this PR diff, all its findings are baseline
            List<SuppressedFinding> baseline = new ArrayList<>();
            for (SecurityFinding f : findings) {
                baseline.add(new SuppressedFinding(f, DIFF_BASELINE_REASON, DIFF_BASELINE_TYPE));
            }
            return new DiffFilterResult(List.of(), baseline);
        }

        List<SecurityFinding> active = new ArrayList<>();
        List<SuppressedFinding> baseline = new ArrayList<>();

        for (SecurityFinding finding : findings) {
            if (fileDiff.touchesRange(finding.getStartLine(), finding.getEndLine())) {
                active.add(finding);
            } else {
                baseline.add(new SuppressedFinding(finding, DIFF_BASELINE_REASON, DIFF_BASELINE_TYPE));
            }
        }

        return new DiffFilterResult(active, baseline);
    }

    /**
     * Resolves the {@link FileDiff} matching the given file path.
     */
    public FileDiff findMatchingFileDiff(String filePath, Map<String, FileDiff> fileDiffs) {
        if (filePath == null || fileDiffs == null) {
            return null;
        }

        // 1. Direct key match
        String clean = cleanPath(filePath);
        if (fileDiffs.containsKey(clean)) {
            return fileDiffs.get(clean);
        }

        // 2. Iterative pattern match using FileDiff.matchesPath
        for (FileDiff fd : fileDiffs.values()) {
            if (fd.matchesPath(filePath)) {
                return fd;
            }
        }

        return null;
    }

    private static String parseFilePath(String raw) {
        if (raw == null) {
            return "";
        }
        String p = raw.trim();
        int tabIdx = p.indexOf('\t');
        if (tabIdx >= 0) {
            p = p.substring(0, tabIdx);
        }
        return cleanPath(p);
    }

    private static String cleanPath(String path) {
        if (path == null) {
            return "";
        }
        String p = path.replace('\\', '/').trim();
        if (p.startsWith("a/") || p.startsWith("b/")) {
            p = p.substring(2);
        }
        if (p.startsWith("/")) {
            p = p.substring(1);
        }
        return p;
    }
}
