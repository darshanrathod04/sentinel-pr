package com.sentinelpr.benchmark.realistic.sec002_03;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

/**
 * EnterpriseLogArchiverService - Noisy realistic log archival service (~220 LOC).
 * Provides rolling log rotation, gzip compression, archive integrity verification,
 * and retention policy enforcement with strict deterministic try-with-resources.
 */
public class EnterpriseLogArchiverService {

    private final Path logStorageDir;
    private final Path archiveStorageDir;
    private final Map<String, Long> compressionStats = new HashMap<>();

    public EnterpriseLogArchiverService(Path logStorageDir, Path archiveStorageDir) {
        this.logStorageDir = Objects.requireNonNull(logStorageDir, "logStorageDir must not be null");
        this.archiveStorageDir = Objects.requireNonNull(archiveStorageDir, "archiveStorageDir must not be null");
    }

    public record ArchiveMetadata(
            String sourceLogName,
            String archivePath,
            long originalSizeBytes,
            long compressedSizeBytes,
            double compressionRatio,
            Instant archivedAt
    ) {}

    public ArchiveMetadata compressAndArchive(String logFileName) throws IOException {
        validateFilename(logFileName);
        Path sourcePath = logStorageDir.resolve(logFileName).normalize();
        if (!Files.exists(sourcePath) || !Files.isRegularFile(sourcePath)) {
            throw new IllegalArgumentException("Source log file does not exist: " + sourcePath);
        }

        String archiveFileName = logFileName + "." + LocalDate.now() + ".gz";
        Path targetArchivePath = archiveStorageDir.resolve(archiveFileName).normalize();

        long originalSize = Files.size(sourcePath);
        byte[] buffer = new byte[8192];

        try (InputStream inStream = new FileInputStream(sourcePath.toFile());
             OutputStream outStream = new FileOutputStream(targetArchivePath.toFile());
             GZIPOutputStream gzipOut = new GZIPOutputStream(outStream)) {

            int bytesRead;
            while ((bytesRead = inStream.read(buffer)) != -1) {
                gzipOut.write(buffer, 0, bytesRead);
            }
            gzipOut.finish();
        }

        long compressedSize = Files.size(targetArchivePath);
        double ratio = originalSize > 0 ? (double) compressedSize / originalSize : 1.0;
        compressionStats.put(archiveFileName, compressedSize);

        return new ArchiveMetadata(logFileName, targetArchivePath.toString(), originalSize, compressedSize, ratio, Instant.now());
    }

    public boolean verifyArchiveIntegrity(Path archivePath) {
        if (archivePath == null || !Files.exists(archivePath)) {
            return false;
        }

        byte[] buffer = new byte[8192];
        try (InputStream fileIn = new FileInputStream(archivePath.toFile());
             GZIPInputStream gzipIn = new GZIPInputStream(fileIn)) {

            long totalDecompressed = 0;
            int bytesRead;
            while ((bytesRead = gzipIn.read(buffer)) != -1) {
                totalDecompressed += bytesRead;
            }
            return totalDecompressed >= 0;
        } catch (IOException e) {
            logError("Integrity check failed for " + archivePath, e);
            return false;
        }
    }

    public List<String> inspectLogPreview(String logFileName, int maxLines) throws IOException {
        validateFilename(logFileName);
        Path path = logStorageDir.resolve(logFileName).normalize();
        if (!Files.exists(path)) {
            return Collections.emptyList();
        }

        List<String> preview = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(new FileReader(path.toFile()))) {
            String line;
            int count = 0;
            while ((line = reader.readLine()) != null && count < maxLines) {
                preview.add(line);
                count++;
            }
        }
        return preview;
    }

    public int purgeExpiredArchives(int retentionDays) throws IOException {
        if (retentionDays <= 0) {
            throw new IllegalArgumentException("Retention days must be positive");
        }

        Instant cutoff = Instant.now().minusSeconds((long) retentionDays * 86400L);
        int purgedCount = 0;

        File[] files = archiveStorageDir.toFile().listFiles();
        if (files != null) {
            for (File file : files) {
                if (file.isFile() && file.getName().endsWith(".gz")) {
                    Instant lastModified = Instant.ofEpochMilli(file.lastModified());
                    if (lastModified.isBefore(cutoff)) {
                        if (file.delete()) {
                            purgedCount++;
                        }
                    }
                }
            }
        }
        return purgedCount;
    }

    public Map<String, Long> getCompressionStatistics() {
        return Collections.unmodifiableMap(compressionStats);
    }

    public void appendAuditMarker(Path targetFile, String marker) throws IOException {
        Objects.requireNonNull(targetFile, "targetFile cannot be null");
        Objects.requireNonNull(marker, "marker cannot be null");

        try (FileOutputStream fos = new FileOutputStream(targetFile.toFile(), true)) {
            byte[] bytes = (marker + System.lineSeparator()).getBytes(java.nio.charset.StandardCharsets.UTF_8);
            fos.write(bytes);
        }
    }

    private void validateFilename(String filename) {
        if (filename == null || filename.isBlank()) {
            throw new IllegalArgumentException("Filename cannot be blank");
        }
        if (filename.contains("..") || filename.contains("/") || filename.contains("\\")) {
            throw new SecurityException("Invalid filename pattern: " + filename);
        }
    }

    private void logError(String message, Throwable t) {
        System.err.printf(Locale.ROOT, "[LOG_ARCHIVER_ERROR] %s: %s%n", message, t.getMessage());
    }
}
