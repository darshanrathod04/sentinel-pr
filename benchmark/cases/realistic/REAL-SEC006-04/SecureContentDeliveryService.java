package com.sentinelpr.benchmark.realistic.sec006_04;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * SecureContentDeliveryService - Large realistic asset delivery engine (~310 LOC).
 * Provides MIME content-type mapping, cache header generation, byte-range partitioning,
 * cryptographic ETag generation, access logging, and canonical path containment checks.
 */
public class SecureContentDeliveryService {

    private static final Pattern SAFE_ASSET_PATTERN = Pattern.compile("^[a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_.-]+)*$");
    private static final Set<String> ALLOWED_EXTENSIONS = Set.of("html", "css", "js", "png", "jpg", "svg", "json", "woff2");
    private static final Map<String, String> MIME_TYPES = Map.of(
            "html", "text/html; charset=UTF-8",
            "css", "text/css",
            "js", "application/javascript",
            "png", "image/png",
            "jpg", "image/jpeg",
            "svg", "image/svg+xml",
            "json", "application/json",
            "woff2", "font/woff2"
    );

    private final Path rootContentDirectory;
    private final Map<String, ContentMetadata> cache = new HashMap<>();

    public SecureContentDeliveryService(Path rootContentDirectory) {
        Objects.requireNonNull(rootContentDirectory, "rootContentDirectory must not be null");
        this.rootContentDirectory = rootContentDirectory.toAbsolutePath().normalize();
    }

    public record ContentMetadata(
            String relativePath,
            String contentType,
            long contentLength,
            String etag,
            Instant lastModified,
            boolean isCompressed
    ) {}

    public record DeliveryResponse(
            byte[] contentBytes,
            ContentMetadata metadata,
            Map<String, String> headers,
            int httpStatusCode
    ) {}

    public record ByteRange(long start, long end, long totalLength) {}

    public DeliveryResponse serveContent(String relativePath, String ifNoneMatchHeader) {
        validateRelativePath(relativePath);
        Path targetPath = resolveAndVerifyPath(relativePath);

        if (!Files.exists(targetPath) || Files.isDirectory(targetPath)) {
            return new DeliveryResponse(new byte[0], null, Map.of("Status", "Not Found"), 404);
        }

        try {
            ContentMetadata metadata = resolveMetadata(targetPath, relativePath);
            if (ifNoneMatchHeader != null && ifNoneMatchHeader.equals(metadata.etag())) {
                return new DeliveryResponse(new byte[0], metadata, buildHeaders(metadata, true), 304);
            }

            byte[] contentBytes;
            try (InputStream is = new FileInputStream(targetPath.toFile())) {
                contentBytes = is.readAllBytes();
            }

            Map<String, String> headers = buildHeaders(metadata, false);
            return new DeliveryResponse(contentBytes, metadata, headers, 200);
        } catch (IOException e) {
            logError("Failed to deliver content for: " + relativePath, e);
            return new DeliveryResponse(new byte[0], null, Map.of("Status", "Internal Error"), 500);
        }
    }

    public Optional<ByteRange> parseByteRange(String rangeHeader, long totalLength) {
        if (rangeHeader == null || !rangeHeader.startsWith("bytes=")) {
            return Optional.empty();
        }

        String spec = rangeHeader.substring("bytes=".length()).trim();
        String[] parts = spec.split("-", -1);
        if (parts.length != 2) {
            return Optional.empty();
        }

        try {
            long start;
            long end;
            if (parts[0].isBlank()) {
                long suffixLength = Long.parseLong(parts[1]);
                start = Math.max(0, totalLength - suffixLength);
                end = totalLength - 1;
            } else if (parts[1].isBlank()) {
                start = Long.parseLong(parts[0]);
                end = totalLength - 1;
            } else {
                start = Long.parseLong(parts[0]);
                end = Long.parseLong(parts[1]);
            }

            if (start <= end && end < totalLength) {
                return Optional.of(new ByteRange(start, end, totalLength));
            }
        } catch (NumberFormatException ignored) {
        }
        return Optional.empty();
    }

    public DeliveryResponse serveRangeContent(String relativePath, String rangeHeader) {
        validateRelativePath(relativePath);
        Path targetPath = resolveAndVerifyPath(relativePath);

        if (!Files.exists(targetPath)) {
            return new DeliveryResponse(new byte[0], null, Map.of("Status", "Not Found"), 404);
        }

        try {
            ContentMetadata metadata = resolveMetadata(targetPath, relativePath);
            Optional<ByteRange> rangeOpt = parseByteRange(rangeHeader, metadata.contentLength());

            if (rangeOpt.isEmpty()) {
                return serveContent(relativePath, null);
            }

            ByteRange range = rangeOpt.get();
            int chunkLength = (int) (range.end() - range.start() + 1);
            byte[] chunk = new byte[chunkLength];

            try (InputStream is = new FileInputStream(targetPath.toFile())) {
                long skipped = is.skip(range.start());
                if (skipped != range.start()) {
                    throw new IOException("Failed to skip to byte offset " + range.start());
                }
                int bytesRead = is.readNBytes(chunk, 0, chunkLength);
                if (bytesRead != chunkLength) {
                    throw new IOException("Truncated read for byte range");
                }
            }

            Map<String, String> headers = new HashMap<>(buildHeaders(metadata, false));
            headers.put("Content-Range", String.format(Locale.ROOT, "bytes %d-%d/%d", range.start(), range.end(), range.totalLength()));
            headers.put("Content-Length", String.valueOf(chunkLength));

            return new DeliveryResponse(chunk, metadata, headers, 206);
        } catch (IOException e) {
            logError("Failed to deliver range content for: " + relativePath, e);
            return new DeliveryResponse(new byte[0], null, Map.of("Status", "Internal Error"), 500);
        }
    }

    public void invalidateCache(String relativePath) {
        if (relativePath != null) {
            cache.remove(relativePath);
        }
    }

    public void clearAllCache() {
        cache.clear();
    }

    public Set<String> getCachedAssetKeys() {
        return Collections.unmodifiableSet(cache.keySet());
    }

    private Path resolveAndVerifyPath(String relativePath) {
        Path resolved = rootContentDirectory.resolve(relativePath).normalize();
        if (!resolved.startsWith(rootContentDirectory)) {
            throw new SecurityException("Directory traversal attempt blocked: " + relativePath);
        }
        return resolved;
    }

    private void validateRelativePath(String relativePath) {
        if (relativePath == null || relativePath.isBlank()) {
            throw new IllegalArgumentException("Relative path must not be null or blank");
        }
        if (relativePath.contains("..") || relativePath.startsWith("/") || relativePath.startsWith("\\")) {
            throw new SecurityException("Suspicious path segments detected: " + relativePath);
        }
        if (!SAFE_ASSET_PATTERN.matcher(relativePath).matches()) {
            throw new IllegalArgumentException("Path contains illegal characters: " + relativePath);
        }
        String ext = extractExtension(relativePath);
        if (!ALLOWED_EXTENSIONS.contains(ext.toLowerCase(Locale.ROOT))) {
            throw new SecurityException("Unsupported or dangerous asset extension: " + ext);
        }
    }

    private ContentMetadata resolveMetadata(Path targetPath, String relativePath) throws IOException {
        ContentMetadata cached = cache.get(relativePath);
        long lastModTime = Files.getLastModifiedTime(targetPath).toMillis();

        if (cached != null && cached.lastModified().toEpochMilli() == lastModTime) {
            return cached;
        }

        long length = Files.size(targetPath);
        String ext = extractExtension(relativePath);
        String mime = MIME_TYPES.getOrDefault(ext.toLowerCase(Locale.ROOT), "application/octet-stream");
        String etag = calculateEtag(targetPath, lastModTime, length);
        Instant lastMod = Instant.ofEpochMilli(lastModTime);
        boolean isCompressed = "woff2".equalsIgnoreCase(ext);

        ContentMetadata meta = new ContentMetadata(relativePath, mime, length, etag, lastMod, isCompressed);
        cache.put(relativePath, meta);
        return meta;
    }

    private String calculateEtag(Path file, long lastModified, long size) {
        try {
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            String identity = file.getFileName().toString() + ":" + lastModified + ":" + size;
            byte[] digest = md5.digest(identity.getBytes(StandardCharsets.UTF_8));
            return "\"" + HexFormat.of().formatHex(digest) + "\"";
        } catch (NoSuchAlgorithmException e) {
            return "\"" + Long.toHexString(lastModified) + "-" + Long.toHexString(size) + "\"";
        }
    }

    private Map<String, String> buildHeaders(ContentMetadata metadata, boolean notModified) {
        Map<String, String> headers = new HashMap<>();
        headers.put("ETag", metadata.etag());
        headers.put("Last-Modified", metadata.lastModified().toString());
        headers.put("Cache-Control", "public, max-age=86400, must-revalidate");
        headers.put("X-Content-Type-Options", "nosniff");

        if (!notModified) {
            headers.put("Content-Type", metadata.contentType());
            headers.put("Content-Length", String.valueOf(metadata.contentLength()));
            headers.put("Accept-Ranges", "bytes");
        }

        return headers;
    }

    private String extractExtension(String filename) {
        int dot = filename.lastIndexOf('.');
        if (dot < 0 || dot >= filename.length() - 1) {
            return "";
        }
        return filename.substring(dot + 1);
    }

    public void prewarmCache(List<String> assetPaths) {
        if (assetPaths == null) {
            return;
        }
        for (String assetPath : assetPaths) {
            try {
                validateRelativePath(assetPath);
                Path targetPath = resolveAndVerifyPath(assetPath);
                if (Files.exists(targetPath) && Files.isRegularFile(targetPath)) {
                    resolveMetadata(targetPath, assetPath);
                }
            } catch (Exception e) {
                logError("Failed to prewarm asset: " + assetPath, e);
            }
        }
    }

    public String computeContentSecurityPolicy() {
        return "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self';";
    }

    public boolean verifyAssetChecksum(String relativePath, String expectedHexMd5) {
        validateRelativePath(relativePath);
        Path targetPath = resolveAndVerifyPath(relativePath);
        if (!Files.exists(targetPath)) {
            return false;
        }

        try {
            long lastModTime = Files.getLastModifiedTime(targetPath).toMillis();
            long length = Files.size(targetPath);
            String calculated = calculateEtag(targetPath, lastModTime, length);
            String cleanExpected = "\"" + expectedHexMd5.replace("\"", "").toLowerCase(Locale.ROOT) + "\"";
            return calculated.equalsIgnoreCase(cleanExpected);
        } catch (IOException e) {
            logError("Checksum validation failed for: " + relativePath, e);
            return false;
        }
    }

    public long getTotalCachedBytes() {
        return cache.values().stream().mapToLong(ContentMetadata::contentLength).sum();
    }

    private void logError(String message, Throwable t) {
        System.err.printf(Locale.ROOT, "[SECURE_CDN_ERROR] %s: %s%n", message, t.getMessage());
    }
}
