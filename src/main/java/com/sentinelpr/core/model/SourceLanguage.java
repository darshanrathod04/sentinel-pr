package com.sentinelpr.core.model;

import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * <b>SourceLanguage</b>
 *
 * <p>Supported programming languages for multi-language AST inspection and static security analysis.</p>
 */
public enum SourceLanguage {

    JAVA(".java"),
    KOTLIN(".kt", ".kts"),
    PYTHON(".py", ".pyw", ".pyi"),
    JAVASCRIPT(".js", ".mjs", ".cjs", ".jsx"),
    TYPESCRIPT(".ts", ".tsx", ".mts", ".cts");

    private final List<String> extensions;

    SourceLanguage(String... extensions) {
        this.extensions = Collections.unmodifiableList(Arrays.asList(extensions));
    }

    public List<String> getExtensions() {
        return extensions;
    }

    public String getPrimaryExtension() {
        return extensions.get(0);
    }

    public boolean isJvmLanguage() {
        return this == JAVA || this == KOTLIN;
    }

    /**
     * Resolves the source language from a file path based on its extension.
     */
    public static SourceLanguage fromPath(Path path) {
        if (path == null) {
            return JAVA;
        }
        return fromFileName(path.getFileName() != null ? path.getFileName().toString() : "");
    }

    /**
     * Resolves the source language from a file name.
     */
    public static SourceLanguage fromFileName(String fileName) {
        if (fileName == null || fileName.isBlank()) {
            return JAVA;
        }
        String lower = fileName.toLowerCase(Locale.ROOT);
        for (SourceLanguage lang : values()) {
            for (String ext : lang.extensions) {
                if (lower.endsWith(ext)) {
                    return lang;
                }
            }
        }
        return JAVA;
    }

    /**
     * Checks if a file path belongs to a recognized supported language.
     */
    public static boolean isSupported(Path path) {
        if (path == null) {
            return false;
        }
        String fileName = path.getFileName() != null ? path.getFileName().toString().toLowerCase(Locale.ROOT) : "";
        for (SourceLanguage lang : values()) {
            for (String ext : lang.extensions) {
                if (fileName.endsWith(ext)) {
                    return true;
                }
            }
        }
        return false;
    }
}
