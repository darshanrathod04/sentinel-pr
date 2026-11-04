package com.sentinelpr.core.service;

import com.sentinelpr.client.SentinelClient;
import com.sentinelpr.core.model.InspectedSource;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.stream.Stream;

/**
 * <b>CodeInspectionService</b>
 *
 * <p>Inspects Java source files, projects, and directories using {@code client.project().parseAst(...)}
 * to construct structural AST graphs containing classes, methods, fields, and imports.</p>
 */
@Service
public class CodeInspectionService {

    private final SentinelClient client;

    public CodeInspectionService() {
        this(SentinelClient.getInstance());
    }

    public CodeInspectionService(SentinelClient client) {
        this.client = Objects.requireNonNull(client, "client must not be null");
    }

    /**
     * Inspects a single Java source file.
     */
    public InspectedSource inspectFile(Path javaFile) throws IOException {
        Objects.requireNonNull(javaFile, "javaFile must not be null");
        if (!Files.exists(javaFile)) {
            throw new IllegalArgumentException("Target Java file does not exist: " + javaFile);
        }
        return client.project().parseAst(javaFile);
    }

    /**
     * Inspects Java source code provided directly as a string.
     */
    public InspectedSource inspectSourceCode(String sourceCode, String simulatedPath) {
        Objects.requireNonNull(sourceCode, "sourceCode must not be null");
        Path path = simulatedPath != null ? Path.of(simulatedPath) : Path.of("InMemorySource.java");
        return client.project().parseAst(sourceCode, path);
    }

    /**
     * Recursively scans and inspects all Java files within a directory.
     */
    public List<InspectedSource> inspectDirectory(Path directoryPath) throws IOException {
        Objects.requireNonNull(directoryPath, "directoryPath must not be null");
        if (!Files.isDirectory(directoryPath)) {
            throw new IllegalArgumentException("Path is not a directory: " + directoryPath);
        }

        List<InspectedSource> results = new ArrayList<>();
        try (Stream<Path> stream = Files.walk(directoryPath)) {
            List<Path> sourceFiles = stream
                    .filter(Files::isRegularFile)
                    .filter(p -> !isIgnoredPath(p))
                    .filter(com.sentinelpr.core.model.SourceLanguage::isSupported)
                    .toList();

            for (Path sourceFile : sourceFiles) {
                try {
                    results.add(inspectFile(sourceFile));
                } catch (Exception e) {
                    System.err.println("[SentinelPR] Warning: could not parse " + sourceFile + ": " + e.getMessage());
                }
            }
        }
        return results;
    }

    private static boolean isIgnoredPath(Path path) {
        for (Path segment : path) {
            String name = segment.toString();
            if (name.equals(".git") || name.equals("node_modules") || name.equals(".venv")
                    || name.equals("venv") || name.equals("__pycache__") || name.equals(".pytest_cache")
                    || name.equals("target") || name.equals("dist") || name.equals("build")) {
                return true;
            }
        }
        return false;
    }

    /**
     * Inspects either a single file or a directory based on the given path.
     */
    public List<InspectedSource> inspectPath(Path targetPath) throws IOException {
        Objects.requireNonNull(targetPath, "targetPath must not be null");
        if (Files.isDirectory(targetPath)) {
            return inspectDirectory(targetPath);
        } else {
            return List.of(inspectFile(targetPath));
        }
    }
}
