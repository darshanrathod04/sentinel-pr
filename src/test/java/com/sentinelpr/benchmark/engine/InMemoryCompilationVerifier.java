package com.sentinelpr.benchmark.engine;

import javax.tools.*;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * In-memory Java compilation verifier using javax.tools.JavaCompiler.
 * Does not emit any .class files to disk.
 */
public class InMemoryCompilationVerifier {

    private static final Pattern PACKAGE_PATTERN = Pattern.compile("(?m)^\\s*package\\s+([a-zA-Z0-9_.]+)\\s*;");
    private static final Pattern CLASS_PATTERN = Pattern.compile("(?m)^\\s*(?:public\\s+)?(?:class|interface|enum|record)\\s+([a-zA-Z0-9_]+)");

    private final JavaCompiler compiler;

    public InMemoryCompilationVerifier() {
        this.compiler = ToolProvider.getSystemJavaCompiler();
        if (this.compiler == null) {
            throw new IllegalStateException("System Java Compiler not available. Running on JRE instead of JDK?");
        }
    }

    public static class CompilationResult {
        private final boolean success;
        private final List<String> diagnostics;

        public CompilationResult(boolean success, List<String> diagnostics) {
            this.success = success;
            this.diagnostics = diagnostics != null ? diagnostics : Collections.emptyList();
        }

        public boolean isSuccess() {
            return success;
        }

        public List<String> getDiagnostics() {
            return diagnostics;
        }
    }

    /**
     * Compiles a single source file in-memory.
     */
    public CompilationResult compileSingle(String sourceCode) {
        return compileSources(Collections.singletonList(sourceCode));
    }

    /**
     * Compiles multiple source files together in-memory.
     */
    public CompilationResult compileSources(List<String> sourceCodes) {
        DiagnosticCollector<JavaFileObject> diagnosticCollector = new DiagnosticCollector<>();
        StandardJavaFileManager standardFileManager = compiler.getStandardFileManager(
                diagnosticCollector, null, StandardCharsets.UTF_8);

        JavaFileManager memoryFileManager = new ForwardingJavaFileManager<JavaFileManager>(standardFileManager) {
            @Override
            public JavaFileObject getJavaFileForOutput(Location location, String className,
                                                      JavaFileObject.Kind kind, FileObject sibling) {
                return new SimpleJavaFileObject(URI.create("mem:///" + className.replace('.', '/') + kind.extension), kind) {
                    @Override
                    public OutputStream openOutputStream() {
                        return new ByteArrayOutputStream();
                    }
                };
            }
        };

        List<JavaFileObject> compilationUnits = new ArrayList<>();
        int index = 0;
        for (String source : sourceCodes) {
            String path = resolveSourcePath(source, index++);
            compilationUnits.add(new InMemorySourceFile(path, source));
        }

        List<String> options = new ArrayList<>();
        options.add("-proc:none"); // Disable annotation processing for speed
        String classpath = System.getProperty("java.class.path");
        if (classpath != null && !classpath.isBlank()) {
            options.add("-classpath");
            options.add(classpath);
        }

        try {
            JavaCompiler.CompilationTask task = compiler.getTask(
                    null,
                    memoryFileManager,
                    diagnosticCollector,
                    options,
                    null,
                    compilationUnits
            );

            boolean success = Boolean.TRUE.equals(task.call());
            List<String> diagnostics = new ArrayList<>();
            for (Diagnostic<? extends JavaFileObject> diag : diagnosticCollector.getDiagnostics()) {
                if (diag.getKind() == Diagnostic.Kind.ERROR) {
                    diagnostics.add(String.format("Line %d:%d: %s",
                            diag.getLineNumber(), diag.getColumnNumber(), diag.getMessage(Locale.ENGLISH)));
                }
            }
            return new CompilationResult(success, diagnostics);
        } catch (Exception e) {
            return new CompilationResult(false, Collections.singletonList("Compilation error: " + e.getMessage()));
        } finally {
            try {
                memoryFileManager.close();
            } catch (Exception ignored) {
            }
        }
    }

    private String resolveSourcePath(String sourceCode, int fallbackIndex) {
        String packageName = "";
        Matcher pkgMatcher = PACKAGE_PATTERN.matcher(sourceCode);
        if (pkgMatcher.find()) {
            packageName = pkgMatcher.group(1).trim();
        }

        String className = "Source" + fallbackIndex;
        Matcher classMatcher = CLASS_PATTERN.matcher(sourceCode);
        if (classMatcher.find()) {
            className = classMatcher.group(1).trim();
        }

        String dir = packageName.isEmpty() ? "" : packageName.replace('.', '/') + "/";
        return dir + className + ".java";
    }

    private static class InMemorySourceFile extends SimpleJavaFileObject {
        private final String content;

        InMemorySourceFile(String path, String content) {
            super(URI.create("string:///" + path), Kind.SOURCE);
            this.content = content;
        }

        @Override
        public CharSequence getCharContent(boolean ignoreEncodingErrors) {
            return content;
        }
    }
}
