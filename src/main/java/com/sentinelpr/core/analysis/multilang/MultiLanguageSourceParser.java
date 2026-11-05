package com.sentinelpr.core.analysis.multilang;

import com.sentinelpr.core.model.InspectedSource;
import com.sentinelpr.core.model.SourceLanguage;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * <b>MultiLanguageSourceParser</b>
 *
 * <p>Parses non-Java source files (Kotlin, Python, JavaScript, TypeScript) into {@link InspectedSource}
 * instances by extracting structural declarations, imports, classes, and language-specific metadata.</p>
 */
public class MultiLanguageSourceParser {

    private static final Pattern KOTLIN_PACKAGE = Pattern.compile("(?m)^\\s*package\\s+([a-zA-Z0-9_.]+)");
    private static final Pattern KOTLIN_IMPORT = Pattern.compile("(?m)^\\s*import\\s+([a-zA-Z0-9_.*]+)");
    private static final Pattern KOTLIN_CLASS = Pattern.compile("(?m)^\\s*(?:public\\s+|internal\\s+|open\\s+|data\\s+|sealed\\s+)*(?:class|interface|object)\\s+([a-zA-Z0-9_]+)");

    private static final Pattern PYTHON_IMPORT = Pattern.compile("(?m)^\\s*(?:import\\s+([a-zA-Z0-9_., ]+)|from\\s+([a-zA-Z0-9_.]+)\\s+import\\s+([a-zA-Z0-9_., *]+))");
    private static final Pattern PYTHON_CLASS = Pattern.compile("(?m)^\\s*class\\s+([a-zA-Z0-9_]+)");

    private static final Pattern JS_IMPORT = Pattern.compile("(?m)^\\s*(?:import\\s+.*?from\\s+['\"](.*?)['\"]|const\\s+.*?=\\s*require\\(['\"](.*?)['\"]\\))");
    private static final Pattern JS_CLASS = Pattern.compile("(?m)^\\s*(?:export\\s+)?(?:default\\s+)?class\\s+([a-zA-Z0-9_]+)");

    public InspectedSource parse(String source, Path path) {
        if (source == null) {
            source = "";
        }
        SourceLanguage lang = SourceLanguage.fromPath(path);

        String packageName = "";
        String primaryClassName = extractDefaultClassName(path);
        List<String> imports = new ArrayList<>();
        com.sentinelpr.core.analysis.multilang.python.ast.PythonModule pythonAst = null;

        switch (lang) {
            case KOTLIN -> {
                Matcher pkgMatcher = KOTLIN_PACKAGE.matcher(source);
                if (pkgMatcher.find()) {
                    packageName = pkgMatcher.group(1);
                }
                Matcher impMatcher = KOTLIN_IMPORT.matcher(source);
                while (impMatcher.find()) {
                    imports.add(impMatcher.group(1));
                }
                Matcher clsMatcher = KOTLIN_CLASS.matcher(source);
                if (clsMatcher.find()) {
                    primaryClassName = clsMatcher.group(1);
                }
            }
            case PYTHON -> {
                com.sentinelpr.core.analysis.multilang.python.PythonSourceParser pyParser =
                        new com.sentinelpr.core.analysis.multilang.python.PythonSourceParser();
                pythonAst = pyParser.parse(source, path);
                for (var imp : pythonAst.getImports()) {
                    imports.add(imp.getEffectiveName());
                }
                if (!pythonAst.getClasses().isEmpty()) {
                    primaryClassName = pythonAst.getClasses().get(0).getName();
                }
            }
            case JAVASCRIPT, TYPESCRIPT -> {
                Matcher impMatcher = JS_IMPORT.matcher(source);
                while (impMatcher.find()) {
                    String mod = impMatcher.group(1) != null ? impMatcher.group(1) : impMatcher.group(2);
                    imports.add(mod);
                }
                Matcher clsMatcher = JS_CLASS.matcher(source);
                if (clsMatcher.find()) {
                    primaryClassName = clsMatcher.group(1);
                }
            }
            default -> {
                // Java is parsed via JavaParser in ProjectFacade
            }
        }

        return new InspectedSource(
                path,
                source,
                null, // compilationUnit is null for non-Java AST
                packageName,
                primaryClassName,
                imports,
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                pythonAst
        );
    }

    private String extractDefaultClassName(Path path) {
        if (path == null || path.getFileName() == null) {
            return "UnknownModule";
        }
        String fileName = path.getFileName().toString();
        int dot = fileName.lastIndexOf('.');
        return dot > 0 ? fileName.substring(0, dot) : fileName;
    }
}
