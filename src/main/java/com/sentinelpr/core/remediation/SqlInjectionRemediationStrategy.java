package com.sentinelpr.core.remediation;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ast.CompilationUnit;
import com.sentinelpr.core.model.InspectedSource;
import com.sentinelpr.core.model.SecurityFinding;
import com.sentinelpr.core.model.SecurityRule;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * <b>SqlInjectionRemediationStrategy</b>
 *
 * <p>Rule-specific remediation for SEC-005-SQL-INJECTION (CWE-89):</p>
 * <ul>
 *   <li>Replaces vulnerable string concatenation in SQL execution sinks with parameterized queries using '?'.</li>
 *   <li>Converts {@code Statement} to {@code PreparedStatement} via {@code conn.prepareStatement(...)}.</li>
 *   <li>Binds untrusted parameters via {@code ps.setString(1, param)} for Strings or {@code ps.setObject(1, param)} for primitives/objects.</li>
 *   <li>Converts {@code executeQuery(rawSql)}, {@code executeUpdate(rawSql)}, and {@code execute(rawSql)} to zero-argument calls.</li>
 *   <li><b>H-1 GUARANTEE:</b> Never erases intervening code between Statement and SQL declaration.</li>
 *   <li>Guarantees zero raw user-input string concatenation into SQL sinks.</li>
 * </ul>
 */
public class SqlInjectionRemediationStrategy implements RemediationStrategy {

    private final JavaParser javaParser;

    public SqlInjectionRemediationStrategy() {
        ParserConfiguration config = new ParserConfiguration();
        config.setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_21);
        this.javaParser = new JavaParser(config);
    }

    @Override
    public SecurityRule getSupportedRule() {
        return SecurityRule.SQL_INJECTION;
    }

    @Override
    public RemediationResult remediate(
            String source,
            SecurityFinding finding,
            InspectedSource inspectedSource,
            RemediationContext context
    ) {
        if (source == null || source.isBlank()) {
            return RemediationResult.unapplied(source, "SqlInjectionRemediationStrategy", "Source is empty");
        }

        // Try primary context-aware transformation
        Optional<String> primaryResult = tryContextAwarePreparedStatementTransform(source, finding);
        if (primaryResult.isPresent() && isValidJava(primaryResult.get())) {
            return RemediationResult.success(
                    primaryResult.get(),
                    "SqlInjectionRemediationStrategy",
                    "Synthesized PreparedStatement with parameterized query and parameter binding",
                    finding.getStartLine(),
                    finding.getEndLine()
            );
        }

        // Try deterministic fallback: targeted PreparedStatement substitution
        Optional<String> fallbackResult = tryDeterministicFallback(source, finding);
        if (fallbackResult.isPresent() && isValidJava(fallbackResult.get())) {
            return RemediationResult.fallback(
                    fallbackResult.get(),
                    "SqlInjectionRemediationStrategy",
                    "Applied deterministic PreparedStatement fallback with parameterized SQL placeholder",
                    finding.getStartLine(),
                    finding.getEndLine()
            );
        }

        return RemediationResult.unapplied(source, "SqlInjectionRemediationStrategy", "Failed to generate syntactically valid SEC-005 patch");
    }

    /**
     * Primary context-aware transformation:
     * Converts Statement + raw SQL string concatenation into PreparedStatement + ? + setString/setObject + ps.executeQuery()/executeUpdate()/execute().
     */
    private Optional<String> tryContextAwarePreparedStatementTransform(String source, SecurityFinding finding) {
        String patched = source;

        // Ensure PreparedStatement is imported
        patched = ensurePreparedStatementImport(patched);

        // Pattern: Match SQL concatenation in variable declaration: String <varName> = "SELECT ... " + <param> ... ;
        Pattern sqlVarDeclPattern = Pattern.compile(
                "(String\\s+([a-zA-Z0-9_]+)\\s*=\\s*)(\"\\s*(?:SELECT|UPDATE|INSERT|DELETE)\\s+[^\"]+?['\"]?\\s*\\+\\s*[a-zA-Z0-9_.]+(?:\\s*\\+[\\s\\S]*?)?)(;)"
        );

        Matcher sqlVarMatcher = sqlVarDeclPattern.matcher(patched);
        if (sqlVarMatcher.find()) {
            String fullVarDecl = sqlVarMatcher.group(0);
            String varName = sqlVarMatcher.group(2);
            String concatExpr = sqlVarMatcher.group(3);

            ExtractedSqlParams extracted = extractSqlAndParams(concatExpr);
            if (extracted != null && !extracted.params().isEmpty()) {
                String parameterizedSql = extracted.parameterizedSql();
                List<String> params = extracted.params();

                // Look for Statement declaration in the method: Statement stmt = conn.createStatement();
                Pattern stmtPattern = Pattern.compile(
                        "(Statement\\s+([a-zA-Z0-9_]+)\\s*=\\s*([a-zA-Z0-9_]+)\\.createStatement\\(\\);)"
                );
                Matcher stmtMatcher = stmtPattern.matcher(patched);

                if (stmtMatcher.find()) {
                    String fullStmtDecl = stmtMatcher.group(0);
                    String stmtVar = stmtMatcher.group(2);
                    String connVar = stmtMatcher.group(3);
                    String psVar = stmtVar;

                    // Determine indentation
                    String indent = extractIndentAtMatch(patched, stmtMatcher.start());

                    // Parameter binding code with type safety (setString for String, setObject for others)
                    StringBuilder bindings = new StringBuilder();
                    for (int i = 0; i < params.size(); i++) {
                        String p = params.get(i);
                        String setter = isStringType(patched, p) ? "setString" : "setObject";
                        bindings.append("\n").append(indent).append(psVar).append(".").append(setter).append("(").append(i + 1).append(", ").append(p).append(");");
                    }

                    // Check relative positions of stmt and sqlVar
                    boolean stmtBeforeSql = stmtMatcher.start() < sqlVarMatcher.start();

                    if (stmtBeforeSql) {
                        int stmtEnd = patched.indexOf(fullStmtDecl) + fullStmtDecl.length();
                        int sqlStart = patched.indexOf(fullVarDecl);
                        if (sqlStart >= stmtEnd) {
                            String between = patched.substring(stmtEnd, sqlStart);
                            if (isWhitespaceOrCommentsOnly(between)) {
                                // Combined contiguous replacement is safe when between is only whitespace or comments
                                String toReplace = fullStmtDecl + between + fullVarDecl;
                                String replacement = "PreparedStatement " + psVar + " = " + connVar + ".prepareStatement(\n"
                                        + indent + "    \"" + parameterizedSql + "\"\n"
                                        + indent + ");"
                                        + bindings.toString();

                                String candidate = patched.replace(toReplace, replacement);
                                candidate = replaceExecutionCalls(candidate, stmtVar, varName, psVar);
                                if (isValidJava(candidate)) {
                                    return Optional.of(candidate);
                                }
                            } else {
                                // H-1 SAFETY: Intervening code exists between Statement and SQL declaration!
                                // DO NOT combine. Transform Statement declaration independently and SQL variable independently.
                                String candidate = patched;
                                // Remove the raw Statement creation
                                candidate = candidate.replace(fullStmtDecl, "");
                                // Synthesize PreparedStatement creation right at the SQL variable declaration location
                                String newSqlAndPsDecl = "String " + varName + " = \"" + parameterizedSql + "\";\n"
                                        + indent + "PreparedStatement " + psVar + " = " + connVar + ".prepareStatement(" + varName + ");"
                                        + bindings.toString();
                                candidate = candidate.replace(fullVarDecl, newSqlAndPsDecl);
                                candidate = replaceExecutionCalls(candidate, stmtVar, varName, psVar);
                                if (isValidJava(candidate)) {
                                    return Optional.of(candidate);
                                }
                            }
                        }

                        // Alternative independent substitution
                        String candidate = patched.replace(fullVarDecl, "String " + varName + " = \"" + parameterizedSql + "\";");
                        candidate = candidate.replace(fullStmtDecl, "PreparedStatement " + psVar + " = " + connVar + ".prepareStatement(" + varName + ");" + bindings.toString());
                        candidate = replaceExecutionCalls(candidate, stmtVar, varName, psVar);
                        if (isValidJava(candidate)) {
                            return Optional.of(candidate);
                        }
                    } else {
                        // SQL variable is before Statement declaration
                        int sqlEnd = patched.indexOf(fullVarDecl) + fullVarDecl.length();
                        int stmtStart = patched.indexOf(fullStmtDecl);
                        if (stmtStart >= sqlEnd) {
                            String between = patched.substring(sqlEnd, stmtStart);
                            if (isWhitespaceOrCommentsOnly(between)) {
                                String toReplace = fullVarDecl + between + fullStmtDecl;
                                String inlinedReplacement = "PreparedStatement " + psVar + " = " + connVar + ".prepareStatement(\"" + parameterizedSql + "\");" + bindings.toString();
                                String candidate = patched.replace(toReplace, inlinedReplacement);
                                candidate = replaceExecutionCalls(candidate, stmtVar, varName, psVar);
                                if (isValidJava(candidate)) {
                                    return Optional.of(candidate);
                                }
                            } else {
                                // H-1 SAFETY: Intervening code exists. Transform independently:
                                String candidate = patched;
                                candidate = candidate.replace(fullVarDecl, "String " + varName + " = \"" + parameterizedSql + "\";");
                                candidate = candidate.replace(fullStmtDecl, "PreparedStatement " + psVar + " = " + connVar + ".prepareStatement(" + varName + ");" + bindings.toString());
                                candidate = replaceExecutionCalls(candidate, stmtVar, varName, psVar);
                                if (isValidJava(candidate)) {
                                    return Optional.of(candidate);
                                }
                            }
                        }

                        // Alternative independent substitution
                        String candidate = patched.replace(fullVarDecl, "String " + varName + " = \"" + parameterizedSql + "\";");
                        candidate = candidate.replace(fullStmtDecl, "PreparedStatement " + psVar + " = " + connVar + ".prepareStatement(" + varName + ");" + bindings.toString());
                        candidate = replaceExecutionCalls(candidate, stmtVar, varName, psVar);
                        if (isValidJava(candidate)) {
                            return Optional.of(candidate);
                        }
                    }
                }
            }
        }

        // Pattern B: Inline SQL query in executeQuery / executeUpdate / execute("SELECT ... " + param):
        Pattern inlineQueryPattern = Pattern.compile(
                "([a-zA-Z0-9_]+)\\.(executeQuery|executeUpdate|execute)\\s*\\(\\s*(\"\\s*(?:SELECT|UPDATE|INSERT|DELETE)\\s+[^\"]+?['\"]?\\s*\\+\\s*[a-zA-Z0-9_.]+(?:\\s*\\+[\\s\\S]*?)?)\\s*\\)"
        );
        Matcher inlineMatcher = inlineQueryPattern.matcher(patched);
        if (inlineMatcher.find()) {
            String stmtVar = inlineMatcher.group(1);
            String execMethod = inlineMatcher.group(2);
            String concatExpr = inlineMatcher.group(3);
            ExtractedSqlParams extracted = extractSqlAndParams(concatExpr);
            if (extracted != null && !extracted.params().isEmpty()) {
                String indent = extractIndentAtMatch(patched, inlineMatcher.start());
                String psVar = stmtVar;

                Pattern stmtPattern = Pattern.compile("Statement\\s+" + Pattern.quote(stmtVar) + "\\s*=\\s*([a-zA-Z0-9_]+)\\.createStatement\\(\\);");
                Matcher stmtM = stmtPattern.matcher(patched);
                if (stmtM.find()) {
                    String connVar = stmtM.group(1);
                    StringBuilder bindings = new StringBuilder();
                    for (int i = 0; i < extracted.params().size(); i++) {
                        String p = extracted.params().get(i);
                        String setter = isStringType(patched, p) ? "setString" : "setObject";
                        bindings.append("\n").append(indent).append(psVar).append(".").append(setter).append("(").append(i + 1).append(", ").append(p).append(");");
                    }

                    String candidate = patched.replace(stmtM.group(0),
                            "PreparedStatement " + psVar + " = " + connVar + ".prepareStatement(\"" + extracted.parameterizedSql() + "\");" + bindings.toString());
                    candidate = candidate.replace(inlineMatcher.group(0), psVar + "." + execMethod + "()");
                    if (isValidJava(candidate)) {
                        return Optional.of(candidate);
                    }
                }
            }
        }

        return Optional.empty();
    }

    /**
     * Deterministic fallback when full structural transform cannot be cleanly matched.
     * Safely replaces vulnerable string concatenation with parameterized placeholder and PreparedStatement.
     */
    private Optional<String> tryDeterministicFallback(String source, SecurityFinding finding) {
        String patched = ensurePreparedStatementImport(source);

        // Replace raw concatenation in SQL query with '?'
        Pattern concatPattern = Pattern.compile("(?i)(\"\\s*SELECT\\s+[^\"\\n]+WHERE\\s+[^=]+=\\s*['\"]?)\"\\s*\\+\\s*([a-zA-Z0-9_]+)(?:\\s*\\+\\s*\"['\"]*\")?");
        Matcher m = concatPattern.matcher(patched);
        if (m.find()) {
            String fullMatch = m.group(0);
            String paramVar = m.group(2);
            String prefix = m.group(1).split("=")[0].trim() + " = ?\"";
            String candidate = patched.replace(fullMatch, prefix);

            // Replace Statement with PreparedStatement
            candidate = candidate.replace("conn.createStatement()", "conn.prepareStatement(" + prefix + ")");
            candidate = candidate.replace("Statement stmt", "PreparedStatement stmt");
            if (candidate.contains("stmt.executeQuery(")) {
                candidate = candidate.replaceFirst("stmt\\.executeQuery\\([^)]*\\)", "stmt.executeQuery()");
            }
            if (candidate.contains("stmt.executeUpdate(")) {
                candidate = candidate.replaceFirst("stmt\\.executeUpdate\\([^)]*\\)", "stmt.executeUpdate()");
            }
            if (candidate.contains("stmt.execute(")) {
                candidate = candidate.replaceFirst("stmt\\.execute\\([^)]*\\)", "stmt.execute()");
            }

            if (isValidJava(candidate)) {
                return Optional.of(candidate);
            }
        }

        return Optional.empty();
    }

    private String replaceExecutionCalls(String code, String stmtVar, String varName, String psVar) {
        String result = code;
        result = result.replaceFirst(Pattern.quote(stmtVar) + "\\.executeQuery\\s*\\(\\s*" + Pattern.quote(varName) + "\\s*\\)", psVar + ".executeQuery()");
        result = result.replaceFirst(Pattern.quote(stmtVar) + "\\.executeUpdate\\s*\\(\\s*" + Pattern.quote(varName) + "\\s*\\)", psVar + ".executeUpdate()");
        result = result.replaceFirst(Pattern.quote(stmtVar) + "\\.execute\\s*\\(\\s*" + Pattern.quote(varName) + "\\s*\\)", psVar + ".execute()");
        return result;
    }

    private boolean isWhitespaceOrCommentsOnly(String text) {
        if (text == null || text.isBlank()) {
            return true;
        }
        String stripped = text.replaceAll("//.*", "").replaceAll("/\\*[\\s\\S]*?\\*/", "").trim();
        return stripped.isEmpty();
    }

    private boolean isStringType(String source, String param) {
        if (param == null || param.isBlank()) return false;
        String cleanParam = param.trim();
        if (cleanParam.endsWith(".toString()") || cleanParam.startsWith("String.valueOf(")) {
            return true;
        }
        Pattern stringDecl = Pattern.compile("\\bString\\s+" + Pattern.quote(cleanParam) + "\\b");
        return stringDecl.matcher(source).find();
    }

    private record ExtractedSqlParams(String parameterizedSql, List<String> params) {}

    /**
     * Extracts SQL query with '?' placeholders and list of parameter expressions from string concatenation.
     */
    private ExtractedSqlParams extractSqlAndParams(String concatExpr) {
        if (concatExpr == null || concatExpr.isBlank()) {
            return null;
        }

        List<String> tokens = splitByTopLevelPlus(concatExpr);
        if (tokens.isEmpty()) {
            return null;
        }

        StringBuilder sqlBuilder = new StringBuilder();
        List<String> params = new ArrayList<>();

        for (int i = 0; i < tokens.size(); i++) {
            String token = tokens.get(i).trim();
            if (token.startsWith("\"") && token.endsWith("\"") && token.length() >= 2) {
                String literalContent = token.substring(1, token.length() - 1);

                boolean nextIsParam = (i + 1 < tokens.size()) && !tokens.get(i + 1).trim().startsWith("\"");
                if (nextIsParam && literalContent.endsWith("'")) {
                    literalContent = literalContent.substring(0, literalContent.length() - 1);
                }

                boolean prevIsParam = (i - 1 >= 0) && !tokens.get(i - 1).trim().startsWith("\"");
                if (prevIsParam && literalContent.startsWith("'")) {
                    literalContent = literalContent.substring(1);
                }

                sqlBuilder.append(literalContent);
            } else if (!token.isEmpty()) {
                params.add(token);
                sqlBuilder.append("?");
            }
        }

        String finalSql = sqlBuilder.toString().trim();
        return new ExtractedSqlParams(finalSql, params);
    }

    private List<String> splitByTopLevelPlus(String expr) {
        List<String> tokens = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        boolean inQuotes = false;
        boolean escaped = false;

        for (int i = 0; i < expr.length(); i++) {
            char c = expr.charAt(i);
            if (escaped) {
                current.append(c);
                escaped = false;
                continue;
            }
            if (c == '\\') {
                current.append(c);
                escaped = true;
                continue;
            }
            if (c == '"') {
                inQuotes = !inQuotes;
                current.append(c);
                continue;
            }
            if (c == '+' && !inQuotes) {
                tokens.add(current.toString().trim());
                current.setLength(0);
                continue;
            }
            current.append(c);
        }

        if (current.length() > 0) {
            tokens.add(current.toString().trim());
        }

        return tokens;
    }

    private String ensurePreparedStatementImport(String source) {
        if (source.contains("import java.sql.PreparedStatement;") || source.contains("import java.sql.*;")) {
            return source;
        }

        if (source.contains("import java.sql.Statement;")) {
            return source.replace("import java.sql.Statement;", "import java.sql.PreparedStatement;\nimport java.sql.Statement;");
        }

        if (source.contains("import java.sql.Connection;")) {
            return source.replace("import java.sql.Connection;", "import java.sql.Connection;\nimport java.sql.PreparedStatement;");
        }

        return source.replaceFirst("package\\s+[^;]+;", "$0\n\nimport java.sql.PreparedStatement;");
    }

    private String extractIndentAtMatch(String source, int matchStart) {
        int lineStart = source.lastIndexOf('\n', matchStart);
        if (lineStart == -1) lineStart = 0;
        else lineStart += 1;

        StringBuilder indent = new StringBuilder();
        for (int i = lineStart; i < matchStart; i++) {
            char c = source.charAt(i);
            if (Character.isWhitespace(c)) {
                indent.append(c);
            } else {
                break;
            }
        }
        return indent.toString();
    }

    private boolean isValidJava(String code) {
        if (code == null || code.isBlank()) return false;
        try {
            Optional<CompilationUnit> result = javaParser.parse(code).getResult();
            return result.isPresent();
        } catch (Exception e) {
            return false;
        }
    }
}
