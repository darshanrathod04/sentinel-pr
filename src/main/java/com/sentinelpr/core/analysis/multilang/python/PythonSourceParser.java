package com.sentinelpr.core.analysis.multilang.python;

import com.sentinelpr.core.analysis.multilang.python.ast.*;

import java.nio.file.Path;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * <b>PythonSourceParser</b>
 *
 * <p>Production-grade, zero-dependency pure-Java Python parser producing structural ASTs
 * with accurate source locations, docstrings, decorators, functions, classes, statements, and expressions.</p>
 */
public class PythonSourceParser {

    private static final Pattern FROM_IMPORT_PATTERN = Pattern.compile("^from\\s+([a-zA-Z0-9_.]+)\\s+import\\s+(.+)$");
    private static final Pattern IMPORT_PATTERN = Pattern.compile("^import\\s+(.+)$");
    private static final Pattern CLASS_PATTERN = Pattern.compile("^class\\s+([a-zA-Z0-9_]+)(?:\\s*\\((.*?)\\))?\\s*:");
    private static final Pattern DEF_PATTERN = Pattern.compile("^(?:async\\s+)?def\\s+([a-zA-Z0-9_]+)\\s*\\((.*?)\\)(?:\\s*->\\s*.*?)?\\s*:");
    private static final Pattern DECORATOR_PATTERN = Pattern.compile("^@([a-zA-Z0-9_.]+)(?:\\s*\\((.*?)\\))?$");
    private static final Pattern EXCEPT_PATTERN = Pattern.compile("^except(?:\\s+([a-zA-Z0-9_., ()]+?)(?:\\s+as\\s+([a-zA-Z0-9_]+))?)?\\s*:");

    public PythonModule parse(String source, Path filePath) {
        if (source == null) {
            source = "";
        }

        String[] rawLines = source.split("\\r?\\n", -1);
        int lineCount = rawLines.length;

        List<PythonImportStmt> imports = new ArrayList<>();
        List<PythonClassDef> classes = new ArrayList<>();
        List<PythonFunctionDef> functions = new ArrayList<>();
        List<PythonAstNode> statements = new ArrayList<>();

        List<PythonDecorator> pendingDecorators = new ArrayList<>();

        int i = 0;
        while (i < rawLines.length) {
            String rawLine = rawLines[i];
            int lineNum = i + 1;
            String trimmed = rawLine.trim();

            if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                i++;
                continue;
            }

            int indent = getIndentation(rawLine);

            // Join continuation lines for unclosed delimiters: (, [, {
            while (hasUnclosedDelimiters(rawLine) && i + 1 < rawLines.length) {
                i++;
                String nextLine = rawLines[i].trim();
                if (nextLine.startsWith("#")) continue;
                rawLine = rawLine + " " + nextLine;
            }
            trimmed = rawLine.trim();

            // Handle decorators
            if (trimmed.startsWith("@")) {
                PythonDecorator dec = parseDecorator(rawLine, lineNum);
                if (dec != null) {
                    pendingDecorators.add(dec);
                }
                i++;
                continue;
            }

            // Handle imports
            if (trimmed.startsWith("import ") || trimmed.startsWith("from ")) {
                List<PythonImportStmt> parsedImports = parseImports(rawLine, lineNum);
                imports.addAll(parsedImports);
                statements.addAll(parsedImports);
                pendingDecorators.clear();
                i++;
                continue;
            }

            // Handle class definitions
            Matcher classMatcher = CLASS_PATTERN.matcher(trimmed);
            if (classMatcher.find()) {
                String className = classMatcher.group(1);
                String baseArgs = classMatcher.group(2);
                List<String> bases = parseBaseClasses(baseArgs);

                List<PythonDecorator> classDecorators = new ArrayList<>(pendingDecorators);
                pendingDecorators.clear();

                int blockStart = i + 1;
                int blockEnd = findBlockEnd(rawLines, blockStart, indent);
                List<String> blockLines = subLines(rawLines, blockStart, blockEnd);

                ParsedBlock classBody = parseClassBody(blockLines, blockStart + 1);

                PythonClassDef classDef = new PythonClassDef(
                        lineNum,
                        indent,
                        blockEnd,
                        0,
                        rawLine,
                        className,
                        bases,
                        classDecorators,
                        classBody.methods,
                        classBody.assignments,
                        classBody.statements,
                        classBody.docstring
                );
                classes.add(classDef);
                statements.add(classDef);
                i = blockEnd;
                continue;
            }

            // Handle function definitions
            Matcher defMatcher = DEF_PATTERN.matcher(trimmed);
            if (defMatcher.find()) {
                String funcName = defMatcher.group(1);
                String paramsStr = defMatcher.group(2);
                boolean isAsync = trimmed.startsWith("async ");
                List<String> params = parseParameters(paramsStr);

                List<PythonDecorator> funcDecorators = new ArrayList<>(pendingDecorators);
                pendingDecorators.clear();

                int blockStart = i + 1;
                int blockEnd = findBlockEnd(rawLines, blockStart, indent);
                List<String> blockLines = subLines(rawLines, blockStart, blockEnd);

                ParsedBlock funcBody = parseBlockStatements(blockLines, blockStart + 1);

                String fullFuncText = rawLine + (blockLines.isEmpty() ? "" : "\n" + String.join("\n", blockLines));
                PythonFunctionDef funcDef = new PythonFunctionDef(
                        lineNum,
                        indent,
                        blockEnd,
                        0,
                        fullFuncText,
                        funcName,
                        params,
                        funcDecorators,
                        funcBody.statements,
                        isAsync,
                        funcBody.docstring
                );
                functions.add(funcDef);
                statements.add(funcDef);
                i = blockEnd;
                continue;
            }

            // Try-except statements at module level
            if (trimmed.startsWith("try:")) {
                int blockStart = i + 1;
                int blockEnd = findBlockEnd(rawLines, blockStart, indent);
                PythonTryStmt tryStmt = parseTryStatement(rawLines, i, indent);
                statements.add(tryStmt);
                i = Math.max(i + 1, blockEnd);
                pendingDecorators.clear();
                continue;
            }

            // If statements at module level
            if (trimmed.startsWith("if ")) {
                PythonIfStmt ifStmt = parseIfStatement(rawLines, i, indent);
                statements.add(ifStmt);
                i = ifStmt.getEndLine();
                pendingDecorators.clear();
                continue;
            }

            // Normal statements (assignments, calls, etc.)
            PythonAstNode stmt = parseSimpleStatement(rawLine, lineNum, indent);
            if (stmt != null) {
                statements.add(stmt);
            }
            pendingDecorators.clear();
            i++;
        }

        return new PythonModule(filePath, lineCount, source, imports, classes, functions, statements);
    }

    private int getIndentation(String line) {
        int count = 0;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (c == ' ') {
                count++;
            } else if (c == '\t') {
                count += 4;
            } else {
                break;
            }
        }
        return count;
    }

    private int findBlockEnd(String[] lines, int startLineIdx, int parentIndent) {
        int end = startLineIdx;
        while (end < lines.length) {
            String l = lines[end];
            String trimmed = l.trim();
            if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                end++;
                continue;
            }
            int curIndent = getIndentation(l);
            if (curIndent <= parentIndent) {
                break;
            }
            end++;
        }
        return end;
    }

    private List<String> subLines(String[] lines, int start, int end) {
        List<String> list = new ArrayList<>();
        for (int i = start; i < end && i < lines.length; i++) {
            list.add(lines[i]);
        }
        return list;
    }

    private PythonDecorator parseDecorator(String rawLine, int lineNum) {
        String trimmed = rawLine.trim();
        Matcher m = DECORATOR_PATTERN.matcher(trimmed);
        if (m.find()) {
            String name = m.group(1);
            String argsStr = m.group(2);
            PythonCallExpr callExpr = null;
            if (argsStr != null) {
                callExpr = parseCallExpression(name + "(" + argsStr + ")", lineNum, 0);
            }
            return new PythonDecorator(lineNum, getIndentation(rawLine), lineNum, rawLine.length(), rawLine, name, callExpr);
        }
        return null;
    }

    private List<PythonImportStmt> parseImports(String rawLine, int lineNum) {
        List<PythonImportStmt> results = new ArrayList<>();
        String trimmed = rawLine.trim();
        int indent = getIndentation(rawLine);

        Matcher fromMatcher = FROM_IMPORT_PATTERN.matcher(trimmed);
        if (fromMatcher.find()) {
            String module = fromMatcher.group(1);
            String symbols = fromMatcher.group(2);
            for (String symPart : symbols.split(",")) {
                String symTrim = symPart.trim();
                if (symTrim.isEmpty()) continue;
                String sym = symTrim;
                String alias = "";
                if (symTrim.contains(" as ")) {
                    String[] tokens = symTrim.split("\\s+as\\s+");
                    sym = tokens[0].trim();
                    alias = tokens.length > 1 ? tokens[1].trim() : "";
                }
                results.add(new PythonImportStmt(lineNum, indent, lineNum, rawLine.length(), rawLine, module, sym, alias, true));
            }
            return results;
        }

        Matcher impMatcher = IMPORT_PATTERN.matcher(trimmed);
        if (impMatcher.find()) {
            String modules = impMatcher.group(1);
            for (String modPart : modules.split(",")) {
                String modTrim = modPart.trim();
                if (modTrim.isEmpty()) continue;
                String mod = modTrim;
                String alias = "";
                if (modTrim.contains(" as ")) {
                    String[] tokens = modTrim.split("\\s+as\\s+");
                    mod = tokens[0].trim();
                    alias = tokens.length > 1 ? tokens[1].trim() : "";
                }
                results.add(new PythonImportStmt(lineNum, indent, lineNum, rawLine.length(), rawLine, mod, "", alias, false));
            }
        }
        return results;
    }

    private List<String> parseBaseClasses(String baseArgs) {
        if (baseArgs == null || baseArgs.isBlank()) {
            return Collections.emptyList();
        }
        List<String> bases = new ArrayList<>();
        for (String b : baseArgs.split(",")) {
            String trimmed = b.trim();
            if (!trimmed.isEmpty()) {
                bases.add(trimmed);
            }
        }
        return bases;
    }

    private List<String> parseParameters(String paramStr) {
        if (paramStr == null || paramStr.isBlank()) {
            return Collections.emptyList();
        }
        List<String> params = new ArrayList<>();
        for (String p : splitTopLevel(paramStr, ',')) {
            String trimmed = p.trim();
            if (trimmed.isEmpty()) continue;
            // Strip type annotation ': type' and default '= val'
            int colonIdx = indexOfTopLevel(trimmed, ':');
            if (colonIdx > 0) {
                trimmed = trimmed.substring(0, colonIdx).trim();
            }
            int eqIdx = indexOfTopLevel(trimmed, '=');
            if (eqIdx > 0) {
                trimmed = trimmed.substring(0, eqIdx).trim();
            }
            if (!trimmed.isEmpty()) {
                params.add(trimmed);
            }
        }
        return params;
    }

    private static class ParsedBlock {
        String docstring = "";
        List<PythonFunctionDef> methods = new ArrayList<>();
        List<PythonAssignStmt> assignments = new ArrayList<>();
        List<PythonAstNode> statements = new ArrayList<>();
    }

    private ParsedBlock parseClassBody(List<String> lines, int startLineNum) {
        ParsedBlock result = new ParsedBlock();
        List<PythonDecorator> pendingDecorators = new ArrayList<>();

        int i = 0;
        while (i < lines.size()) {
            String rawLine = lines.get(i);
            int currentLine = startLineNum + i;
            String trimmed = rawLine.trim();

            if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                i++;
                continue;
            }

            int indent = getIndentation(rawLine);

            // Join continuation lines for unclosed delimiters: (, [, {
            while (hasUnclosedDelimiters(rawLine) && i + 1 < lines.size()) {
                i++;
                String nextLine = lines.get(i).trim();
                if (nextLine.startsWith("#")) continue;
                rawLine = rawLine + " " + nextLine;
            }
            trimmed = rawLine.trim();

            // Docstring check at start of block
            if (result.docstring.isEmpty() && (trimmed.startsWith("\"\"\"") || trimmed.startsWith("'''"))) {
                result.docstring = extractDocstring(lines, i);
                i += countDocstringLines(lines, i);
                continue;
            }

            // Decorators
            if (trimmed.startsWith("@")) {
                PythonDecorator dec = parseDecorator(rawLine, currentLine);
                if (dec != null) pendingDecorators.add(dec);
                i++;
                continue;
            }

            // Methods inside class
            Matcher defMatcher = DEF_PATTERN.matcher(trimmed);
            if (defMatcher.find()) {
                String methodName = defMatcher.group(1);
                String paramsStr = defMatcher.group(2);
                boolean isAsync = trimmed.startsWith("async ");
                List<String> params = parseParameters(paramsStr);

                List<PythonDecorator> methodDecorators = new ArrayList<>(pendingDecorators);
                pendingDecorators.clear();

                int methodStart = i + 1;
                int methodEnd = findBlockEndList(lines, methodStart, indent);
                List<String> methodLines = lines.subList(methodStart, Math.min(methodEnd, lines.size()));

                ParsedBlock methodBody = parseBlockStatements(methodLines, startLineNum + methodStart);

                String fullMethodText = rawLine + (methodLines.isEmpty() ? "" : "\n" + String.join("\n", methodLines));
                PythonFunctionDef method = new PythonFunctionDef(
                        currentLine,
                        indent,
                        startLineNum + methodEnd,
                        0,
                        fullMethodText,
                        methodName,
                        params,
                        methodDecorators,
                        methodBody.statements,
                        isAsync,
                        methodBody.docstring
                );
                result.methods.add(method);
                result.statements.add(method);
                i = methodEnd;
                continue;
            }

            // Class variables / assignments
            PythonAstNode stmt = parseSimpleStatement(rawLine, currentLine, indent);
            if (stmt instanceof PythonAssignStmt assign) {
                result.assignments.add(assign);
            }
            if (stmt != null) {
                result.statements.add(stmt);
            }
            pendingDecorators.clear();
            i++;
        }

        return result;
    }

    private ParsedBlock parseBlockStatements(List<String> lines, int startLineNum) {
        ParsedBlock result = new ParsedBlock();

        int i = 0;
        while (i < lines.size()) {
            String rawLine = lines.get(i);
            int currentLine = startLineNum + i;
            String trimmed = rawLine.trim();

            if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                i++;
                continue;
            }

            int indent = getIndentation(rawLine);

            // Join continuation lines for unclosed delimiters: (, [, {
            while (hasUnclosedDelimiters(rawLine) && i + 1 < lines.size()) {
                i++;
                String nextLine = lines.get(i).trim();
                if (nextLine.startsWith("#")) continue;
                rawLine = rawLine + " " + nextLine;
            }
            trimmed = rawLine.trim();

            // Docstring check
            if (result.docstring.isEmpty() && (trimmed.startsWith("\"\"\"") || trimmed.startsWith("'''"))) {
                result.docstring = extractDocstring(lines, i);
                i += countDocstringLines(lines, i);
                continue;
            }

            // Try-except statements
            if (trimmed.startsWith("try:")) {
                String[] lineArray = lines.toArray(new String[0]);
                PythonTryStmt tryStmt = parseTryStatement(lineArray, i, indent, startLineNum);
                result.statements.add(tryStmt);
                i = tryStmt.getEndLine() - startLineNum + 1;
                continue;
            }

            // If statements
            if (trimmed.startsWith("if ")) {
                String[] lineArray = lines.toArray(new String[0]);
                PythonIfStmt ifStmt = parseIfStatement(lineArray, i, indent, startLineNum);
                result.statements.add(ifStmt);
                i = ifStmt.getEndLine() - startLineNum + 1;
                continue;
            }

            // With statements: with open(...) as f:
            if (trimmed.startsWith("with ") || trimmed.startsWith("async with ")) {
                int colonIdx = trimmed.lastIndexOf(':');
                String withHeader = colonIdx > 0 ? trimmed.substring(0, colonIdx) : trimmed;
                if (withHeader.startsWith("async with ")) {
                    withHeader = withHeader.substring(11).trim();
                } else {
                    withHeader = withHeader.substring(5).trim();
                }
                for (String item : splitTopLevel(withHeader, ',')) {
                    String itemTrim = item.trim();
                    int asIdx = itemTrim.lastIndexOf(" as ");
                    if (asIdx > 0) {
                        itemTrim = itemTrim.substring(0, asIdx).trim();
                    }
                    PythonAstNode withExpr = parseExpression(itemTrim, currentLine, indent);
                    if (withExpr != null) {
                        result.statements.add(withExpr);
                    }
                }
                i++;
                continue;
            }

            // Return statement
            if (trimmed.startsWith("return")) {
                String retExprStr = trimmed.substring(6).trim();
                PythonAstNode retVal = !retExprStr.isEmpty() ? parseExpression(retExprStr, currentLine, indent) : null;
                result.statements.add(new PythonReturnStmt(currentLine, indent, currentLine, rawLine.length(), rawLine, retVal));
                i++;
                continue;
            }

            // Simple statements (assignment, call, expression)
            PythonAstNode stmt = parseSimpleStatement(rawLine, currentLine, indent);
            if (stmt instanceof PythonAssignStmt assign) {
                result.assignments.add(assign);
            }
            if (stmt != null) {
                result.statements.add(stmt);
            }
            i++;
        }

        return result;
    }

    private PythonAstNode parseSimpleStatement(String rawLine, int lineNum, int indent) {
        String trimmed = rawLine.trim();
        if (trimmed.isEmpty() || trimmed.startsWith("#")) {
            return null;
        }

        // Assignment check: target = value (avoiding ==, <=, >=, !=)
        int eqIdx = findAssignmentEquals(trimmed);
        if (eqIdx > 0) {
            String targetPart = trimmed.substring(0, eqIdx).trim();
            String valuePart = trimmed.substring(eqIdx + 1).trim();

            List<String> targets = new ArrayList<>();
            for (String t : splitTopLevel(targetPart, ',')) {
                String targetTrim = t.trim();
                if (!targetTrim.isEmpty()) {
                    targets.add(targetTrim);
                }
            }

            PythonAstNode valueNode = parseExpression(valuePart, lineNum, indent + eqIdx + 1);
            return new PythonAssignStmt(lineNum, indent, lineNum, rawLine.length(), rawLine, targets, valueNode);
        }

        // Otherwise parse expression
        return parseExpression(trimmed, lineNum, indent);
    }

    private int findAssignmentEquals(String text) {
        int depthParen = 0;
        int depthBracket = 0;
        int depthBrace = 0;
        boolean inSingleQuote = false;
        boolean inDoubleQuote = false;

        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);

            if (c == '\'' && !inDoubleQuote && (i == 0 || text.charAt(i - 1) != '\\')) {
                inSingleQuote = !inSingleQuote;
            } else if (c == '"' && !inSingleQuote && (i == 0 || text.charAt(i - 1) != '\\')) {
                inDoubleQuote = !inDoubleQuote;
            }

            if (inSingleQuote || inDoubleQuote) continue;

            if (c == '(') depthParen++;
            else if (c == ')') depthParen--;
            else if (c == '[') depthBracket++;
            else if (c == ']') depthBracket--;
            else if (c == '{') depthBrace++;
            else if (c == '}') depthBrace--;

            if (depthParen == 0 && depthBracket == 0 && depthBrace == 0 && c == '=') {
                if (i + 1 < text.length() && text.charAt(i + 1) == '=') {
                    i++; // skip ==
                    continue;
                }
                if (i > 0) {
                    char prev = text.charAt(i - 1);
                    if (prev == '!' || prev == '<' || prev == '>' || prev == '+' || prev == '-' || prev == '*' || prev == '/') {
                        continue;
                    }
                }
                return i;
            }
        }
        return -1;
    }

    private boolean isEscaped(String text, int index) {
        int backslashCount = 0;
        for (int j = index - 1; j >= 0 && text.charAt(j) == '\\'; j--) {
            backslashCount++;
        }
        return backslashCount % 2 != 0;
    }

    private static class StringLiteralInfo {
        final boolean isLiteral;
        final PythonLiteralExpr.Kind kind;
        final String content;

        StringLiteralInfo(boolean isLiteral, PythonLiteralExpr.Kind kind, String content) {
            this.isLiteral = isLiteral;
            this.kind = kind;
            this.content = content;
        }
    }

    private StringLiteralInfo parseStringLiteralInfo(String text) {
        if (text == null || text.isBlank()) {
            return new StringLiteralInfo(false, null, null);
        }
        String trimmed = text.trim();
        int len = trimmed.length();
        if (len < 2) {
            return new StringLiteralInfo(false, null, null);
        }

        // Prefix detection: r, f, b, u, rf, fr, br, rb (case-insensitive)
        int prefixEnd = 0;
        while (prefixEnd < len && Character.isLetter(trimmed.charAt(prefixEnd))) {
            prefixEnd++;
        }
        String prefix = trimmed.substring(0, prefixEnd).toLowerCase(Locale.ROOT);
        boolean isFString = prefix.contains("f");

        if (prefixEnd >= len) {
            return new StringLiteralInfo(false, null, null);
        }

        String rem = trimmed.substring(prefixEnd);
        String delimiter = null;
        if (rem.startsWith("\"\"\"")) delimiter = "\"\"\"";
        else if (rem.startsWith("'''")) delimiter = "'''";
        else if (rem.startsWith("\"")) delimiter = "\"";
        else if (rem.startsWith("'")) delimiter = "'";

        if (delimiter == null) {
            return new StringLiteralInfo(false, null, null);
        }

        int delimLen = delimiter.length();
        int contentStart = prefixEnd + delimLen;
        int endIdx = -1;

        for (int i = contentStart; i <= len - delimLen; i++) {
            if (trimmed.startsWith(delimiter, i) && !isEscaped(trimmed, i)) {
                endIdx = i;
                break;
            }
        }

        if (endIdx != -1 && endIdx + delimLen == len) {
            PythonLiteralExpr.Kind kind = isFString ? PythonLiteralExpr.Kind.FSTRING : PythonLiteralExpr.Kind.STRING;
            return new StringLiteralInfo(true, kind, trimmed);
        }

        return new StringLiteralInfo(false, null, null);
    }

    public PythonAstNode parseExpression(String expr, int lineNum, int col) {
        if (expr == null || expr.isBlank()) {
            return null;
        }
        String trimmed = expr.trim();

        // 0. Unwrap outer parentheses if they enclose the entire expression, e.g. (a + b)
        if (trimmed.startsWith("(") && trimmed.endsWith(")")) {
            int matching = findMatchingParenStart(trimmed);
            if (matching == 0) {
                return parseExpression(trimmed.substring(1, trimmed.length() - 1), lineNum, col + 1);
            }
        }

        // 1. Binary operations (+ or %) at top level (must precede string literal check for concatenations)
        int binOpIdx = findTopLevelBinaryOp(trimmed, "+");
        if (binOpIdx > 0) {
            String leftPart = trimmed.substring(0, binOpIdx).trim();
            String rightPart = trimmed.substring(binOpIdx + 1).trim();
            PythonAstNode left = parseExpression(leftPart, lineNum, col);
            PythonAstNode right = parseExpression(rightPart, lineNum, col + binOpIdx + 1);
            return new PythonBinaryExpr(lineNum, col, lineNum, col + trimmed.length(), trimmed, left, "+", right);
        }

        int modOpIdx = findTopLevelBinaryOp(trimmed, "%");
        if (modOpIdx > 0) {
            String leftPart = trimmed.substring(0, modOpIdx).trim();
            String rightPart = trimmed.substring(modOpIdx + 1).trim();
            PythonAstNode left = parseExpression(leftPart, lineNum, col);
            PythonAstNode right = parseExpression(rightPart, lineNum, col + modOpIdx + 1);
            return new PythonBinaryExpr(lineNum, col, lineNum, col + trimmed.length(), trimmed, left, "%", right);
        }

        int slashOpIdx = findTopLevelBinaryOp(trimmed, "/");
        if (slashOpIdx > 0) {
            String leftPart = trimmed.substring(0, slashOpIdx).trim();
            String rightPart = trimmed.substring(slashOpIdx + 1).trim();
            PythonAstNode left = parseExpression(leftPart, lineNum, col);
            PythonAstNode right = parseExpression(rightPart, lineNum, col + slashOpIdx + 1);
            return new PythonBinaryExpr(lineNum, col, lineNum, col + trimmed.length(), trimmed, left, "/", right);
        }

        // 2. Complete String literal (atomic single or triple-quoted string, optionally prefixed)
        StringLiteralInfo litInfo = parseStringLiteralInfo(trimmed);
        if (litInfo.isLiteral) {
            return new PythonLiteralExpr(lineNum, col, lineNum, col + trimmed.length(), trimmed, litInfo.kind, trimmed);
        }

        // 3. Subscript expression: target[index]
        if (trimmed.endsWith("]") && trimmed.contains("[")) {
            int bracketIdx = findMatchingBracketStart(trimmed);
            if (bracketIdx > 0) {
                String targetPart = trimmed.substring(0, bracketIdx).trim();
                String indexPart = trimmed.substring(bracketIdx + 1, trimmed.length() - 1).trim();
                PythonAstNode target = parseExpression(targetPart, lineNum, col);
                PythonAstNode index = parseExpression(indexPart, lineNum, col + bracketIdx + 1);
                return new PythonSubscriptExpr(lineNum, col, lineNum, col + trimmed.length(), trimmed, target, index);
            }
        }

        // 4. Call expression: callee(args...)
        if (trimmed.endsWith(")") && trimmed.contains("(")) {
            int parenIdx = findMatchingParenStart(trimmed);
            if (parenIdx > 0) {
                return parseCallExpression(trimmed, lineNum, col);
            }
        }

        // 4b. Attribute access: target.attr (e.g. requests.get(url).text)
        int attrDotIdx = findTopLevelDot(trimmed);
        if (attrDotIdx > 0) {
            String leftPart = trimmed.substring(0, attrDotIdx).trim();
            String attrName = trimmed.substring(attrDotIdx + 1).trim();
            if (attrName.matches("^[a-zA-Z_][a-zA-Z0-9_]*$")) {
                PythonAstNode target = parseExpression(leftPart, lineNum, col);
                return new PythonAttributeExpr(lineNum, col, lineNum, col + trimmed.length(), trimmed, target, attrName);
            }
        }

        // 5. Literals: numbers, bools, None
        if (trimmed.matches("-?\\d+(\\.\\d+)?")) {
            return new PythonLiteralExpr(lineNum, col, lineNum, col + trimmed.length(), trimmed, PythonLiteralExpr.Kind.NUMBER, trimmed);
        }
        if ("True".equals(trimmed) || "False".equals(trimmed)) {
            return new PythonLiteralExpr(lineNum, col, lineNum, col + trimmed.length(), trimmed, PythonLiteralExpr.Kind.BOOLEAN, trimmed);
        }
        if ("None".equals(trimmed)) {
            return new PythonLiteralExpr(lineNum, col, lineNum, col + trimmed.length(), trimmed, PythonLiteralExpr.Kind.NONE, trimmed);
        }

        // 6. Name identifier
        return new PythonNameExpr(lineNum, col, lineNum, col + trimmed.length(), trimmed, trimmed);
    }

    public PythonCallExpr parseCallExpression(String callStr, int lineNum, int col) {
        String trimmed = callStr.trim();
        int openParen = findMatchingParenStart(trimmed);
        if (openParen <= 0) {
            return null;
        }

        String fullCallee = trimmed.substring(0, openParen).trim();
        String shortCallee = fullCallee;
        int dotIdx = findTopLevelDot(fullCallee);
        PythonAstNode target = null;
        if (dotIdx >= 0) {
            shortCallee = fullCallee.substring(dotIdx + 1).trim();
            String targetStr = fullCallee.substring(0, dotIdx).trim();
            target = parseExpression(targetStr, lineNum, col);
        }

        String argsContent = trimmed.substring(openParen + 1, trimmed.length() - 1).trim();
        List<PythonArgument> arguments = new ArrayList<>();

        if (!argsContent.isEmpty()) {
            List<String> rawArgs = splitTopLevel(argsContent, ',');
            for (String argStr : rawArgs) {
                String argTrim = argStr.trim();
                if (argTrim.isEmpty()) continue;

                int eqIdx = findTopLevelBinaryOp(argTrim, "=");
                if (eqIdx > 0 && !argTrim.startsWith("==")) {
                    String kw = argTrim.substring(0, eqIdx).trim();
                    String val = argTrim.substring(eqIdx + 1).trim();
                    PythonAstNode valNode = parseExpression(val, lineNum, col);
                    arguments.add(new PythonArgument(lineNum, col, lineNum, col + argTrim.length(), argTrim, kw, valNode));
                } else {
                    PythonAstNode valNode = parseExpression(argTrim, lineNum, col);
                    arguments.add(new PythonArgument(lineNum, col, lineNum, col + argTrim.length(), argTrim, null, valNode));
                }
            }
        }

        return new PythonCallExpr(
                lineNum,
                col,
                lineNum,
                col + trimmed.length(),
                trimmed,
                shortCallee,
                fullCallee,
                target,
                arguments
        );
    }

    private int findTopLevelDot(String text) {
        int depthParen = 0;
        int depthBracket = 0;
        int depthBrace = 0;
        boolean inSingleQuote = false;
        boolean inDoubleQuote = false;

        for (int i = text.length() - 1; i >= 0; i--) {
            char c = text.charAt(i);

            if (c == '\'' && !inDoubleQuote && (i == 0 || text.charAt(i - 1) != '\\')) {
                inSingleQuote = !inSingleQuote;
            } else if (c == '"' && !inSingleQuote && (i == 0 || text.charAt(i - 1) != '\\')) {
                inDoubleQuote = !inDoubleQuote;
            }

            if (inSingleQuote || inDoubleQuote) continue;

            if (c == ')') depthParen++;
            else if (c == '(') depthParen--;
            else if (c == ']') depthBracket++;
            else if (c == '[') depthBracket--;
            else if (c == '}') depthBrace++;
            else if (c == '{') depthBrace--;

            if (depthParen == 0 && depthBracket == 0 && depthBrace == 0 && c == '.') {
                return i;
            }
        }
        return -1;
    }

    private int findTopLevelBinaryOp(String text, String op) {
        int depthParen = 0;
        int depthBracket = 0;
        int depthBrace = 0;
        boolean inSingleQuote = false;
        boolean inDoubleQuote = false;
        boolean inTripleSingle = false;
        boolean inTripleDouble = false;

        for (int i = 0; i < text.length(); i++) {
            if (!inSingleQuote && !inDoubleQuote && !inTripleSingle && !inTripleDouble) {
                if (text.startsWith("\"\"\"", i)) {
                    inTripleDouble = true;
                    i += 2;
                    continue;
                } else if (text.startsWith("'''", i)) {
                    inTripleSingle = true;
                    i += 2;
                    continue;
                } else if (text.charAt(i) == '"') {
                    inDoubleQuote = true;
                    continue;
                } else if (text.charAt(i) == '\'') {
                    inSingleQuote = true;
                    continue;
                }
            } else if (inTripleDouble) {
                if (text.startsWith("\"\"\"", i) && !isEscaped(text, i)) {
                    inTripleDouble = false;
                    i += 2;
                }
                continue;
            } else if (inTripleSingle) {
                if (text.startsWith("'''", i) && !isEscaped(text, i)) {
                    inTripleSingle = false;
                    i += 2;
                }
                continue;
            } else if (inDoubleQuote) {
                if (text.charAt(i) == '"' && !isEscaped(text, i)) {
                    inDoubleQuote = false;
                }
                continue;
            } else if (inSingleQuote) {
                if (text.charAt(i) == '\'' && !isEscaped(text, i)) {
                    inSingleQuote = false;
                }
                continue;
            }

            char c = text.charAt(i);
            if (c == '(') depthParen++;
            else if (c == ')') depthParen--;
            else if (c == '[') depthBracket++;
            else if (c == ']') depthBracket--;
            else if (c == '{') depthBrace++;
            else if (c == '}') depthBrace--;

            if (depthParen == 0 && depthBracket == 0 && depthBrace == 0) {
                if (op.equals("+") && c == '+') {
                    return i;
                } else if (op.equals("%") && c == '%') {
                    return i;
                } else if (op.equals("/") && c == '/' && (i + 1 == text.length() || text.charAt(i + 1) != '/') && (i == 0 || text.charAt(i - 1) != '/')) {
                    return i;
                } else if (op.equals("=") && c == '=' && (i + 1 == text.length() || text.charAt(i + 1) != '=') && (i == 0 || text.charAt(i - 1) != '=')) {
                    return i;
                }
            }
        }
        return -1;
    }

    private int findMatchingParenStart(String text) {
        if (!text.endsWith(")")) return -1;
        int depth = 0;
        boolean inSingle = false;
        boolean inDouble = false;
        for (int i = text.length() - 1; i >= 0; i--) {
            char c = text.charAt(i);
            if (c == '\'' && !inDouble && (i == 0 || text.charAt(i - 1) != '\\')) inSingle = !inSingle;
            else if (c == '"' && !inSingle && (i == 0 || text.charAt(i - 1) != '\\')) inDouble = !inDouble;
            if (inSingle || inDouble) continue;

            if (c == ')') depth++;
            else if (c == '(') {
                depth--;
                if (depth == 0) return i;
            }
        }
        return -1;
    }

    private int findMatchingBracketStart(String text) {
        if (!text.endsWith("]")) return -1;
        int depth = 0;
        boolean inSingle = false;
        boolean inDouble = false;
        for (int i = text.length() - 1; i >= 0; i--) {
            char c = text.charAt(i);
            if (c == '\'' && !inDouble && (i == 0 || text.charAt(i - 1) != '\\')) inSingle = !inSingle;
            else if (c == '"' && !inSingle && (i == 0 || text.charAt(i - 1) != '\\')) inDouble = !inDouble;
            if (inSingle || inDouble) continue;

            if (c == ']') depth++;
            else if (c == '[') {
                depth--;
                if (depth == 0) return i;
            }
        }
        return -1;
    }

    private List<String> splitTopLevel(String text, char delimiter) {
        List<String> tokens = new ArrayList<>();
        int depthParen = 0;
        int depthBracket = 0;
        int depthBrace = 0;
        boolean inSingleQuote = false;
        boolean inDoubleQuote = false;

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);

            if (c == '\'' && !inDoubleQuote && (i == 0 || text.charAt(i - 1) != '\\')) {
                inSingleQuote = !inSingleQuote;
            } else if (c == '"' && !inSingleQuote && (i == 0 || text.charAt(i - 1) != '\\')) {
                inDoubleQuote = !inDoubleQuote;
            }

            if (!inSingleQuote && !inDoubleQuote) {
                if (c == '(') depthParen++;
                else if (c == ')') depthParen--;
                else if (c == '[') depthBracket++;
                else if (c == ']') depthBracket--;
                else if (c == '{') depthBrace++;
                else if (c == '}') depthBrace--;
            }

            if (c == delimiter && depthParen == 0 && depthBracket == 0 && depthBrace == 0 && !inSingleQuote && !inDoubleQuote) {
                tokens.add(sb.toString());
                sb.setLength(0);
            } else {
                sb.append(c);
            }
        }
        if (sb.length() > 0) {
            tokens.add(sb.toString());
        }
        return tokens;
    }

    private int indexOfTopLevel(String text, char target) {
        int depthParen = 0;
        int depthBracket = 0;
        int depthBrace = 0;
        boolean inSingleQuote = false;
        boolean inDoubleQuote = false;

        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == '\'' && !inDoubleQuote && (i == 0 || text.charAt(i - 1) != '\\')) {
                inSingleQuote = !inSingleQuote;
            } else if (c == '"' && !inSingleQuote && (i == 0 || text.charAt(i - 1) != '\\')) {
                inDoubleQuote = !inDoubleQuote;
            }
            if (inSingleQuote || inDoubleQuote) continue;

            if (c == '(') depthParen++;
            else if (c == ')') depthParen--;
            else if (c == '[') depthBracket++;
            else if (c == ']') depthBracket--;
            else if (c == '{') depthBrace++;
            else if (c == '}') depthBrace--;

            if (c == target && depthParen == 0 && depthBracket == 0 && depthBrace == 0) {
                return i;
            }
        }
        return -1;
    }

    private String extractDocstring(List<String> lines, int startIdx) {
        StringBuilder sb = new StringBuilder();
        String quoteType = lines.get(startIdx).trim().startsWith("\"\"\"") ? "\"\"\"" : "'''";
        for (int i = startIdx; i < lines.size(); i++) {
            String l = lines.get(i);
            sb.append(l).append("\n");
            if (i > startIdx && l.contains(quoteType)) {
                break;
            } else if (i == startIdx && l.indexOf(quoteType, l.indexOf(quoteType) + 3) >= 0) {
                break;
            }
        }
        return sb.toString().trim();
    }

    private int countDocstringLines(List<String> lines, int startIdx) {
        String quoteType = lines.get(startIdx).trim().startsWith("\"\"\"") ? "\"\"\"" : "'''";
        for (int i = startIdx; i < lines.size(); i++) {
            String l = lines.get(i);
            if (i > startIdx && l.contains(quoteType)) {
                return i - startIdx + 1;
            } else if (i == startIdx && l.indexOf(quoteType, l.indexOf(quoteType) + 3) >= 0) {
                return 1;
            }
        }
        return 1;
    }

    private int findBlockEndList(List<String> lines, int startIdx, int parentIndent) {
        int end = startIdx;
        while (end < lines.size()) {
            String l = lines.get(end);
            String trimmed = l.trim();
            if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                end++;
                continue;
            }
            int curIndent = getIndentation(l);
            if (curIndent <= parentIndent) {
                break;
            }
            end++;
        }
        return end;
    }

    private PythonTryStmt parseTryStatement(String[] lines, int tryLineIdx, int parentIndent) {
        return parseTryStatement(lines, tryLineIdx, parentIndent, 1);
    }

    private PythonTryStmt parseTryStatement(String[] lines, int tryLineIdx, int parentIndent, int lineOffset) {
        int lineNum = lineOffset + tryLineIdx;
        List<PythonAstNode> tryBody = new ArrayList<>();
        List<PythonExceptClause> exceptClauses = new ArrayList<>();
        List<PythonAstNode> finallyBody = new ArrayList<>();

        int i = tryLineIdx + 1;
        // Parse try body
        while (i < lines.length) {
            String l = lines[i];
            String trimmed = l.trim();
            if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                i++;
                continue;
            }
            int indent = getIndentation(l);
            if (indent <= parentIndent) {
                break;
            }
            PythonAstNode stmt = parseSimpleStatement(l, lineOffset + i, indent);
            if (stmt != null) tryBody.add(stmt);
            i++;
        }

        // Parse except clauses
        while (i < lines.length) {
            String l = lines[i];
            String trimmed = l.trim();
            int indent = getIndentation(l);
            if (indent == parentIndent && trimmed.startsWith("except")) {
                Matcher m = EXCEPT_PATTERN.matcher(trimmed);
                String excType = "";
                String excAlias = "";
                if (m.find()) {
                    excType = m.group(1);
                    excAlias = m.group(2);
                }
                int excLine = lineOffset + i;
                List<PythonAstNode> excBody = new ArrayList<>();
                i++;
                while (i < lines.length) {
                    String el = lines[i];
                    String elTrim = el.trim();
                    if (elTrim.isEmpty() || elTrim.startsWith("#")) {
                        i++;
                        continue;
                    }
                    if (getIndentation(el) <= parentIndent) {
                        break;
                    }
                    PythonAstNode stmt = parseSimpleStatement(el, lineOffset + i, getIndentation(el));
                    if (stmt != null) excBody.add(stmt);
                    i++;
                }
                exceptClauses.add(new PythonExceptClause(excLine, indent, lineOffset + i, 0, l, excType, excAlias, excBody));
            } else if (indent == parentIndent && trimmed.startsWith("finally:")) {
                i++;
                while (i < lines.length) {
                    String fl = lines[i];
                    String flTrim = fl.trim();
                    if (flTrim.isEmpty() || flTrim.startsWith("#")) {
                        i++;
                        continue;
                    }
                    if (getIndentation(fl) <= parentIndent) {
                        break;
                    }
                    PythonAstNode stmt = parseSimpleStatement(fl, lineOffset + i, getIndentation(fl));
                    if (stmt != null) finallyBody.add(stmt);
                    i++;
                }
                break;
            } else {
                break;
            }
        }

        return new PythonTryStmt(lineNum, parentIndent, lineOffset + i, 0, lines[tryLineIdx], tryBody, exceptClauses, finallyBody);
    }

    private PythonIfStmt parseIfStatement(String[] lines, int ifLineIdx, int parentIndent) {
        return parseIfStatement(lines, ifLineIdx, parentIndent, 1);
    }

    private PythonIfStmt parseIfStatement(String[] lines, int ifLineIdx, int parentIndent, int lineOffset) {
        int lineNum = lineOffset + ifLineIdx;
        String ifLine = lines[ifLineIdx].trim();
        String condStr = ifLine.substring(2, ifLine.length() - (ifLine.endsWith(":") ? 1 : 0)).trim();
        PythonAstNode condition = parseExpression(condStr, lineNum, parentIndent + 3);

        List<PythonAstNode> thenBranch = new ArrayList<>();
        List<PythonAstNode> elseBranch = new ArrayList<>();

        int i = ifLineIdx + 1;
        while (i < lines.length) {
            String l = lines[i];
            String trimmed = l.trim();
            if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                i++;
                continue;
            }
            int indent = getIndentation(l);
            if (indent <= parentIndent) {
                break;
            }
            PythonAstNode stmt = parseSimpleStatement(l, lineOffset + i, indent);
            if (stmt != null) thenBranch.add(stmt);
            i++;
        }

        if (i < lines.length && getIndentation(lines[i]) == parentIndent && lines[i].trim().startsWith("else:")) {
            i++;
            while (i < lines.length) {
                String l = lines[i];
                String trimmed = l.trim();
                if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                    i++;
                    continue;
                }
                int indent = getIndentation(l);
                if (indent <= parentIndent) {
                    break;
                }
                PythonAstNode stmt = parseSimpleStatement(l, lineOffset + i, indent);
                if (stmt != null) elseBranch.add(stmt);
                i++;
            }
        }

        return new PythonIfStmt(lineNum, parentIndent, lineOffset + i, 0, lines[ifLineIdx], condition, thenBranch, elseBranch);
    }

    private boolean hasUnclosedDelimiters(String text) {
        if (text == null) return false;
        int depthParen = 0;
        int depthBracket = 0;
        int depthBrace = 0;
        boolean inSingleQuote = false;
        boolean inDoubleQuote = false;

        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == '\'' && !inDoubleQuote && (i == 0 || text.charAt(i - 1) != '\\')) {
                inSingleQuote = !inSingleQuote;
            } else if (c == '"' && !inSingleQuote && (i == 0 || text.charAt(i - 1) != '\\')) {
                inDoubleQuote = !inDoubleQuote;
            }
            if (inSingleQuote || inDoubleQuote) continue;

            if (c == '(') depthParen++;
            else if (c == ')') depthParen--;
            else if (c == '[') depthBracket++;
            else if (c == ']') depthBracket--;
            else if (c == '{') depthBrace++;
            else if (c == '}') depthBrace--;
        }
        return depthParen > 0 || depthBracket > 0 || depthBrace > 0;
    }
}
