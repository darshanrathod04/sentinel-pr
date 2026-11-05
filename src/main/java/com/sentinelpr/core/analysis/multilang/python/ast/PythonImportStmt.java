package com.sentinelpr.core.analysis.multilang.python.ast;

/**
 * Import statement in Python (import x, from x import y as z).
 */
public class PythonImportStmt extends PythonAstNode {

    private final String moduleName;
    private final String importedSymbol;
    private final String alias;
    private final boolean isFromImport;

    public PythonImportStmt(
            int line,
            int column,
            int endLine,
            int endColumn,
            String rawText,
            String moduleName,
            String importedSymbol,
            String alias,
            boolean isFromImport
    ) {
        super(line, column, endLine, endColumn, rawText);
        this.moduleName = moduleName != null ? moduleName : "";
        this.importedSymbol = importedSymbol != null ? importedSymbol : "";
        this.alias = alias != null ? alias : "";
        this.isFromImport = isFromImport;
    }

    public String getModuleName() {
        return moduleName;
    }

    public String getImportedSymbol() {
        return importedSymbol;
    }

    public String getAlias() {
        return alias;
    }

    public boolean isFromImport() {
        return isFromImport;
    }

    public String getEffectiveName() {
        if (!alias.isBlank()) {
            return alias;
        }
        if (!importedSymbol.isBlank()) {
            return importedSymbol;
        }
        return moduleName;
    }

    @Override
    public void accept(PythonAstVisitor visitor) {
        visitor.visit(this);
    }
}
