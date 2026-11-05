package com.sentinelpr.core.analysis.multilang.python.ast;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Call expression in Python (e.g., cursor.execute("SELECT ...", (id,))).
 */
public class PythonCallExpr extends PythonAstNode {

    private final String calleeName;
    private final String fullCalleeName;
    private final PythonAstNode target;
    private final List<PythonArgument> arguments;

    public PythonCallExpr(
            int line,
            int column,
            int endLine,
            int endColumn,
            String rawText,
            String calleeName,
            String fullCalleeName,
            PythonAstNode target,
            List<PythonArgument> arguments
    ) {
        super(line, column, endLine, endColumn, rawText);
        this.calleeName = calleeName != null ? calleeName : "";
        this.fullCalleeName = fullCalleeName != null ? fullCalleeName : this.calleeName;
        this.target = target;
        this.arguments = arguments != null ? Collections.unmodifiableList(arguments) : Collections.emptyList();
    }

    public String getCalleeName() {
        return calleeName;
    }

    public String getFullCalleeName() {
        return fullCalleeName;
    }

    public PythonAstNode getTarget() {
        return target;
    }

    public List<PythonArgument> getArguments() {
        return arguments;
    }

    public List<PythonAstNode> getPositionalArguments() {
        List<PythonAstNode> pos = new ArrayList<>();
        for (PythonArgument arg : arguments) {
            if (!arg.isKeyword() && arg.getValue() != null) {
                pos.add(arg.getValue());
            }
        }
        return Collections.unmodifiableList(pos);
    }

    public Map<String, PythonAstNode> getKeywordArguments() {
        Map<String, PythonAstNode> kw = new LinkedHashMap<>();
        for (PythonArgument arg : arguments) {
            if (arg.isKeyword() && arg.getValue() != null) {
                kw.put(arg.getKeywordName(), arg.getValue());
            }
        }
        return Collections.unmodifiableMap(kw);
    }

    public PythonAstNode getKeywordArgument(String name) {
        for (PythonArgument arg : arguments) {
            if (arg.isKeyword() && name.equals(arg.getKeywordName())) {
                return arg.getValue();
            }
        }
        return null;
    }

    @Override
    public List<PythonAstNode> getChildren() {
        List<PythonAstNode> children = new ArrayList<>();
        if (target != null) children.add(target);
        children.addAll(arguments);
        return Collections.unmodifiableList(children);
    }

    @Override
    public void accept(PythonAstVisitor visitor) {
        visitor.visit(this);
    }
}
