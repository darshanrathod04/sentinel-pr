package com.sentinelpr.core.analysis.taint;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.Objects;

/**
 * <b>TaintSource</b>
 *
 * <p>Represents an entry point of untrusted data into a procedure.</p>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class TaintSource {

    public enum SourceType {
        METHOD_PARAMETER,
        HTTP_REQUEST,
        SYSTEM_INPUT,
        ENVIRONMENT,
        CUSTOM
    }

    private final String name;
    private final String qualifiedName;
    private final SourceType type;
    private final int line;
    private final String snippet;

    public TaintSource(String name, SourceType type, int line, String snippet) {
        this(name, name, type, line, snippet);
    }

    public TaintSource(String name, String qualifiedName, SourceType type, int line, String snippet) {
        this.name = Objects.requireNonNull(name, "name must not be null");
        this.qualifiedName = qualifiedName != null ? qualifiedName : name;
        this.type = type != null ? type : SourceType.METHOD_PARAMETER;
        this.line = line;
        this.snippet = snippet != null ? snippet : "";
    }

    public String getName() {
        return name;
    }

    public String getQualifiedName() {
        return qualifiedName;
    }

    public SourceType getType() {
        return type;
    }

    public int getLine() {
        return line;
    }

    public String getSnippet() {
        return snippet;
    }

    @Override
    public String toString() {
        return "TaintSource{" +
                "name='" + name + '\'' +
                ", type=" + type +
                ", line=" + line +
                '}';
    }
}
