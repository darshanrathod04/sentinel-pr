package com.sentinelpr.core.analysis.taint;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.Objects;

/**
 * <b>TaintSink</b>
 *
 * <p>Represents a sensitive operation or API where tainted data can cause security violations.</p>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class TaintSink {

    public enum SinkType {
        COMMAND_EXECUTION,
        FILE_IO,
        RAW_SQL,
        GENERIC
    }

    private final SinkType type;
    private final String targetMethod;
    private final int line;
    private final String snippet;

    public TaintSink(SinkType type, String targetMethod, int line, String snippet) {
        this.type = type != null ? type : SinkType.GENERIC;
        this.targetMethod = Objects.requireNonNull(targetMethod, "targetMethod must not be null");
        this.line = line;
        this.snippet = snippet != null ? snippet : "";
    }

    public SinkType getType() {
        return type;
    }

    public String getTargetMethod() {
        return targetMethod;
    }

    public int getLine() {
        return line;
    }

    public String getSnippet() {
        return snippet;
    }

    @Override
    public String toString() {
        return "TaintSink{" +
                "type=" + type +
                ", targetMethod='" + targetMethod + '\'' +
                ", line=" + line +
                '}';
    }
}
