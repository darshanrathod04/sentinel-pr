package com.sentinelpr.core.analysis.taint;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * <b>TaintFlow</b>
 *
 * <p>Represents a complete dataflow trace from an untrusted source to a sensitive sink.</p>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class TaintFlow {

    private final TaintSource source;
    private final TaintSink sink;
    private final List<String> traceSteps;
    private final boolean sanitized;
    private final String sanitizerName;

    public TaintFlow(
            TaintSource source,
            TaintSink sink,
            List<String> traceSteps,
            boolean sanitized,
            String sanitizerName
    ) {
        this.source = Objects.requireNonNull(source, "source must not be null");
        this.sink = Objects.requireNonNull(sink, "sink must not be null");
        this.traceSteps = traceSteps != null ? Collections.unmodifiableList(traceSteps) : List.of();
        this.sanitized = sanitized;
        this.sanitizerName = sanitizerName != null ? sanitizerName : "";
    }

    public TaintSource getSource() {
        return source;
    }

    public TaintSink getSink() {
        return sink;
    }

    public List<String> getTraceSteps() {
        return traceSteps;
    }

    public boolean isSanitized() {
        return sanitized;
    }

    public String getSanitizerName() {
        return sanitizerName;
    }

    public String formatTrace() {
        StringBuilder sb = new StringBuilder();
        sb.append(source.getName()).append(" (line ").append(source.getLine()).append(")");
        for (String step : traceSteps) {
            sb.append(" -> ").append(step);
        }
        sb.append(" -> ").append(sink.getTargetMethod()).append(" (line ").append(sink.getLine()).append(")");
        if (sanitized) {
            sb.append(" [SANITIZED by ").append(sanitizerName).append("]");
        }
        return sb.toString();
    }

    public String formatMultiHopTrace() {
        StringBuilder sb = new StringBuilder();
        String src = source.getQualifiedName() != null && !source.getQualifiedName().isBlank()
                ? source.getQualifiedName()
                : source.getName();
        sb.append(src);
        for (String step : traceSteps) {
            sb.append(" -> ").append(step);
        }
        sb.append(" -> ").append(sink.getTargetMethod());
        return sb.toString();
    }

    @Override
    public String toString() {
        return "TaintFlow{" + formatTrace() + "}";
    }
}
