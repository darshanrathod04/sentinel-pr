# SentinelPR Reliability & Benchmarking Framework (v1.2)

## Overview
This benchmark suite objectively evaluates the **detection accuracy**, **remediation quality**, and **performance latency** of SentinelPR across all 13 supported rules:

- **10 Security Rules (OWASP / CWE)**: `SEC-001` through `SEC-010`
- **3 Architectural Hygiene Rules**: `ARCH-001` through `ARCH-003`

## Initial Corpus (26 Cases)
- 13 Vulnerable Cases (`TC-***-V01`): Positive tests to measure True Positives ($TP$) and False Negatives ($FN$).
- 13 Safe Cases (`TC-***-S01`): Negative tests to measure True Negatives ($TN$) and False Positives ($FP$).

## Ground Truth
All expectations are formally defined in `benchmark/ground-truth/ground-truth-catalog.json` and validated against `benchmark/ground-truth/schema/benchmark-case.schema.json`.

## Evaluation Pipeline
1. **Detection Evaluation**: Calculates Confusion Matrix, Precision, Recall, F1-Score, False Positive Rate (FPR), and False Negative Rate (FNR).
2. **Remediation Verification (8 Stages)**:
   - Patch Generation
   - Unified Diff Validity
   - Clean In-Memory Patch Application
   - JavaParser AST Syntax Verification (Java 21 LTS)
   - JDK 21 In-Memory Compilation (`javax.tools.JavaCompiler`)
   - Target Vulnerability Elimination
   - Cross-Rule Regression Freedom
   - Token & Policy Safety Checks
3. **Performance Profiling**: High-resolution `System.nanoTime()` measurements for inspection, rule evaluation, remediation, and compilation.

## Running the Benchmark
```bash
# Via Maven
mvn test -Dtest=BenchmarkRunnerTest

# Filter by specific rule
mvn test -Dtest=BenchmarkRunnerTest -Dbenchmark.rule=SEC-005
```
