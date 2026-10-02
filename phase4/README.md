# Phase 4: Production Validation & Productization

## Sub-Phase 4A — Real Repository Validation

### 1. Charter & Purpose

The objective of **Phase 4A** is to systematically evaluate, stress-test, and harden SentinelPR against real-world, standalone software repositories beyond the curated benchmark corpus.

> [!IMPORTANT]
> **Corpus Scope Notice:**
> The 108-case benchmark measures behavior on a controlled corpus. It is not evidence of 100% accuracy on arbitrary repositories. Real-world code introduces diverse architectures, nested frameworks, varied build systems, dynamic dataflows, and idiom variations that require rigorous empirical validation.

---

### 2. The Real Repository Validation Loop

Real-repository validation follows a closed-loop empirical methodology designed to prevent confirmation bias and isolate engineering defects:

```
┌────────────────────────┐
│    REAL REPOSITORY     │
│  (Target Commit SHA)   │
└───────────┬────────────┘
            │
            ▼
┌────────────────────────┐
│  SENTINELPR ANALYSIS   │
│  (AST / Taint / Rules) │
└───────────┬────────────┘
            │
            ▼
┌────────────────────────┐
│      OBSERVATIONS      │
│  (Raw Findings & Logs) │
└───────────┬────────────┘
            │
            ▼
┌────────────────────────┐
│ GROUND-TRUTH AUDIT     │
│ (Independent Review)   │
└───────────┬────────────┘
            │
            ▼
┌───────────────────────────────────────────┐
│              CLASSIFICATION               │
│  TP  │  FP  │  FN  │  TN  │  UNCERTAIN   │
└───────────────────┬───────────────────────┘
                    │
                    ▼
┌────────────────────────┐
│  ROOT-CAUSE ANALYSIS   │
│  (Parser/Taint/Models) │
└───────────┬────────────┘
            │
            ▼
┌────────────────────────┐
│ ACTIONABLE ENGINEERING │
│ (Hardening / Upgrades) │
└────────────────────────┘
```

1. **Target Identification:** Select an existing repository from the catalog at a pinned commit SHA.
2. **Analysis Execution:** Run the pinned production SentinelPR release (currently `v1.1.4`) or development engine against the target source tree.
3. **Observation Recording:** Log every finding verbatim, capturing file path, line numbers, snippet, severity, rule ID, and causal explanation.
4. **Independent Ground-Truth Audit:** Manually inspect the surrounding class hierarchy, framework configurations, and dataflow paths without altering the analyzed source.
5. **Rigorous Classification:** Categorize every observation using verified criteria.
6. **Root-Cause Analysis:** For all false positives, false negatives, parser errors, or remediation regressions, identify the exact engine heuristic, AST limitation, or framework gap responsible.
7. **Actionable Engineering Work:** Generate prioritized backlog items for engine enhancement.

---

### 3. Classification Taxonomy

To ensure mathematical and statistical integrity, findings must be classified into exactly one of five verified outcomes:

| Classification | Definition | Ground Truth State | SentinelPR State |
| :--- | :--- | :--- | :--- |
| **`TP` (True Positive)** | Verified genuine security flaw correctly flagged by the engine. | Vulnerable | Finding Detected |
| **`FP` (False Positive)** | Verified safe construct or mitigated path incorrectly flagged as an active flaw. | Safe | Finding Detected |
| **`FN` (False Negative)** | Verified security flaw that the engine failed to detect. | Vulnerable | No Finding Detected |
| **`TN` (True Negative)** | Verified safe construct where the engine correctly remained silent. | Safe | No Finding Detected |
| **`UNCERTAIN`** | Ambiguous construct with insufficient operational or business logic context to establish ground truth. | Inconclusive | Evaluated |

> [!WARNING]
> **Strict Guardrail on Inconclusive Findings:**
> Never force ambiguous observations into `TP`, `FP`, `FN`, or `TN`. If business context, external service configuration, runtime environment, or library semantics cannot be proven conclusively, the observation **must** remain classified as `UNCERTAIN` until evidence is obtained.

---

### 4. Directory Structure

- [`repositories/`](repositories/README.md): Metadata catalog of target repositories selected for real-world validation.
- [`schemas/`](schemas/): JSON schemas enforcing structural consistency across repository runs and individual finding audits.
- [`observations/`](observations/README.md): Raw audit records, classification logs, and causal reviews.
- [`reports/`](reports/README.md): Normalized engineering scorecards and findings summaries per repository.
- [`scripts/`](scripts/README.md): Automation tools for execution orchestration and report generation.
