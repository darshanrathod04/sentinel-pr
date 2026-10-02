# Phase 4 Automation Scripts Documentation

This directory is designated for automation utilities supporting real-repository validation workflows.

---

## 1. Scope of Future Automation

Future engineering phases may provide scripts to standardize and streamline repetitive tasks:

- **Repository Preparation:** Pinned checkout of target repositories to dedicated sandboxes outside the SentinelPR tree.
- **SentinelPR Execution:** Running the SentinelPR CLI or Docker container against target directories with standardized rule configurations.
- **Result Collection:** Ingesting SARIF or JSON review comment outputs into structured observation records.
- **Normalization & Validation:** Validating observation files against `repository-validation.schema.json` and `finding-observation.schema.json`.
- **Scorecard Generation:** Rendering aggregated Markdown and JSON summary reports.

---

## 2. Phase 4A Operational Safety Constraints

> [!CAUTION]
> **Strict Operational Constraints for Phase 4A:**
> 1. **No Automatic Crawlers:** Do NOT implement web scrapers, crawlers, or bulk repository downloaders.
> 2. **No Arbitrary Ingestion:** Do NOT download or clone unvetted repositories.
> 3. **No Untrusted Execution:** Do NOT execute untrusted test suites, build scripts, or code from external repositories. SentinelPR performs purely static AST and dataflow inspection.
> 4. **No Automated Ground-Truth Assignment:** Algorithms or heuristics must NEVER assign `TP`, `FP`, `FN`, `TN`, or `UNCERTAIN` automatically. Ground truth determination requires expert human code review and causal verification.

During Phase 4A, all validations must be performed in a controlled, manual, step-by-step manner.
