# SentinelPR Phase 5.2 — Python Security Engine Edge-Case Hardening Report

**Status:** COMPLETE  
**Verdict:** **PASS** (Ready for maintainer release gate review)  
**Target Release:** `v1.2.0` (**BLOCKED** — Audit and hardening phase only; no tags or version bumps created)  
**Evaluated Commit SHA:** `3c79ad7ab8f55da4f9958c003ceb185c7b35e44d`  
**Remote `origin/main`:** In exact sync at `3c79ad7ab8f55da4f9958c003ceb185c7b35e44d`  

---

## 1. Executive Summary

Phase 5.2 was executed to eliminate the two confirmed false negatives identified during the Phase 5.1 independent audit (`case17` and `case19`), implement focused security rules for TLS verification bypass and session cookie security attributes, expand the curated benchmark suite from 40 to 50 fixtures, and validate the complete multi-language engine against a full clean-clone regression suite.

All objectives have been successfully achieved:
1. **Defect 1 Resolved (M1 - Expression Parsing):** Distinguishes binary concatenations from atomic string literals. `case17_taint_sqli.py` is detected with zero regressions on static literals or f-strings.
2. **Defect 2 Resolved (M2 - Dynamic Path Evaluation):** Evaluates `PythonCallExpr` (`os.path.join`, `pathlib.Path`, `joinpath`) and `/` division operator with multi-hop taint propagation. `case19_path_multihop.py` is detected with zero false alarms on static constants.
3. **M3 Implemented (TLS & Cookie Security):** Detects explicitly disabled TLS verification (`verify=False`) in `requests` and `httpx`, and flags sensitive session/authentication cookies set without mandatory `HttpOnly` and `Secure` attributes across Flask, Django, and FastAPI.
4. **Governed 50-Case Benchmark Ground Truth:** Expanded from 40 to 50 cases (25 vulnerable, 25 safe controls):
   - **True Positives (TP):** 25
   - **False Positives (FP):** 0
   - **True Negatives (TN):** 25
   - **False Negatives (FN):** 0
   - **Precision:** 100.00%
   - **Recall:** 100.00%
   - **Specificity:** 100.00%
   - **Accuracy:** 100.00%
   - **F1-Score:** 100.00%
   - **Manual Remediation Boundary:** 25 / 25 (100.00%)
5. **Clean-Clone Full Regression Suite:** Fresh isolated clone from `origin/main` executed `mvn clean test` across the entire project: **253 tests run, 0 failures, 0 errors, 0 skipped**. The 108-case Java benchmark remains invariant at 100% precision/recall with 56 verified automatic patches.

---

## 2. Baseline and Milestone Commit Log

All changes were implemented, verified, and pushed milestone by milestone to `origin/main`:

| Milestone | Commit SHA | Message | Key Changes |
| :--- | :--- | :--- | :--- |
| **Baseline** | `13257ba` | `audit(phase-5.1): record independent python security engine audit report` | Phase 5.1 baseline verification |
| **M1** | `fa70ff4` | `fix(python): distinguish binary string concatenations from atomic literals` | `PythonSourceParser`: tokenized literal detection, escape tracking, unwrapping |
| **M2** | `d54809a` | `fix(python): evaluate dynamic call expressions and multi-hop paths in os.path and pathlib` | `PythonSecurityRuleEngine`: `isDynamicPathExpression` handles calls, `/` operator |
| **M3** | `5e8785d` | `feat(python): implement tls verification bypass and cookie security analysis` | Detects `verify=False` and insecure cookie attributes (`HttpOnly`, `Secure`) |
| **M4** | `3c79ad7` | `test(python): expand hardened benchmark suite to 50 cases with 100 percent precision and recall` | 50 benchmark cases (cases 21-25 safe & vuln) and updated ground truth |

---

## 3. Root Cause and Defect Remediation

### Defect 1: Expression Parsing Classification Gap (`case17`)
- **Observed Failure:** `"SELECT * FROM users WHERE role = '" + role_filter + "'"` was classified as an atomic string literal because it starts with `"` and ends with `"`.
- **Root Cause:** `parseExpression()` applied `trimmed.startsWith("\"") && trimmed.endsWith("\"")` before parsing top-level binary operators, falsely absorbing the entire binary concatenation.
- **Fix:**
  1. Reordered `parseExpression()` to parse top-level binary operators (`+`, `%`, `/`) *prior* to string literal classification.
  2. Implemented `parseStringLiteralInfo()`: verifies that the opening quote matches an unescaped closing quote that terminates *strictly* at `trimmed.length()`.
  3. Implemented `isEscaped(text, index)`: accurately accounts for consecutive backslashes (`\\`) to distinguish escaped quotes (`\"`) from escaped backslashes preceding a quote (`\\"`).
  4. Added triple-quoted string tracking (`"""`, `'''`) in `findTopLevelBinaryOp`.

### Defect 2: Dynamic Path Call Expression Evaluation Gap (`case19`)
- **Observed Failure:** `target_path = os.path.join("/var/documents", doc_id); open(target_path)` was evaluated as a static path.
- **Root Cause:** `isDynamicPathExpression()` inspected only `PythonBinaryExpr`, `PythonLiteralExpr.Kind.FSTRING`, and `PythonNameExpr`, returning `false` whenever an assignment right-hand side was a `PythonCallExpr`.
- **Fix:**
  1. Extended `isDynamicPathExpression()` to handle `PythonCallExpr`:
     - Checks if call is an input source (`request.args.get`, `request.form.get`, `request.values`, `sys.argv`, `os.environ.get`, `input`).
     - Checks if call is a path construction function (`os.path.join`, `Path`, `pathlib.Path`, `joinpath`, `os.path.expanduser`).
     - Recursively checks all arguments: if any argument is dynamic, the constructed path is dynamic. If all arguments are static literals, the constructed path is static.
  2. Added support for pathlib `/` division operator in `PythonSourceParser` and `isDynamicPathExpression`.
  3. Added cycle-safe recursion (`Set<String> visitedVars`) to prevent infinite recursion on circular variable assignments.

---

## 4. Parser and Taint Tracker Boundaries & Limitations

The following engineering limitations are preserved and explicitly documented:
1. **Intra-Procedural Taint Only:** Taint flows within a single function body across variable assignments, string concatenations, and method call arguments. Inter-procedural propagation across external caller/callee function boundaries is not performed.
2. **Dynamic Script Execution Prohibited:** SentinelPR never invokes a Python runtime or executes Python code (e.g. `setup.py` dynamic builds are disallowed).
3. **No AST Mutation for Non-Java Code:** Automatic unified diff generation and AST rewrite transformers are strictly disabled for Python source code.
4. **Unsupported Syntax Constructs:**
   - Structural pattern matching (`match ... case`) from Python 3.10 is parsed as generic block statements.
   - Dynamic `getattr()`, `setattr()`, and `locals()` reflections are not symbolically resolved.
   - Bitwise shift operators (`<<`, `>>`) and matrix multiplication (`@`) in expressions are not split.

---

## 5. TLS and Cookie Security Analysis Behavior

### 1. TLS Certificate Verification Bypass
- **Rule Mapped:** `SecurityRule.FAIL_OPEN_SECURITY` (`SEC-001-FAIL-OPEN`) / CWE-295 / CWE-393
- **Severity:** `CRITICAL` (Confidence: 0.99)
- **Detection Targets:**
  - `requests.get(url, verify=False)`
  - `requests.post(url, verify=False)`
  - `requests.put(url, verify=False)`, `requests.delete(url, verify=False)`, `requests.request(url, verify=False)`
  - `httpx.get(url, verify=False)`, `httpx.post(url, verify=False)`, `httpx.Client(verify=False)`
- **Precision Guards:**
  - Flags only when `verify` keyword argument is present and explicitly set to `False`.
  - Does NOT flag `verify=True`, omitted `verify` (safe default), or passing custom CA paths (`verify="/etc/ssl/certs/custom.pem"`).
  - Does NOT flag unrelated variables named `verify = False`.

### 2. Cookie Security Attributes
- **Rule Mapped:** `SecurityRule.FAIL_OPEN_SECURITY` (`SEC-001-FAIL-OPEN`) / CWE-614 / CWE-1004
- **Severity:** `HIGH` (Confidence: 0.95)
- **Detection Targets:**
  - `response.set_cookie(...)` in Flask, Django, and FastAPI
- **Precision Guards:**
  - Inspects cookie name: flags only sensitive session/authentication cookies (`session`, `sessionid`, `auth`, `token`, `jwt`, `user`, `login`, `credentials`, `csrf`, `id_token`).
  - Requires `httponly=True` (guards against XSS extraction via `document.cookie`).
  - Requires `secure=True` (guards against transmission over plaintext HTTP).
  - Does NOT flag harmless tracking or UI preferences (e.g., `theme`, `lang`, `ui_mode`).

---

## 6. Governed 50-Case Python Benchmark Suite

The suite was expanded to 50 cases (25 vulnerable, 25 safe controls) under `benchmark/cases/python/`:

```
===============================================================================
            SENTINELPR HARDENED PYTHON SECURITY BENCHMARK SCORECARD            
===============================================================================
--- VULNERABLE FIXTURES (25 CASES) ---
 [PASS - TP] case01_sqli.py                    -> 1 finding(s) [SEC-005-SQL-INJECTION]
 [PASS - TP] case02_cmdi.py                    -> 1 finding(s) [SEC-004-UNISOLATED-SUBPROCESS]
 [PASS - TP] case03_eval.py                    -> 1 finding(s) [SEC-004-UNISOLATED-SUBPROCESS]
 [PASS - TP] case04_pickle.py                  -> 1 finding(s) [SEC-007-INSECURE-DESERIALIZATION]
 [PASS - TP] case05_yaml.py                    -> 1 finding(s) [SEC-007-INSECURE-DESERIALIZATION]
 [PASS - TP] case06_path.py                    -> 1 finding(s) [SEC-006-PATH-TRAVERSAL]
 [PASS - TP] case07_ssrf.py                    -> 1 finding(s) [SEC-012-SSRF]
 [PASS - TP] case08_crypto.py                  -> 1 finding(s) [SEC-018-WEAK-CRYPTO]
 [PASS - TP] case09_random.py                  -> 1 finding(s) [SEC-019-INSECURE-RANDOM]
 [PASS - TP] case10_flask.py                   -> 1 finding(s) [SEC-020-XSS]
 [PASS - TP] case11_django_raw_sqli.py         -> 1 finding(s) [SEC-005-SQL-INJECTION]
 [PASS - TP] case12_django_xss.py              -> 1 finding(s) [SEC-020-XSS]
 [PASS - TP] case13_fastapi_cors.py            -> 1 finding(s) [SEC-010-SPRING-PERMISSIVE-CORS]
 [PASS - TP] case14_flask_debug.py             -> 1 finding(s) [SEC-001-FAIL-OPEN]
 [PASS - TP] case15_django_hosts.py            -> 1 finding(s) [SEC-001-FAIL-OPEN]
 [PASS - TP] case16_cmdi_shell.py              -> 1 finding(s) [SEC-004-UNISOLATED-SUBPROCESS]
 [PASS - TP] case17_taint_sqli.py              -> 1 finding(s) [SEC-005-SQL-INJECTION]
 [PASS - TP] case18_exec_code.py               -> 1 finding(s) [SEC-004-UNISOLATED-SUBPROCESS]
 [PASS - TP] case19_path_multihop.py           -> 1 finding(s) [SEC-006-PATH-TRAVERSAL]
 [PASS - TP] case20_ssrf_post.py               -> 1 finding(s) [SEC-012-SSRF]
 [PASS - TP] case21_tls_verify_disabled.py     -> 1 finding(s) [SEC-001-FAIL-OPEN]
 [PASS - TP] case22_insecure_cookie.py         -> 1 finding(s) [SEC-001-FAIL-OPEN]
 [PASS - TP] case23_pathlib_slash_traversal.py -> 1 finding(s) [SEC-006-PATH-TRAVERSAL]
 [PASS - TP] case24_nested_concat_sqli.py      -> 1 finding(s) [SEC-005-SQL-INJECTION]
 [PASS - TP] case25_httpx_tls_bypass.py        -> 1 finding(s) [SEC-001-FAIL-OPEN]

--- SAFE CONTROL FIXTURES (25 CASES) ---
 [PASS - TN] case01_sqli_safe.py               -> Clean (0 findings)
 [PASS - TN] case02_cmdi_safe.py               -> Clean (0 findings)
 [PASS - TN] case03_eval_safe.py               -> Clean (0 findings)
 [PASS - TN] case04_pickle_safe.py             -> Clean (0 findings)
 [PASS - TN] case05_yaml_safe.py               -> Clean (0 findings)
 [PASS - TN] case06_path_safe.py               -> Clean (0 findings)
 [PASS - TN] case07_ssrf_safe.py               -> Clean (0 findings)
 [PASS - TN] case08_crypto_safe.py             -> Clean (0 findings)
 [PASS - TN] case09_random_safe.py             -> Clean (0 findings)
 [PASS - TN] case10_flask_safe.py              -> Clean (0 findings)
 [PASS - TN] case11_django_raw_sqli_safe.py    -> Clean (0 findings)
 [PASS - TN] case12_django_xss_safe.py         -> Clean (0 findings)
 [PASS - TN] case13_fastapi_cors_safe.py       -> Clean (0 findings)
 [PASS - TN] case14_flask_debug_safe.py        -> Clean (0 findings)
 [PASS - TN] case15_django_hosts_safe.py       -> Clean (0 findings)
 [PASS - TN] case16_cmdi_shell_safe.py         -> Clean (0 findings)
 [PASS - TN] case17_taint_sqli_safe.py         -> Clean (0 findings)
 [PASS - TN] case18_exec_code_safe.py          -> Clean (0 findings)
 [PASS - TN] case19_adversarial_comments.py    -> Clean (0 findings)
 [PASS - TN] case20_adversarial_malformed.py   -> Clean (0 findings)
 [PASS - TN] case21_tls_verify_safe.py         -> Clean (0 findings)
 [PASS - TN] case22_insecure_cookie_safe.py    -> Clean (0 findings)
 [PASS - TN] case23_pathlib_slash_safe.py      -> Clean (0 findings)
 [PASS - TN] case24_nested_concat_safe.py      -> Clean (0 findings)
 [PASS - TN] case25_httpx_tls_safe.py          -> Clean (0 findings)
===============================================================================
Detection Matrix: TP=25, FP=0, TN=25, FN=0
Precision: 100.00% | Recall: 100.00% | Specificity: 100.00% | Accuracy: 100.00%
F1-Score: 100.00%  | Manual Remediation Boundary: 25 / 25 (100.00%)
--- PER-RULE DETECTION BREAKDOWN ---
  SEC-001-FAIL-OPEN              : 5 detection(s)
  SEC-004-UNISOLATED-SUBPROCESS  : 4 detection(s)
  SEC-005-SQL-INJECTION          : 4 detection(s)
  SEC-006-PATH-TRAVERSAL         : 3 detection(s)
  SEC-007-INSECURE-DESERIALIZATION : 2 detection(s)
  SEC-010-SPRING-PERMISSIVE-CORS : 1 detection(s)
  SEC-012-SSRF                   : 2 detection(s)
  SEC-018-WEAK-CRYPTO            : 1 detection(s)
  SEC-019-INSECURE-RANDOM        : 1 detection(s)
  SEC-020-XSS                    : 2 detection(s)
===============================================================================
```

### Benchmark Progression Comparison

| Metric | Phase 5 Baseline (20 Cases) | Phase 5.1 Audit (40 Cases) | Phase 5.2 Hardened (50 Cases) | Delta (5.1 -> 5.2) |
| :--- | :--- | :--- | :--- | :--- |
| **Vulnerable Cases** | 10 | 20 | **25** | +5 cases |
| **Safe Control Cases** | 10 | 20 | **25** | +5 cases |
| **True Positives (TP)** | 10 | 18 | **25** | +7 TPs |
| **False Positives (FP)** | 0 | 0 | **0** | 0 (Invariance preserved) |
| **True Negatives (TN)** | 10 | 20 | **25** | +5 TNs |
| **False Negatives (FN)** | 0 | 2 | **0** | -2 FNs (Resolved) |
| **Precision** | 100.00% | 100.00% | **100.00%** | Unchanged |
| **Recall** | 100.00% | 90.00% | **100.00%** | **+10.00%** |
| **F1-Score** | 100.00% | 94.74% | **100.00%** | **+5.26%** |
| **Manual Remediation** | 10 / 10 (100%) | 18 / 18 (100%) | **25 / 25 (100%)** | 100.00% Enforced |

---

## 7. Full Regression Evidence (Clean-Clone Validation)

A fresh isolated clone of `origin/main` commit `3c79ad7ab8f55da4f9958c003ceb185c7b35e44d` was evaluated in an isolated directory:

- **Environment:** Clean clone (`git clone --branch main https://github.com/darshanrathod04/sentinel-pr.git`)
- **Command:** `mvn clean test`
- **Exit Code:** `0`
- **Summary:**
  ```
  [INFO] -------------------------------------------------------
  [INFO]  T E S T S
  [INFO] -------------------------------------------------------
  ...
  [INFO] Results:
  [INFO] 
  [INFO] Tests run: 253, Failures: 0, Errors: 0, Skipped: 0
  [INFO] 
  [INFO] ------------------------------------------------------------------------
  [INFO] BUILD SUCCESS
  [INFO] ------------------------------------------------------------------------
  [INFO] Total time:  03:14 min
  [INFO] Finished at: 2026-11-06T11:05:07+05:30
  ```

### Breakdown of Test Suites in Full Regression
- **Phase 4B.2 Action PR-Diff Contract & Integration:** 10 tests passing
- **Core Java Security Benchmark Suite (108 Cases):** 108 fixtures evaluated ($TP=62, TN=46, FP=0, FN=0$, 56 automatic patches synthesized)
- **Phase 5.2 Python Security Benchmark Suite (50 Cases):** 50 fixtures evaluated ($TP=25, TN=25, FP=0, FN=0$)
- **Python AST Parser Suite (`PythonSourceParserTest`, `PythonParserAuditTest`):** 14 tests passing
- **Python Security & Taint Suites (`PythonSecurityRulesTest`, `PythonTaintAnalysisTest`):** 13 tests passing
- **Python Framework & Dependency Suites (`PythonFrameworkSecurityTest`, `PythonDependencyScannerTest`):** 11 tests passing
- **Multi-Language, CLI & SARIF Suites (`PythonSarifAndCommentIntegrationTest`, `MixedLanguageIntegrationTest`):** 9 tests passing
- **Architecture, Intelligence & Controller Suites:** 48 tests passing
- **Total:** **253 / 253 passing (100% pass rate, 0 failures, 0 errors)**

---

## 8. Java Benchmark & Engine Invariance

The Python edge-case fixes caused zero disruption to the core Java security and patch engine:
- **Java Benchmark Ground Truth:** Invariant at 108 cases ($TP = 62, TN = 46, FP = 0, FN = 0$).
- **Verified Automated Patches:** Exactly 56 verified unified diff patches produced.
- **Strict AST Boundary:** Non-Java files are handled exclusively by `MultiLanguageSourceInspector`. Java AST transformers (`JavaParser`, `CompilationUnit`) are never invoked for Python source files.

---

## 9. Security and Remediation Boundary Verification

Every Python finding across all unit tests and benchmark cases strictly satisfies:
1. `patch.getStatus() == UnifiedDiffPatch.Status.MANUAL_REMEDIATION_REQUIRED`
2. `patch.isVerified() == false`
3. `patch.getUnifiedDiff().isEmpty() == true`
4. Zero automated edits or patch suggestions are written to Python source files.
5. All PR comments explicitly append:  
   `"*(Automated code transformation is restricted to Java. Manual remediation is required for Python findings.)*"`

---

## 10. Remaining Risks & Phase 6 Recommendations

1. **Inter-procedural Taint Propagation:** As currently designed, taint does not track across external helper functions or module boundaries. If a web route handler passes `request.args` to an unannotated helper function in another module that executes SQL, intra-procedural taint tracking will not bridge the call. (Slated for Phase 6 whole-program call-graph analysis).
2. **Pipfile.lock & setup.py Manifests:** Manifest scanning supports `requirements.txt`, `pyproject.toml`, `poetry.lock`, and `Pipfile`, but does not parse JSON-based `Pipfile.lock`.
3. **Complex Type Inference:** Python's dynamic duck-typing limits static inference when method calls are invoked on untyped parameters (`obj.do_something()`).

---

## 11. Final Verdict

### Final Verdict: **PASS**

All requirements of Phase 5.2 have been satisfied:
- Confirmed false negatives eliminated ($FN = 0$).
- Hardened 50-case benchmark ground truth established with 100% precision, 100% recall, and 100% F1-score.
- TLS verification bypass and cookie security rules implemented and verified.
- 100% manual remediation boundary strictly enforced for Python findings.
- Clean-clone full regression suite passing across all 253 automated tests.
- **SentinelPR v1.2.0 release remains held pending maintainer release authorization.**
