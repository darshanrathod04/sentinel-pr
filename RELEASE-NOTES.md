# RELEASE-NOTES — SentinelPR v1.0.0 (Maintainer Release Checklist)

Release engineering checklist for publishing SentinelPR v1.0.0. No feature work is
included in this phase; all items below are release mechanics. Execute top-to-bottom.

## 0. Repository cleanup (manual decision required)

- [ ] **Duplicate documentation under `apps/sentinel-pr/`** — `apps/sentinel-pr/README.md`
      and `apps/sentinel-pr/USAGE_GUIDE.md` duplicate the root `README.md` and
      `USAGE_GUIDE.md` and can drift out of sync.
      **Recommendation: remove this directory in the release PR** (it is not referenced
      by the build). Intentionally *not* deleted automatically — confirm with the
      maintainer first.
- [ ] Confirm working-tree noise (`.sentinelhistory.json`, `compliance-audit.log`,
      `local-baseline.json`, `strict-policy.json` at root, `release/`, `SHA256SUMS.txt`)
      is gitignored or intentionally committed. `local-baseline.json` and
      `strict-policy.json` are also shipped in `examples/`.

## 1. Build

- [ ] `mvn clean install -DskipTests` succeeds on JDK 21
- [ ] Run `powershell -ExecutionPolicy Bypass -File scripts/build-release.ps1`
      (clean → test → package → SHA256SUMS.txt → `release/` assembly)
- [ ] `release/sentinel-pr-1.0.0.jar` exists and starts:
      `java -jar release/sentinel-pr-1.0.0.jar` prints the CLI usage menu (exit 3)
- [ ] `release/SHA256SUMS.txt` lists every release asset with SHA-256 hashes
      (verify: `sha256sum -c SHA256SUMS.txt` on Linux, or `Get-FileHash` on Windows)

## 2. Tests

- [ ] `mvn test` green: **36 tests, 0 failures, 0 errors, 0 skipped**
      across `SentinelPrApplicationTest` + P0–P4 verification suites
- [ ] Spot-check the CLI end-to-end:
      - audit: `mvn exec:java -Dexec.mainClass=com.sentinelpr.cli.SentinelCliRunner "-Dexec.args=examples/VulnerableService.java"`
      - governance: same target with `--baseline examples/local-baseline.json --policy examples/strict-policy.json`
      - chat: `-Dexec.args=--chat "Explain why requestCount++ is unsafe in Java"`
        (with and without `GEMINI_API_KEY` set)
- [ ] REST smoke test: `mvn spring-boot:run` then `GET http://localhost:8080/api/v1/sentinel/health`

## 3. CI

- [ ] `.github/workflows/maven.yml` present (ubuntu-latest, Temurin 21, Maven cache,
      `mvn -B test`, triggers on push + pull_request)
- [ ] Workflow executes green on the release PR and on `main` after merge
- [ ] (Optional follow-up) add a release workflow triggered on version tags

## 4. License

- [ ] `LICENSE` (Apache-2.0, official text) committed at repository root
- [ ] Optional: add `NOTICE` naming Shree AI OS (`io.github.darshanrathod04:shree-ai-os`)
      and JavaParser
- [ ] Optional: add the `<licenses>` block to `pom.xml` (see `docs/LICENSE-RECOMMENDATION.md`)
- [ ] Confirm the README badge now resolves to an existing file

## 5. Tag

- [ ] Version is `1.0.0` in `pom.xml` (`com.sentinelpr:sentinel-pr` — coordinates unchanged)
- [ ] Tag the release commit:
      ```bash
      git tag -a v1.0.0 -m "SentinelPR v1.0.0"
      git push origin v1.0.0
      ```
- [ ] Confirm `CHANGELOG.md` has the matching `[1.0.0]` entry

## 6. GitHub Release

- [ ] Create release **v1.0.0** from the tag (GitHub → Releases → Draft new release)
- [ ] Title: `SentinelPR v1.0.0 — Enterprise Code & Security Review Copilot`
- [ ] Paste the `CHANGELOG.md` `[1.0.0]` section as the release body
- [ ] Mark **not** a pre-release (it supersedes the SDK's own developer-preview naming)

## 7. Upload JAR

- [ ] Attach `release/sentinel-pr-1.0.0.jar` (executable Spring Boot CLI jar)
- [ ] Note in the release body: run with `java -jar sentinel-pr-1.0.0.jar <target-path> [options]`

## 8. Upload SHA256

- [ ] Attach `release/SHA256SUMS.txt`
- [ ] Verify the published checksums match the uploaded JAR exactly

## 9. Publish

- [ ] Publish the GitHub Release
- [ ] Verify the release page renders the checklist body and both assets download
- [ ] Announce: README badge links, project homepage URL
      (`https://github.com/darshanrathod04/sentinel-pr`)
- [ ] Post-publish: create an `Unreleased` section at the top of `CHANGELOG.md`

---

### Environment variables referenced by the product (unchanged)

| Variable | Purpose |
|---|---|
| `GEMINI_API_KEY` | Google Gemini BYOK for the `--chat` assistant / reasoning |
| `SHREE_API_KEY` | Shree AI OS platform bootstrap (defaults to `local`) |
