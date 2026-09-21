# License Recommendation — Apache-2.0

**Recommendation: adopt the Apache License 2.0** and commit the canonical license text as `LICENSE` in the repository root.

> **Status (updated):** the official Apache-2.0 text **is now committed** as `LICENSE` at the
> repository root (release engineering phase, v1.0.0). Remaining optional follow-ups are
> listed below.

## Why Apache-2.0 fits SentinelPR

1. **The project already declares it.** The README badge (`License: Apache 2.0`) signals the intent; committing the file makes the intent enforceable and unambiguous.

2. **Explicit patent grant.** Apache-2.0 includes a contributor patent license. SentinelPR is a static-analysis tool whose value lies partly in detection techniques (taint tracking, rule engines); an explicit patent grant protects adopters and enterprise users from patent assertions by contributors.

3. **Enterprise redistributability.** The target users are enterprises embedding SentinelPR in CI/CD. Apache-2.0 permits commercial use, private forks, and redistribution with minimal conditions (license notice + NOTICE file), unlike copyleft licenses (GPL/AGPL) that would complicate embedding the copilot in proprietary pipelines.

4. **Ecosystem compatibility.** Key dependencies are already Apache-2.0-family friendly: Shree AI OS is distributed via Maven Central by the same author under Apache-2.0, Spring Framework is Apache-2.0, and JavaParser is Apache-2.0/LGPL dual-licensed. Apache-2.0 at the project level keeps attribution obligations simple and compatible.

5. **NOTICE mechanism.** The Apache NOTICE file workflow lets the project document derived components (Shree AI OS, JavaParser) cleanly — useful for compliance teams performing SOC2/ISO vendor reviews, which is exactly SentinelPR's audience.

## Required follow-up (release blockers)

1. Add the official Apache-2.0 text as `LICENSE` at the repository root.
2. Add a short `NOTICE` file naming the project and noting it relies on Shree AI OS (`io.github.darshanrathod04:shree-ai-os`) and JavaParser.
3. Update `pom.xml` with the license block:

```xml
<licenses>
    <license>
        <name>Apache License, Version 2.0</name>
        <url>https://www.apache.org/licenses/LICENSE-2.0.txt</url>
        <distribution>repo</distribution>
    </license>
</licenses>
```

4. Add SPDX identifier headers (`SPDX-License-Identifier: Apache-2.0`) to source files if the maintainer wants file-level clarity (optional; the root `LICENSE` is legally sufficient).
5. Verify `apps/sentinel-pr/README.md` (the duplicate copy) carries the same license statement.

## Alternatives considered

| License | Verdict |
|---|---|
| MIT | Simpler, but no explicit patent grant — weaker for a detection-technique-heavy tool |
| GPL-3.0/AGPL | Copyleft would discourage the enterprise embedding that is SentinelPR's primary use case |
| BSD-3 | Acceptable, but lacks the patent grant and NOTICE workflow |
