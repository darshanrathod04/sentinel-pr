# Phase 4 Real-Repository Corpus Policy

This directory documents the catalog of standalone repositories selected for empirical evaluation in Phase 4A.

> [!CAUTION]
> **Repository Isolation & Secret Safety Policy:**
> 1. **Do NOT add third-party or external repository source code to the SentinelPR git tree.**
> 2. **Do NOT clone target repositories automatically during build or benchmark cycles.**
> 3. **Never store credentials, private access tokens, API secrets, database passwords, or proprietary customer source code in SentinelPR.**
> 4. All target repositories must be analyzed in independent external directories or temporary sandboxes.

---

## Target Repository Catalog

Each target repository is assigned a stable identifier (`REAL-REPO-xxx`) and tracked with strict metadata before analysis.

### `REAL-REPO-001`: Todo-Application
- **Repository Name:** `Todo-Application`
- **Owner:** darshanrathod04
- **Repository URL:** `https://github.com/darshanrathod04/Todo-Application`
- **Language:** Java 17+
- **Framework:** Spring Boot 3.x, Spring Data JPA, Spring Security
- **Repository Size:** Small (~10–25 classes)
- **Module Structure:** Single-module Maven application
- **Database Usage:** H2 / PostgreSQL via Spring Data JPA & JDBC
- **Authentication/Security Usage:** Basic Auth / JWT token authentication
- **Ownership:** Owned / Managed by maintainer
- **Visibility:** Public
- **Analysis Date:** Pending Phase 4A execution
- **Commit SHA Analyzed:** TBD (pinned on execution)
- **Validation Status:** `PLANNED`

---

### `REAL-REPO-002`: Smart Campus Connect
- **Repository Name:** `smart-campus-connect` (or `Smart-Campus-Connect`)
- **Owner:** darshanrathod04
- **Repository URL:** `https://github.com/darshanrathod04/smart-campus-connect`
- **Language:** Java 17+
- **Framework:** Spring Boot, REST APIs, JPA
- **Repository Size:** Medium (~25–60 classes)
- **Module Structure:** Multi-service / modular architecture
- **Database Usage:** Relational database (MySQL / PostgreSQL) with dynamic query generation
- **Authentication/Security Usage:** Role-based access control, session validation
- **Ownership:** Owned / Managed by maintainer
- **Visibility:** Public
- **Analysis Date:** Pending Phase 4A execution
- **Commit SHA Analyzed:** TBD (pinned on execution)
- **Validation Status:** `PLANNED`

---

### `REAL-REPO-003`: Library Management System
- **Repository Name:** `library-management-system`
- **Owner:** darshanrathod04
- **Repository URL:** `https://github.com/darshanrathod04/library-management-system`
- **Language:** Java
- **Framework:** Spring Boot / Classic Spring MVC, JDBC / Hibernate
- **Repository Size:** Medium (~20–40 classes)
- **Module Structure:** Standard controller-service-repository layered application
- **Database Usage:** SQL database with raw query composition and transactional updates
- **Authentication/Security Usage:** Form-based login, role permissions
- **Ownership:** Owned / Managed by maintainer
- **Visibility:** Public
- **Analysis Date:** Pending Phase 4A execution
- **Commit SHA Analyzed:** TBD (pinned on execution)
- **Validation Status:** `PLANNED`

---

### `REAL-REPO-004`: External Java/Spring Boot Benchmark Candidate 1
- **Repository Name:** Open-source Spring Boot reference application (e.g., Spring PetClinic or equivalent standard sample)
- **Owner:** Community / Open-Source Maintainers
- **Repository URL:** Pinned public open-source URL
- **Language:** Java 21 LTS
- **Framework:** Spring Boot 3.x/4.x, Spring Data JPA, Thymeleaf / REST
- **Repository Size:** Medium (~40–80 classes)
- **Module Structure:** Multi-layer Spring application
- **Database Usage:** Embedded HSQLDB / MySQL with Spring Data JPA
- **Authentication/Security Usage:** Standard Spring Security baseline
- **Ownership:** External Open Source
- **Visibility:** Public
- **Analysis Date:** Pending Phase 4A execution
- **Commit SHA Analyzed:** TBD (pinned on execution)
- **Validation Status:** `PLANNED`

---

### `REAL-REPO-005`: External Java/Spring Boot Enterprise Candidate 2
- **Repository Name:** Open-source enterprise microservices reference application (e.g., PiggyMetrics or Spring Cloud sample)
- **Owner:** Community / Open-Source Maintainers
- **Repository URL:** Pinned public open-source URL
- **Language:** Java 17/21
- **Framework:** Spring Boot, Spring Cloud, OAuth2 / JWT
- **Repository Size:** Large multi-module (>100 classes)
- **Module Structure:** Multi-module Maven / Gradle project
- **Database Usage:** Polyglot (MongoDB / PostgreSQL)
- **Authentication/Security Usage:** OAuth2 Resource Server, Gateway routing
- **Ownership:** External Open Source
- **Visibility:** Public
- **Analysis Date:** Pending Phase 4A execution
- **Commit SHA Analyzed:** TBD (pinned on execution)
- **Validation Status:** `PLANNED`

---

## Required Metadata Fields Checklist

When onboarding any new repository to this catalog, the following fields must be established and committed:
1. `repositoryId`: Stable identifier (`REAL-REPO-xxx`)
2. `repositoryName`: Exact repository name
3. `owner`: GitHub organization or individual owner
4. `repositoryUrl`: Pinned repository URL
5. `language`: Primary language and runtime version (e.g., Java 21)
6. `framework`: Framework and major version (e.g., Spring Boot 3.4.1)
7. `repositorySize`: Approximate class count and lines of code (LOC)
8. `moduleStructure`: Single-module vs. multi-module hierarchy
9. `databaseUsage`: ORM, JPA, JdbcTemplate, or raw JDBC
10. `authenticationUsage`: Security architecture (None, Basic, Session, JWT, OAuth2)
11. `analysisDate`: ISO-8601 UTC timestamp of audit execution
12. `commitSha`: Exact 40-character commit SHA audited
13. `ownership`: `OWNED` | `EXTERNAL_OSS` | `PROPRIETARY`
14. `visibility`: `PUBLIC` | `PRIVATE`
15. `validationStatus`: `PLANNED` | `IN_PROGRESS` | `AUDITED` | `BLOCKED`
