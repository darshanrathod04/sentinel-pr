package com.sentinelpr.reproduction;

import com.sentinelpr.client.SentinelClient;
import com.sentinelpr.core.analysis.architecture.ArchitectureReviewEngine;
import com.sentinelpr.core.model.InspectedSource;
import com.sentinelpr.core.model.SecurityFinding;
import com.sentinelpr.core.model.SecurityRule;
import com.sentinelpr.core.service.CodeInspectionService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import com.sentinelpr.cli.SentinelCliRunner;
import com.sentinelpr.core.model.ReviewReport;

import static org.junit.jupiter.api.Assertions.*;

/**
 * <b>Phase4A7SccFailureReproductionTest</b>
 *
 * <p>Phase 4A.7 / Phase 4A.8 Test Suite for issues observed in Smart Campus Connect:</p>
 * <ul>
 *   <li><b>ISSUE A (ARCH-002):</b> Verified fix for sibling-source candidate resolution defect in {@code matchesFqcn}.</li>
 *   <li><b>ISSUE B (SEC-006):</b> Observation of false positives from numeric {@code Long @PathVariable} identifiers
 *       and constant path string concatenation.</li>
 * </ul>
 */
class Phase4A7SccFailureReproductionTest {

    private SentinelClient client;
    private CodeInspectionService inspectionService;
    private ArchitectureReviewEngine architectureEngine;

    @BeforeEach
    void setUp() {
        client = SentinelClient.bootstrap("local");
        inspectionService = new CodeInspectionService(client);
        architectureEngine = new ArchitectureReviewEngine();
    }

    // =========================================================================
    // PART 1: ARCH-002 SIBLING-SOURCE RESOLUTION FIX & CONTROLS
    // =========================================================================
    @Nested
    @DisplayName("Part 1: ARCH-002 Sibling-Source Resolution Fix & Controls")
    class Arch002SiblingSourceResolution {

        private final String activityLogCode = """
                package com.example.model;
                import jakarta.persistence.Entity;
                import jakarta.persistence.Id;
                @Entity
                public class ActivityLog {
                    @Id private Long id;
                    private String message;
                }
                """;

        private final String eventCode = """
                package com.example.model;
                import jakarta.persistence.Entity;
                import jakarta.persistence.Id;
                @Entity
                public class Event {
                    @Id private Long id;
                    private String title;
                }
                """;

        private final String partnerCode = """
                package com.example.model;
                import jakarta.persistence.Entity;
                import jakarta.persistence.Id;
                @Entity
                public class Partner {
                    @Id private Long id;
                    private String name;
                }
                """;

        private final String eventControllerCode = """
                package com.example.controller;
                import com.example.model.Event;
                import org.springframework.http.ResponseEntity;
                import org.springframework.web.bind.annotation.GetMapping;
                import org.springframework.web.bind.annotation.PostMapping;
                import org.springframework.web.bind.annotation.RequestBody;
                import org.springframework.web.bind.annotation.RequestMapping;
                import org.springframework.web.bind.annotation.RestController;
                import java.util.List;

                @RestController
                @RequestMapping("/api/events")
                public class EventController {
                    @GetMapping
                    public ResponseEntity<List<Event>> getAllEvents() {
                        return ResponseEntity.ok(List.of());
                    }

                    @PostMapping
                    public ResponseEntity<Event> createEvent(@RequestBody Event event) {
                        return ResponseEntity.ok(event);
                    }
                }
                """;

        @Test
        @DisplayName("Verified Fix: ActivityLog ordered before Event now resolves Event correctly (True Positive)")
        void testActivityLogBeforeEvent_ResolvesCorrectly() {
            InspectedSource activityLogSource = inspectionService.inspectSourceCode(activityLogCode, "ActivityLog.java");
            InspectedSource eventSource = inspectionService.inspectSourceCode(eventCode, "Event.java");
            InspectedSource controllerSource = inspectionService.inspectSourceCode(eventControllerCode, "EventController.java");

            // Ordering: ActivityLog is candidate #1 in com.example.model package
            List<InspectedSource> allSources = List.of(activityLogSource, eventSource, controllerSource);

            // 1. Check isEntityType
            boolean isEntity = architectureEngine.isEntityType("Event", controllerSource, allSources);
            assertTrue(isEntity, "Fix verified: isEntityType returns true when sibling ActivityLog precedes Event");

            // 2. Check full ARCH-002 evaluation
            List<SecurityFinding> findings = architectureEngine.evaluate(controllerSource, allSources);
            List<SecurityFinding> arch002Findings = findings.stream()
                    .filter(f -> f.getRule() == SecurityRule.ARCH_LEAKY_ABSTRACTION)
                    .toList();

            assertEquals(2, arch002Findings.size(), "Both endpoints in EventController must be detected as ARCH-002");
        }

        @Test
        @DisplayName("Control A: When Event is first in allSources, resolution succeeds (Detected)")
        void testControlA_EventFirst_Succeeds() {
            InspectedSource eventSource = inspectionService.inspectSourceCode(eventCode, "Event.java");
            InspectedSource activityLogSource = inspectionService.inspectSourceCode(activityLogCode, "ActivityLog.java");
            InspectedSource controllerSource = inspectionService.inspectSourceCode(eventControllerCode, "EventController.java");

            List<InspectedSource> allSources = List.of(eventSource, activityLogSource, controllerSource);

            boolean isEntity = architectureEngine.isEntityType("Event", controllerSource, allSources);
            assertTrue(isEntity, "Control A: When Event is candidate #1, matchesFqcn hits Event.java and returns true");

            List<SecurityFinding> findings = architectureEngine.evaluate(controllerSource, allSources);
            long arch002Count = findings.stream()
                    .filter(f -> f.getRule() == SecurityRule.ARCH_LEAKY_ABSTRACTION)
                    .count();
            assertEquals(2, arch002Count, "Control A: Both endpoints detected when Event is examined first");
        }

        @Test
        @DisplayName("Control B: When Event is after another entity in same package, resolution now succeeds")
        void testControlB_EventAfterOtherEntity_Succeeds() {
            InspectedSource partnerSource = inspectionService.inspectSourceCode(partnerCode, "Partner.java");
            InspectedSource eventSource = inspectionService.inspectSourceCode(eventCode, "Event.java");
            InspectedSource controllerSource = inspectionService.inspectSourceCode(eventControllerCode, "EventController.java");

            List<InspectedSource> allSources = List.of(partnerSource, eventSource, controllerSource);

            boolean isEntity = architectureEngine.isEntityType("Event", controllerSource, allSources);
            assertTrue(isEntity, "Control B: Fix verifies Partner before Event does not cause premature termination");
        }

        @Test
        @DisplayName("Control C: Wildcard import preserves correct entity detection")
        void testControlC_WildcardImport_Succeeds() {
            InspectedSource activityLogSource = inspectionService.inspectSourceCode(activityLogCode, "ActivityLog.java");
            InspectedSource eventSource = inspectionService.inspectSourceCode(eventCode, "Event.java");

            String wildcardControllerCode = """
                    package com.example.controller;
                    import com.example.model.*;
                    import org.springframework.http.ResponseEntity;
                    import org.springframework.web.bind.annotation.GetMapping;
                    import org.springframework.web.bind.annotation.RestController;

                    @RestController
                    public class WildcardController {
                        @GetMapping("/events")
                        public ResponseEntity<Event> getEvent() { return null; }
                    }
                    """;
            InspectedSource wildcardControllerSource = inspectionService.inspectSourceCode(wildcardControllerCode, "WildcardController.java");
            List<InspectedSource> allSources = List.of(activityLogSource, eventSource, wildcardControllerSource);

            boolean isEntityWildcard = architectureEngine.isEntityType("Event", wildcardControllerSource, allSources);
            assertTrue(isEntityWildcard, "Control C: Wildcard import resolves Event correctly via candidate matching");
        }

        @Test
        @DisplayName("Control D: Same simple name in different packages resolves to explicit import")
        void testControlD_DifferentPackageExplicitSelection() {
            String pkg1DtoCode = """
                    package com.example.model;
                    public class Event { private Long id; }
                    """;
            String pkg2EntityCode = """
                    package com.other.model;
                    import jakarta.persistence.Entity;
                    @Entity
                    public class Event { private Long id; }
                    """;
            InspectedSource dtoSource = inspectionService.inspectSourceCode(pkg1DtoCode, "DtoEvent.java");
            InspectedSource entitySource = inspectionService.inspectSourceCode(pkg2EntityCode, "OtherEvent.java");

            // Controller explicitly imports the DTO from com.example.model
            InspectedSource controllerSource = inspectionService.inspectSourceCode(eventControllerCode, "EventController.java");
            List<InspectedSource> allSources = List.of(entitySource, dtoSource, controllerSource);

            boolean isEntity = architectureEngine.isEntityType("Event", controllerSource, allSources);
            assertFalse(isEntity, "Control D: Controller explicitly importing com.example.model.Event (DTO) must NOT be an entity");
        }

        @Test
        @DisplayName("Control E: Non-entity DTO with same simple name is True Negative")
        void testControlE_NonEntityDto_IsFalse() {
            String eventDtoCode = """
                    package com.example.model;
                    public class Event {
                        private Long id;
                        private String title;
                    }
                    """;
            InspectedSource eventDtoSource = inspectionService.inspectSourceCode(eventDtoCode, "EventDto.java");
            InspectedSource controllerSource = inspectionService.inspectSourceCode(eventControllerCode, "EventController.java");

            List<InspectedSource> allSources = List.of(eventDtoSource, controllerSource);

            boolean isEntity = architectureEngine.isEntityType("Event", controllerSource, allSources);
            assertFalse(isEntity, "Control E: DTO without @Entity annotation must evaluate to false");
        }
    }

    // =========================================================================
    // PART 2: ARCH-002 SMART CAMPUS CONNECT ENTITY VERIFICATION (POST-FIX)
    // =========================================================================
    @Nested
    @DisplayName("Part 2: ARCH-002 SCC Entity Verification Post-Fix")
    class Arch002SccEntitiesResolution {

        private final String activityLogCode = """
                package com.scc.smart_campus.model;
                import jakarta.persistence.Entity;
                import jakarta.persistence.Id;
                @Entity
                public class ActivityLog { @Id private Long id; }
                """;

        private final String eventEntityCode = """
                package com.scc.smart_campus.model;
                import jakarta.persistence.Entity;
                import jakarta.persistence.Id;
                @Entity
                public class Event { @Id private Long id; }
                """;

        private final String internshipEntityCode = """
                package com.scc.smart_campus.model;
                import jakarta.persistence.Entity;
                import jakarta.persistence.Id;
                @Entity
                public class Internship { @Id private Long id; }
                """;

        private final String partnerEntityCode = """
                package com.scc.smart_campus.model;
                import jakarta.persistence.Entity;
                import jakarta.persistence.Id;
                @Entity
                public class Partner { @Id private Long id; }
                """;

        private final String watchlistEntityCode = """
                package com.scc.smart_campus.model;
                import jakarta.persistence.Entity;
                import jakarta.persistence.Id;
                @Entity
                public class Watchlist { @Id private Long id; }
                """;

        private final String skillAuditEntityCode = """
                package com.scc.smart_campus.model;
                import jakarta.persistence.Entity;
                import jakarta.persistence.Id;
                @Entity
                public class SkillAudit { @Id private Long id; }
                """;

        @Test
        @DisplayName("Verify Event resolves correctly when ActivityLog precedes it in allSources")
        void testScc_EventResolved() {
            String controllerCode = """
                    package com.scc.smart_campus.controller;
                    import com.scc.smart_campus.model.Event;
                    import org.springframework.http.ResponseEntity;
                    import org.springframework.web.bind.annotation.*;
                    import java.util.List;
                    @RestController
                    @RequestMapping("/api/events")
                    public class EventController {
                        @GetMapping public ResponseEntity<List<Event>> getAllEvents() { return null; }
                    }
                    """;
            InspectedSource act = inspectionService.inspectSourceCode(activityLogCode, "ActivityLog.java");
            InspectedSource ent = inspectionService.inspectSourceCode(eventEntityCode, "Event.java");
            InspectedSource ctrl = inspectionService.inspectSourceCode(controllerCode, "EventController.java");

            assertTrue(architectureEngine.isEntityType("Event", ctrl, List.of(act, ent, ctrl)));
        }

        @Test
        @DisplayName("Verify Internship resolves correctly when ActivityLog precedes it in allSources")
        void testScc_InternshipResolved() {
            String controllerCode = """
                    package com.scc.smart_campus.controller;
                    import com.scc.smart_campus.model.Internship;
                    import org.springframework.http.ResponseEntity;
                    import org.springframework.web.bind.annotation.*;
                    import java.util.List;
                    @RestController
                    @RequestMapping("/api/internships")
                    public class InternshipController {
                        @GetMapping public ResponseEntity<List<Internship>> getAllInternships() { return null; }
                    }
                    """;
            InspectedSource act = inspectionService.inspectSourceCode(activityLogCode, "ActivityLog.java");
            InspectedSource ent = inspectionService.inspectSourceCode(internshipEntityCode, "Internship.java");
            InspectedSource ctrl = inspectionService.inspectSourceCode(controllerCode, "InternshipController.java");

            assertTrue(architectureEngine.isEntityType("Internship", ctrl, List.of(act, ent, ctrl)));
        }

        @Test
        @DisplayName("Verify Partner resolves correctly when ActivityLog precedes it in allSources")
        void testScc_PartnerResolved() {
            String controllerCode = """
                    package com.scc.smart_campus.controller;
                    import com.scc.smart_campus.model.Partner;
                    import org.springframework.http.ResponseEntity;
                    import org.springframework.web.bind.annotation.*;
                    import java.util.List;
                    @RestController
                    @RequestMapping("/api/partners")
                    public class PartnerController {
                        @GetMapping public ResponseEntity<List<Partner>> getPendingPartners() { return null; }
                    }
                    """;
            InspectedSource act = inspectionService.inspectSourceCode(activityLogCode, "ActivityLog.java");
            InspectedSource ent = inspectionService.inspectSourceCode(partnerEntityCode, "Partner.java");
            InspectedSource ctrl = inspectionService.inspectSourceCode(controllerCode, "PartnerController.java");

            assertTrue(architectureEngine.isEntityType("Partner", ctrl, List.of(act, ent, ctrl)));
        }

        @Test
        @DisplayName("Verify Watchlist resolves correctly when ActivityLog precedes it in allSources")
        void testScc_WatchlistResolved() {
            String controllerCode = """
                    package com.scc.smart_campus.controller;
                    import com.scc.smart_campus.model.Watchlist;
                    import org.springframework.http.ResponseEntity;
                    import org.springframework.web.bind.annotation.*;
                    @RestController
                    @RequestMapping("/api/partners")
                    public class PartnerController {
                        @PostMapping("/watchlist") public ResponseEntity<?> addToWatchlist(@RequestBody Watchlist entry) { return null; }
                    }
                    """;
            InspectedSource act = inspectionService.inspectSourceCode(activityLogCode, "ActivityLog.java");
            InspectedSource ent = inspectionService.inspectSourceCode(watchlistEntityCode, "Watchlist.java");
            InspectedSource ctrl = inspectionService.inspectSourceCode(controllerCode, "PartnerController.java");

            assertTrue(architectureEngine.isEntityType("Watchlist", ctrl, List.of(act, ent, ctrl)));
        }

        @Test
        @DisplayName("Verify SkillAudit resolves correctly when ActivityLog precedes it in allSources")
        void testScc_SkillAuditResolved() {
            String controllerCode = """
                    package com.scc.smart_campus.controller;
                    import com.scc.smart_campus.model.SkillAudit;
                    import org.springframework.web.bind.annotation.*;
                    import java.util.List;
                    @RestController
                    @RequestMapping("/api/admin")
                    public class AdminAuditController {
                        @GetMapping("/audits") public List<SkillAudit> getPendingAudits() { return null; }
                    }
                    """;
            InspectedSource act = inspectionService.inspectSourceCode(activityLogCode, "ActivityLog.java");
            InspectedSource ent = inspectionService.inspectSourceCode(skillAuditEntityCode, "SkillAudit.java");
            InspectedSource ctrl = inspectionService.inspectSourceCode(controllerCode, "AdminAuditController.java");

            assertTrue(architectureEngine.isEntityType("SkillAudit", ctrl, List.of(act, ent, ctrl)));
        }
    }

    // =========================================================================
    // PART 3: SEC-006 BEHAVIOR PRESERVED (STRICTLY UNTOUCHED)
    // =========================================================================
    @Nested
    @DisplayName("Part 3: SEC-006 False Positive Reproduction & Controls (Preserved)")
    class Sec006FalsePositiveReproduction {

        @Test
        @DisplayName("Case A (FP): Long @PathVariable id used in filename reproduces false positive SEC-006")
        void testCaseA_LongPathVariable_ReproducesFalsePositive() {
            String code = """
                    package com.scc.smart_campus.controller;
                    import org.springframework.core.io.Resource;
                    import org.springframework.core.io.FileSystemResource;
                    import org.springframework.http.ResponseEntity;
                    import org.springframework.web.bind.annotation.GetMapping;
                    import org.springframework.web.bind.annotation.PathVariable;
                    import org.springframework.web.bind.annotation.RestController;
                    import java.nio.file.Path;
                    import java.nio.file.Paths;

                    @RestController
                    public class StudentController {
                        private final String uploadDirectory = "uploads/images/";

                        @GetMapping("/{id}/image")
                        public ResponseEntity<Resource> getStudentImage(@PathVariable Long id) {
                            String fileName = "profile_" + id + ".png";
                            Path path = Paths.get(uploadDirectory + fileName);
                            return ResponseEntity.ok(new FileSystemResource(path.toFile()));
                        }
                    }
                    """;

            InspectedSource source = inspectionService.inspectSourceCode(code, "StudentController.java");
            List<SecurityFinding> findings = client.reasoning().evaluatePathTraversal(source);

            assertFalse(findings.isEmpty(), "Case A current behavior: SEC-006 false positive is preserved");
            assertEquals(SecurityRule.PATH_TRAVERSAL, findings.get(0).getRule());
        }

        @Test
        @DisplayName("Case B (FP): Constant path concatenation reproduces false positive SEC-006")
        void testCaseB_ConstantPathConcatenation_ReproducesFalsePositive() {
            String code = """
                    package com.scc.smart_campus.exception;
                    import org.springframework.http.ResponseEntity;
                    import org.springframework.web.bind.annotation.ExceptionHandler;
                    import org.springframework.web.bind.annotation.RestControllerAdvice;
                    import java.nio.file.Path;
                    import java.nio.file.Paths;

                    @RestControllerAdvice
                    public class GlobalExceptionHandler {
                        private static final String UPLOAD_DIR = "static/signatures/";

                        @ExceptionHandler(Exception.class)
                        public ResponseEntity<String> handleException() {
                            String uploadDir = UPLOAD_DIR;
                            Path path = Paths.get(uploadDir + "signature.png");
                            return ResponseEntity.ok(path.toString());
                        }
                    }
                    """;

            InspectedSource source = inspectionService.inspectSourceCode(code, "GlobalExceptionHandler.java");
            List<SecurityFinding> findings = client.reasoning().evaluatePathTraversal(source);

            assertFalse(findings.isEmpty(), "Case B current behavior: SEC-006 false positive is preserved");
            assertEquals(SecurityRule.PATH_TRAVERSAL, findings.get(0).getRule());
        }

        @Test
        @DisplayName("Case C (Control / TP): @PathVariable String filename is correctly detected as SEC-006")
        void testCaseC_StringPathVariable_DetectedAsTruePositive() {
            String code = """
                    package com.example.controller;
                    import org.springframework.web.bind.annotation.GetMapping;
                    import org.springframework.web.bind.annotation.PathVariable;
                    import org.springframework.web.bind.annotation.RestController;
                    import java.nio.file.Path;
                    import java.nio.file.Paths;

                    @RestController
                    public class FileController {
                        private String baseDir = "/var/data/";

                        @GetMapping("/download/{filename}")
                        public String download(@PathVariable String filename) {
                            Path path = Paths.get(baseDir + filename);
                            return path.toString();
                        }
                    }
                    """;

            InspectedSource source = inspectionService.inspectSourceCode(code, "FileController.java");
            List<SecurityFinding> findings = client.reasoning().evaluatePathTraversal(source);

            assertFalse(findings.isEmpty(), "Case C: @PathVariable String is a genuine vulnerability and must be detected");
            assertEquals(SecurityRule.PATH_TRAVERSAL, findings.get(0).getRule());
        }

        @Test
        @DisplayName("Case D (Control / TP): @RequestParam String filename is correctly detected as SEC-006")
        void testCaseD_StringRequestParam_DetectedAsTruePositive() {
            String code = """
                    package com.example.controller;
                    import org.springframework.web.bind.annotation.GetMapping;
                    import org.springframework.web.bind.annotation.RequestParam;
                    import org.springframework.web.bind.annotation.RestController;
                    import java.nio.file.Path;
                    import java.nio.file.Paths;

                    @RestController
                    public class FileController {
                        private String baseDir = "/var/data/";

                        @GetMapping("/download")
                        public String download(@RequestParam String filename) {
                            Path path = Paths.get(baseDir + filename);
                            return path.toString();
                        }
                    }
                    """;

            InspectedSource source = inspectionService.inspectSourceCode(code, "FileController.java");
            List<SecurityFinding> findings = client.reasoning().evaluatePathTraversal(source);

            assertFalse(findings.isEmpty(), "Case D: @RequestParam String is a genuine vulnerability and must be detected");
            assertEquals(SecurityRule.PATH_TRAVERSAL, findings.get(0).getRule());
        }

        @Test
        @DisplayName("Case E (Control / TN): Hardcoded string literal produces NO SEC-006 finding")
        void testCaseE_HardcodedConstant_ProducesNoFinding() {
            String code = """
                    package com.example.controller;
                    import org.springframework.web.bind.annotation.GetMapping;
                    import org.springframework.web.bind.annotation.RestController;
                    import java.nio.file.Path;
                    import java.nio.file.Paths;

                    @RestController
                    public class StaticFileController {
                        @GetMapping("/signature")
                        public String getSignature() {
                            Path path = Paths.get("static/images/signature.png");
                            return path.toString();
                        }
                    }
                    """;

            InspectedSource source = inspectionService.inspectSourceCode(code, "StaticFileController.java");
            List<SecurityFinding> findings = client.reasoning().evaluatePathTraversal(source);

            assertTrue(findings.isEmpty(), "Case E: Pure string literal in Paths.get must produce 0 findings (True Negative)");
        }

        @Test
        @DisplayName("Case F (Analysis): Numeric Long id transformed into filename semantics")
        void testCaseF_NumericInputTransformedIntoFilename() {
            String code = """
                    package com.example.controller;
                    import org.springframework.web.bind.annotation.GetMapping;
                    import org.springframework.web.bind.annotation.PathVariable;
                    import org.springframework.web.bind.annotation.RestController;
                    import java.nio.file.Paths;

                    @RestController
                    public class NumericFileController {
                        @GetMapping("/item/{id}")
                        public void getItem(@PathVariable Long id) {
                            String name = "profile_" + id + ".png";
                            Paths.get("/tmp/" + name);
                        }
                    }
                    """;
            InspectedSource source = inspectionService.inspectSourceCode(code, "NumericFileController.java");
            List<SecurityFinding> findings = client.reasoning().evaluatePathTraversal(source);
            assertFalse(findings.isEmpty(), "Case F: Demonstrates current lack of numeric type sanitization in dataflow tracking");
        }
    }

    // =========================================================================
    // PART 4: 12 REQUIRED REGRESSION CASES (PHASE 4A.8)
    // =========================================================================
    @Nested
    @DisplayName("Part 4: Phase 4A.8 Required Regression Suite (12 Cases)")
    class Arch002Phase4A8RequiredRegressionCases {

        private final String activityLogCode = """
                package com.scc.smart_campus.model;
                import jakarta.persistence.Entity;
                import jakarta.persistence.Id;
                @Entity
                public class ActivityLog { @Id private Long id; }
                """;

        // Case 1: ActivityLog before Event
        @Test
        @DisplayName("Case 1: ActivityLog before Event -> Event resolves correctly")
        void testCase1_ActivityLogBeforeEvent() {
            String eventCode = """
                    package com.scc.smart_campus.model;
                    import jakarta.persistence.Entity;
                    import jakarta.persistence.Id;
                    @Entity
                    public class Event { @Id private Long id; }
                    """;
            String controllerCode = """
                    package com.scc.smart_campus.controller;
                    import com.scc.smart_campus.model.Event;
                    import org.springframework.http.ResponseEntity;
                    import org.springframework.web.bind.annotation.*;
                    @RestController
                    public class EventController {
                        @GetMapping("/events")
                        public ResponseEntity<Event> get() { return null; }
                    }
                    """;
            InspectedSource act = inspectionService.inspectSourceCode(activityLogCode, "ActivityLog.java");
            InspectedSource ent = inspectionService.inspectSourceCode(eventCode, "Event.java");
            InspectedSource ctrl = inspectionService.inspectSourceCode(controllerCode, "EventController.java");

            assertTrue(architectureEngine.isEntityType("Event", ctrl, List.of(act, ent, ctrl)));
        }

        // Case 2: ActivityLog before Internship
        @Test
        @DisplayName("Case 2: ActivityLog before Internship -> Internship resolves correctly")
        void testCase2_ActivityLogBeforeInternship() {
            String internshipCode = """
                    package com.scc.smart_campus.model;
                    import jakarta.persistence.Entity;
                    import jakarta.persistence.Id;
                    @Entity
                    public class Internship { @Id private Long id; }
                    """;
            String controllerCode = """
                    package com.scc.smart_campus.controller;
                    import com.scc.smart_campus.model.Internship;
                    import org.springframework.http.ResponseEntity;
                    import org.springframework.web.bind.annotation.*;
                    @RestController
                    public class InternshipController {
                        @GetMapping("/internships")
                        public ResponseEntity<Internship> get() { return null; }
                    }
                    """;
            InspectedSource act = inspectionService.inspectSourceCode(activityLogCode, "ActivityLog.java");
            InspectedSource ent = inspectionService.inspectSourceCode(internshipCode, "Internship.java");
            InspectedSource ctrl = inspectionService.inspectSourceCode(controllerCode, "InternshipController.java");

            assertTrue(architectureEngine.isEntityType("Internship", ctrl, List.of(act, ent, ctrl)));
        }

        // Case 3: ActivityLog before Partner
        @Test
        @DisplayName("Case 3: ActivityLog before Partner -> Partner resolves correctly")
        void testCase3_ActivityLogBeforePartner() {
            String partnerCode = """
                    package com.scc.smart_campus.model;
                    import jakarta.persistence.Entity;
                    import jakarta.persistence.Id;
                    @Entity
                    public class Partner { @Id private Long id; }
                    """;
            String controllerCode = """
                    package com.scc.smart_campus.controller;
                    import com.scc.smart_campus.model.Partner;
                    import org.springframework.http.ResponseEntity;
                    import org.springframework.web.bind.annotation.*;
                    @RestController
                    public class PartnerController {
                        @GetMapping("/partners")
                        public ResponseEntity<Partner> get() { return null; }
                    }
                    """;
            InspectedSource act = inspectionService.inspectSourceCode(activityLogCode, "ActivityLog.java");
            InspectedSource ent = inspectionService.inspectSourceCode(partnerCode, "Partner.java");
            InspectedSource ctrl = inspectionService.inspectSourceCode(controllerCode, "PartnerController.java");

            assertTrue(architectureEngine.isEntityType("Partner", ctrl, List.of(act, ent, ctrl)));
        }

        // Case 4: ActivityLog before Watchlist
        @Test
        @DisplayName("Case 4: ActivityLog before Watchlist -> Watchlist resolves correctly")
        void testCase4_ActivityLogBeforeWatchlist() {
            String watchlistCode = """
                    package com.scc.smart_campus.model;
                    import jakarta.persistence.Entity;
                    import jakarta.persistence.Id;
                    @Entity
                    public class Watchlist { @Id private Long id; }
                    """;
            String controllerCode = """
                    package com.scc.smart_campus.controller;
                    import com.scc.smart_campus.model.Watchlist;
                    import org.springframework.http.ResponseEntity;
                    import org.springframework.web.bind.annotation.*;
                    @RestController
                    public class WatchlistController {
                        @PostMapping("/watchlist")
                        public ResponseEntity<?> add(@RequestBody Watchlist w) { return null; }
                    }
                    """;
            InspectedSource act = inspectionService.inspectSourceCode(activityLogCode, "ActivityLog.java");
            InspectedSource ent = inspectionService.inspectSourceCode(watchlistCode, "Watchlist.java");
            InspectedSource ctrl = inspectionService.inspectSourceCode(controllerCode, "WatchlistController.java");

            assertTrue(architectureEngine.isEntityType("Watchlist", ctrl, List.of(act, ent, ctrl)));
        }

        // Case 5: ActivityLog before SkillAudit
        @Test
        @DisplayName("Case 5: ActivityLog before SkillAudit -> SkillAudit resolves correctly")
        void testCase5_ActivityLogBeforeSkillAudit() {
            String skillAuditCode = """
                    package com.scc.smart_campus.model;
                    import jakarta.persistence.Entity;
                    import jakarta.persistence.Id;
                    @Entity
                    public class SkillAudit { @Id private Long id; }
                    """;
            String controllerCode = """
                    package com.scc.smart_campus.controller;
                    import com.scc.smart_campus.model.SkillAudit;
                    import org.springframework.web.bind.annotation.*;
                    import java.util.List;
                    @RestController
                    public class AdminController {
                        @GetMapping("/audits")
                        public List<SkillAudit> get() { return null; }
                    }
                    """;
            InspectedSource act = inspectionService.inspectSourceCode(activityLogCode, "ActivityLog.java");
            InspectedSource ent = inspectionService.inspectSourceCode(skillAuditCode, "SkillAudit.java");
            InspectedSource ctrl = inspectionService.inspectSourceCode(controllerCode, "AdminController.java");

            assertTrue(architectureEngine.isEntityType("SkillAudit", ctrl, List.of(act, ent, ctrl)));
        }

        // Case 6: Explicit Student import with sibling entities
        @Test
        @DisplayName("Case 6: Explicit Student import with sibling entities -> Student resolves correctly")
        void testCase6_ExplicitStudentImportWithSiblings() {
            String studentCode = """
                    package com.scc.smart_campus.model;
                    import jakarta.persistence.Entity;
                    import jakarta.persistence.Id;
                    @Entity
                    public class Student { @Id private Long id; }
                    """;
            String eventCode = """
                    package com.scc.smart_campus.model;
                    import jakarta.persistence.Entity;
                    import jakarta.persistence.Id;
                    @Entity
                    public class Event { @Id private Long id; }
                    """;
            String controllerCode = """
                    package com.scc.smart_campus.controller;
                    import com.scc.smart_campus.model.Student;
                    import org.springframework.http.ResponseEntity;
                    import org.springframework.web.bind.annotation.*;
                    @RestController
                    public class StudentPortalController {
                        @GetMapping("/student")
                        public ResponseEntity<Student> get() { return null; }
                    }
                    """;
            InspectedSource act = inspectionService.inspectSourceCode(activityLogCode, "ActivityLog.java");
            InspectedSource evt = inspectionService.inspectSourceCode(eventCode, "Event.java");
            InspectedSource stu = inspectionService.inspectSourceCode(studentCode, "Student.java");
            InspectedSource ctrl = inspectionService.inspectSourceCode(controllerCode, "StudentPortalController.java");

            // ActivityLog and Event precede Student in allSources
            assertTrue(architectureEngine.isEntityType("Student", ctrl, List.of(act, evt, stu, ctrl)));
        }

        // Case 7: Wildcard import
        @Test
        @DisplayName("Case 7: Wildcard import preserves correct entity detection")
        void testCase7_WildcardImport() {
            String studentCode = """
                    package com.scc.smart_campus.model;
                    import jakarta.persistence.Entity;
                    import jakarta.persistence.Id;
                    @Entity
                    public class Student { @Id private Long id; }
                    """;
            String controllerCode = """
                    package com.scc.smart_campus.controller;
                    import com.scc.smart_campus.model.*;
                    import org.springframework.http.ResponseEntity;
                    import org.springframework.web.bind.annotation.*;
                    @RestController
                    public class WildcardStudentController {
                        @GetMapping("/student")
                        public ResponseEntity<Student> get() { return null; }
                    }
                    """;
            InspectedSource act = inspectionService.inspectSourceCode(activityLogCode, "ActivityLog.java");
            InspectedSource stu = inspectionService.inspectSourceCode(studentCode, "Student.java");
            InspectedSource ctrl = inspectionService.inspectSourceCode(controllerCode, "WildcardStudentController.java");

            assertTrue(architectureEngine.isEntityType("Student", ctrl, List.of(act, stu, ctrl)));
        }

        // Case 8: DTO with same simple name
        @Test
        @DisplayName("Case 8: DTO with same simple name must NOT trigger ARCH-002")
        void testCase8_DtoWithSameSimpleName() {
            String dtoCode = """
                    package com.scc.smart_campus.dto;
                    public class Event { private Long id; }
                    """;
            String controllerCode = """
                    package com.scc.smart_campus.controller;
                    import com.scc.smart_campus.dto.Event;
                    import org.springframework.http.ResponseEntity;
                    import org.springframework.web.bind.annotation.*;
                    @RestController
                    public class EventDtoController {
                        @GetMapping("/events")
                        public ResponseEntity<Event> get() { return null; }
                    }
                    """;
            InspectedSource dto = inspectionService.inspectSourceCode(dtoCode, "EventDto.java");
            InspectedSource ctrl = inspectionService.inspectSourceCode(controllerCode, "EventDtoController.java");

            assertFalse(architectureEngine.isEntityType("Event", ctrl, List.of(dto, ctrl)));
        }

        // Case 9: Same simple name in different packages
        @Test
        @DisplayName("Case 9: Same simple name in different packages -> Explicit import selects correct source")
        void testCase9_SameSimpleNameDifferentPackages() {
            String entityPkgCode = """
                    package com.app.entity;
                    import jakarta.persistence.Entity;
                    @Entity
                    public class Order { private Long id; }
                    """;
            String dtoPkgCode = """
                    package com.app.dto;
                    public class Order { private Long id; }
                    """;
            InspectedSource entitySource = inspectionService.inspectSourceCode(entityPkgCode, "OrderEntity.java");
            InspectedSource dtoSource = inspectionService.inspectSourceCode(dtoPkgCode, "OrderDto.java");

            // Controller 1: imports DTO
            String ctrlDtoCode = """
                    package com.app.controller;
                    import com.app.dto.Order;
                    import org.springframework.web.bind.annotation.GetMapping;
                    import org.springframework.web.bind.annotation.RestController;
                    @RestController
                    public class DtoOrderController {
                        @GetMapping("/order") public Order get() { return null; }
                    }
                    """;
            InspectedSource ctrlDto = inspectionService.inspectSourceCode(ctrlDtoCode, "DtoOrderController.java");

            // Controller 2: imports Entity
            String ctrlEntityCode = """
                    package com.app.controller;
                    import com.app.entity.Order;
                    import org.springframework.web.bind.annotation.GetMapping;
                    import org.springframework.web.bind.annotation.RestController;
                    @RestController
                    public class EntityOrderController {
                        @GetMapping("/order") public Order get() { return null; }
                    }
                    """;
            InspectedSource ctrlEntity = inspectionService.inspectSourceCode(ctrlEntityCode, "EntityOrderController.java");

            List<InspectedSource> allSources = List.of(entitySource, dtoSource, ctrlDto, ctrlEntity);

            assertFalse(architectureEngine.isEntityType("Order", ctrlDto, allSources), "DTO import must NOT be entity");
            assertTrue(architectureEngine.isEntityType("Order", ctrlEntity, allSources), "Entity import MUST be entity");
        }

        // Case 10: Fully-qualified type in method signature
        @Test
        @DisplayName("Case 10: Fully-qualified type in method signature resolves correctly")
        void testCase10_FullyQualifiedTypeInSignature() {
            String studentCode = """
                    package com.scc.smart_campus.model;
                    import jakarta.persistence.Entity;
                    import jakarta.persistence.Id;
                    @Entity
                    public class Student { @Id private Long id; }
                    """;
            String controllerCode = """
                    package com.scc.smart_campus.controller;
                    import org.springframework.http.ResponseEntity;
                    import org.springframework.web.bind.annotation.*;
                    import java.util.List;
                    @RestController
                    public class SignatureController {
                        @GetMapping("/applicants")
                        public ResponseEntity<List<com.scc.smart_campus.model.Student>> getApplicants() { return null; }
                    }
                    """;
            InspectedSource act = inspectionService.inspectSourceCode(activityLogCode, "ActivityLog.java");
            InspectedSource stu = inspectionService.inspectSourceCode(studentCode, "Student.java");
            InspectedSource ctrl = inspectionService.inspectSourceCode(controllerCode, "SignatureController.java");

            assertTrue(architectureEngine.isEntityType("com.scc.smart_campus.model.Student", ctrl, List.of(act, stu, ctrl)));
        }

        // Case 11: Generic wrappers
        @Test
        @DisplayName("Case 11: Generic wrappers (List, ResponseEntity, Optional, Set) unwrapped correctly")
        void testCase11_GenericWrappersUnwrapped() {
            String itemCode = """
                    package com.app.model;
                    import jakarta.persistence.Entity;
                    import jakarta.persistence.Id;
                    @Entity
                    public class Item { @Id private Long id; }
                    """;
            String controllerCode = """
                    package com.app.controller;
                    import com.app.model.Item;
                    import org.springframework.http.ResponseEntity;
                    import org.springframework.web.bind.annotation.*;
                    import java.util.List;
                    import java.util.Optional;
                    import java.util.Set;
                    @RestController
                    public class GenericController {
                        @GetMapping("/1") public List<Item> get1() { return null; }
                        @GetMapping("/2") public ResponseEntity<Item> get2() { return null; }
                        @GetMapping("/3") public Optional<Item> get3() { return null; }
                        @GetMapping("/4") public Set<Item> get4() { return null; }
                        @GetMapping("/5") public ResponseEntity<List<Item>> get5() { return null; }
                    }
                    """;
            InspectedSource item = inspectionService.inspectSourceCode(itemCode, "Item.java");
            InspectedSource ctrl = inspectionService.inspectSourceCode(controllerCode, "GenericController.java");
            List<InspectedSource> allSources = List.of(item, ctrl);

            assertTrue(architectureEngine.isEntityType("List<Item>", ctrl, allSources));
            assertTrue(architectureEngine.isEntityType("ResponseEntity<Item>", ctrl, allSources));
            assertTrue(architectureEngine.isEntityType("Optional<Item>", ctrl, allSources));
            assertTrue(architectureEngine.isEntityType("Set<Item>", ctrl, allSources));
            assertTrue(architectureEngine.isEntityType("ResponseEntity<List<Item>>", ctrl, allSources));
        }

        // Case 12: Existing *Entity naming fallback
        @Test
        @DisplayName("Case 12: Existing *Entity naming fallback remains working")
        void testCase12_EntitySuffixFallback() {
            String controllerCode = """
                    package com.app.controller;
                    import org.springframework.web.bind.annotation.GetMapping;
                    import org.springframework.web.bind.annotation.RestController;
                    @RestController
                    public class StandaloneController {
                        @GetMapping("/user")
                        public UserEntity getUser() { return null; }
                    }
                    """;
            InspectedSource ctrl = inspectionService.inspectSourceCode(controllerCode, "StandaloneController.java");

            // Even when UserEntity source is not in allSources, *Entity suffix triggers entity detection
            assertTrue(architectureEngine.isEntityType("UserEntity", ctrl, List.of(ctrl)));
        }
    }

    // =========================================================================
    // PART 5: LIVE VERIFICATION AGAINST PINNED SMART CAMPUS CONNECT
    // =========================================================================
    @Nested
    @DisplayName("Part 5: Live Verification against Pinned Smart Campus Connect")
    class LiveSccVerification {

        @Test
        @DisplayName("Live audit against pinned SCC commit: verifies exactly 22 ARCH-002 findings detected")
        void testLiveSccAudit() {
            Path sccPath = Path.of("C:/Users/darsh/.gemini/antigravity/brain/51831e20-2d30-495b-ae03-c4228f903e74/scratch/smart-campus-connect");
            if (!Files.exists(sccPath)) {
                return;
            }
            SentinelCliRunner runner = new SentinelCliRunner();
            ReviewReport report = runner.run(sccPath);
            assertNotNull(report);
            List<SecurityFinding> findings = report.getFindings();
            List<SecurityFinding> arch002 = findings.stream()
                    .filter(f -> f.getRule() == SecurityRule.ARCH_LEAKY_ABSTRACTION)
                    .toList();
            List<SecurityFinding> sec006 = findings.stream()
                    .filter(f -> f.getRule() == SecurityRule.PATH_TRAVERSAL)
                    .toList();
            List<SecurityFinding> arch003 = findings.stream()
                    .filter(f -> f.getRule() == SecurityRule.ARCH_NON_DETERMINISTIC_CALL)
                    .toList();

            System.out.println("=== LIVE SCC AUDIT RESULTS ===");
            System.out.println("Total findings: " + findings.size());
            System.out.println("ARCH-002 findings: " + arch002.size());
            System.out.println("SEC-006 findings: " + sec006.size());
            System.out.println("ARCH-003 findings: " + arch003.size());
            for (SecurityFinding f : arch002) {
                System.out.println("ARCH-002: " + f.getTargetFile() + " line " + f.getStartLine() + " " + f.getMethodName() + " -> " + f.getDescription());
            }

            assertEquals(22, arch002.size(), "All 22 vulnerable endpoint instances must be detected by ARCH-002");
            assertEquals(4, sec006.size(), "SEC-006 findings must remain unchanged at 4");
            assertEquals(1, arch003.size(), "ARCH-003 findings must remain unchanged at 1");
        }
    }
}
