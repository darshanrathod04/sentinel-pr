package com.sentinelpr.reproduction;

import com.github.javaparser.ast.body.MethodDeclaration;
import com.sentinelpr.client.ReasoningFacade;
import com.sentinelpr.client.SentinelClient;
import com.sentinelpr.core.analysis.DataflowTracker;
import com.sentinelpr.core.analysis.taint.TaintFlow;
import com.sentinelpr.core.analysis.taint.TaintSink;
import com.sentinelpr.core.analysis.taint.TaintSource;
import com.sentinelpr.core.model.InspectedSource;
import com.sentinelpr.core.model.SecurityFinding;
import com.sentinelpr.core.model.SecurityRule;
import com.sentinelpr.core.service.CodeInspectionService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * <b>Phase4A9Sec006PrecisionInvestigationTest</b>
 *
 * <p>Phase 4A.9 / Phase 4A.10 Focused Regression and Precision Hardening Suite for SEC-006 Path Traversal:</p>
 * <ul>
 *   <li><b>FP-1 (Phase 4A.10):</b> Proves that {@link DataflowTracker} excludes safe scalar/numeric types
 *       ({@code Long}, {@code Integer}, {@code int}, {@code long}, {@code UUID}, etc.) from taint seeding,
 *       while preserving untrusted classification for {@code String}, collections, and DTO objects.</li>
 *   <li><b>FP-2 (Preserved):</b> Documents that constant concatenations without taint currently remain flagged
 *       by {@link ReasoningFacade} until Phase 4A.11.</li>
 *   <li><b>Controls:</b> Strictly verifies positive detection of vulnerable string paths and negative suppression for guarded paths.</li>
 * </ul>
 */
class Phase4A9Sec006PrecisionInvestigationTest {

    private SentinelClient client;
    private CodeInspectionService inspectionService;
    private DataflowTracker dataflowTracker;
    private ReasoningFacade reasoningFacade;

    @BeforeEach
    void setUp() {
        client = SentinelClient.bootstrap("local");
        inspectionService = new CodeInspectionService(client);
        reasoningFacade = client.reasoning();
        dataflowTracker = reasoningFacade.getDataflowTracker();
    }

    // =========================================================================
    // PART 1: PHASE 4A.10 REQUIRED REGRESSION TESTS (A - J)
    // =========================================================================
    @Nested
    @DisplayName("Part 1: FP-1 Numeric Parameter Taint Classification (Cases A - J)")
    class Fp1NumericParameterTaintClassification {

        // Case A: Long parameter does not create a SEC-006 taint source
        @Test
        @DisplayName("Case A: Long parameter does not create a SEC-006 taint source")
        void testCaseA_LongParameter_DoesNotCreateTaintSource() {
            String code = """
                    package com.example.controller;
                    import java.nio.file.Paths;
                    import org.springframework.web.bind.annotation.PathVariable;
                    public class TestController {
                        public void getFile(@PathVariable Long id) {
                            Paths.get("/tmp/" + id);
                        }
                    }
                    """;
            InspectedSource source = inspectionService.inspectSourceCode(code, "TestController.java");
            MethodDeclaration method = source.getMethods().get(0);
            List<TaintFlow> flows = dataflowTracker.analyzeMethod(method, "TestController.java", List.of(source));

            assertTrue(flows.isEmpty(), "Long parameter must NOT create a taint flow to sink");
        }

        // Case B: Integer parameter does not create a SEC-006 taint source
        @Test
        @DisplayName("Case B: Integer parameter does not create a SEC-006 taint source")
        void testCaseB_IntegerParameter_DoesNotCreateTaintSource() {
            String code = """
                    package com.example.controller;
                    import java.nio.file.Paths;
                    public class TestController {
                        public void getFile(Integer count) {
                            Paths.get("/tmp/" + count);
                        }
                    }
                    """;
            InspectedSource source = inspectionService.inspectSourceCode(code, "TestController.java");
            MethodDeclaration method = source.getMethods().get(0);
            List<TaintFlow> flows = dataflowTracker.analyzeMethod(method, "TestController.java", List.of(source));

            assertTrue(flows.isEmpty(), "Integer parameter must NOT create a taint flow to sink");
        }

        // Case C: int primitive does not create a SEC-006 taint source
        @Test
        @DisplayName("Case C: int primitive does not create a SEC-006 taint source")
        void testCaseC_IntPrimitive_DoesNotCreateTaintSource() {
            String code = """
                    package com.example.controller;
                    import java.nio.file.Paths;
                    public class TestController {
                        public void getFile(int fileId) {
                            Paths.get("/tmp/" + fileId);
                        }
                    }
                    """;
            InspectedSource source = inspectionService.inspectSourceCode(code, "TestController.java");
            MethodDeclaration method = source.getMethods().get(0);
            List<TaintFlow> flows = dataflowTracker.analyzeMethod(method, "TestController.java", List.of(source));

            assertTrue(flows.isEmpty(), "Primitive int parameter must NOT create a taint flow to sink");
        }

        // Case D: long primitive does not create a SEC-006 taint source
        @Test
        @DisplayName("Case D: long primitive does not create a SEC-006 taint source")
        void testCaseD_LongPrimitive_DoesNotCreateTaintSource() {
            String code = """
                    package com.example.controller;
                    import java.nio.file.Paths;
                    public class TestController {
                        public void getFile(long offset) {
                            Paths.get("/tmp/" + offset);
                        }
                    }
                    """;
            InspectedSource source = inspectionService.inspectSourceCode(code, "TestController.java");
            MethodDeclaration method = source.getMethods().get(0);
            List<TaintFlow> flows = dataflowTracker.analyzeMethod(method, "TestController.java", List.of(source));

            assertTrue(flows.isEmpty(), "Primitive long parameter must NOT create a taint flow to sink");
        }

        // Case E: String parameter STILL creates a SEC-006 taint source
        @Test
        @DisplayName("Case E: String parameter STILL creates a SEC-006 taint source")
        void testCaseE_StringParameter_StillCreatesTaintSource() {
            String code = """
                    package com.example.controller;
                    import java.nio.file.Paths;
                    public class TestController {
                        public void getFile(String filename) {
                            Paths.get("/tmp/" + filename);
                        }
                    }
                    """;
            InspectedSource source = inspectionService.inspectSourceCode(code, "TestController.java");
            MethodDeclaration method = source.getMethods().get(0);
            List<TaintFlow> flows = dataflowTracker.analyzeMethod(method, "TestController.java", List.of(source));

            assertFalse(flows.isEmpty(), "String parameter MUST create a taint flow");
            assertEquals("filename", flows.get(0).getSource().getName());
            assertEquals(TaintSource.SourceType.METHOD_PARAMETER, flows.get(0).getSource().getType());
            assertEquals(TaintSink.SinkType.FILE_IO, flows.get(0).getSink().getType());
        }

        // Case F: @PathVariable String filename remains detectable
        @Test
        @DisplayName("Case F: @PathVariable String filename remains detectable")
        void testCaseF_StringPathVariable_RemainsDetectable() {
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
            List<SecurityFinding> findings = reasoningFacade.evaluatePathTraversal(source);

            assertEquals(1, findings.size(), "@PathVariable String must be detected as PATH_TRAVERSAL");
            SecurityFinding finding = findings.get(0);
            assertEquals(SecurityRule.PATH_TRAVERSAL, finding.getRule());
            assertEquals(0.99, finding.getConfidence(), 0.001);
            assertTrue(finding.getCausalRationale().contains("Taint trace:"));
        }

        // Case G: Dynamic String concatenation remains detectable: String fileName = "profile_" + filename + ".png";
        @Test
        @DisplayName("Case G: Dynamic String concatenation remains detectable with multi-hop trace")
        void testCaseG_DynamicStringConcatenation_RemainsDetectable() {
            String code = """
                    package com.example.controller;
                    import org.springframework.web.bind.annotation.GetMapping;
                    import org.springframework.web.bind.annotation.PathVariable;
                    import org.springframework.web.bind.annotation.RestController;
                    import java.nio.file.Path;
                    import java.nio.file.Paths;

                    @RestController
                    public class ImageController {
                        private String uploadDir = "/var/uploads/";

                        @GetMapping("/user/{filename}")
                        public String getUserImage(@PathVariable String filename) {
                            String fileName = "profile_" + filename + ".png";
                            Path path = Paths.get(uploadDir + fileName);
                            return path.toString();
                        }
                    }
                    """;
            InspectedSource source = inspectionService.inspectSourceCode(code, "ImageController.java");
            MethodDeclaration method = source.getMethods().get(0);
            List<TaintFlow> flows = dataflowTracker.analyzeMethod(method, "ImageController.java", List.of(source));

            assertFalse(flows.isEmpty(), "Taint must propagate from filename -> fileName -> Paths.get");
            TaintFlow flow = flows.get(0);
            assertTrue(flow.getTraceSteps().contains("fileName"));

            List<SecurityFinding> findings = reasoningFacade.evaluatePathTraversal(source);
            assertEquals(1, findings.size());
            assertEquals(0.99, findings.get(0).getConfidence(), 0.001);
            assertTrue(findings.get(0).getCausalRationale().contains("Taint trace:"));
        }

        // Case H: Numeric parameter converted to String remains safe for traversal
        @Test
        @DisplayName("Case H: Numeric parameter converted to String produces NO taint flow")
        void testCaseH_NumericConvertedToString_ProducesNoTaintFlow() {
            String code = """
                    package com.scc.smart_campus.controller;
                    import org.springframework.web.bind.annotation.GetMapping;
                    import org.springframework.web.bind.annotation.PathVariable;
                    import org.springframework.web.bind.annotation.RestController;
                    import java.nio.file.Path;
                    import java.nio.file.Paths;

                    @RestController
                    public class StudentController {
                        private final String uploadDirectory = "uploads/images/";

                        @GetMapping("/{id}/image")
                        public String getStudentImage(@PathVariable Long id) {
                            String fileName = "profile_" + id + ".png";
                            Path path = Paths.get(uploadDirectory + fileName);
                            return path.toString();
                        }
                    }
                    """;
            InspectedSource source = inspectionService.inspectSourceCode(code, "StudentController.java");
            MethodDeclaration method = source.getMethods().get(0);
            List<TaintFlow> flows = dataflowTracker.analyzeMethod(method, "StudentController.java", List.of(source));

            // PROOF: In DataflowTracker, Long id is NOT tainted, so flows is empty!
            assertTrue(flows.isEmpty(), "DataflowTracker must NOT report any taint flow for numeric Long id");

            // PROOF: In ReasoningFacade, because matching flow is absent, confidence is NOT boosted to 0.99 with taint trace
            List<SecurityFinding> findings = reasoningFacade.evaluatePathTraversal(source);
            if (!findings.isEmpty()) {
                SecurityFinding finding = findings.get(0);
                assertFalse(finding.getCausalRationale().contains("Taint trace:"),
                        "Finding must NOT have a taint trace connecting numeric id to sink");
                assertNotEquals(0.99, finding.getConfidence(),
                        "Confidence must NOT be 0.99 when DataflowTracker found no taint");
            }
        }

        // Case I: Existing safe guards continue working
        @Test
        @DisplayName("Case I: Existing path guards (.normalize().startsWith()) continue suppressing findings")
        void testCaseI_ExistingPathGuards_ContinueWorking() {
            String code = """
                    package com.example.controller;
                    import org.springframework.web.bind.annotation.GetMapping;
                    import org.springframework.web.bind.annotation.PathVariable;
                    import org.springframework.web.bind.annotation.RestController;
                    import java.nio.file.Path;
                    import java.nio.file.Paths;

                    @RestController
                    public class GuardedController {
                        private final Path baseDir = Paths.get("/var/data").toAbsolutePath().normalize();

                        @GetMapping("/download/{filename}")
                        public String download(@PathVariable String filename) {
                            Path resolved = baseDir.resolve(filename).normalize();
                            if (!resolved.startsWith(baseDir)) {
                                throw new SecurityException("Traversal attempt");
                            }
                            return resolved.toString();
                        }
                    }
                    """;
            InspectedSource source = inspectionService.inspectSourceCode(code, "GuardedController.java");
            List<SecurityFinding> findings = reasoningFacade.evaluatePathTraversal(source);

            assertTrue(findings.isEmpty(), "Path containment check (.normalize().startsWith()) must suppress findings");
        }

        // Case J: Existing DTO/object behavior remains unchanged
        @Test
        @DisplayName("Case J: DTO and object parameters remain in active taint tracking")
        void testCaseJ_DtoAndObjectParameters_RemainTainted() {
            String code = """
                    package com.example.controller;
                    import java.nio.file.Paths;
                    public class DtoController {
                        public void process(CustomUserRequest request) {
                            Paths.get("/tmp/" + request);
                        }
                    }
                    """;
            InspectedSource source = inspectionService.inspectSourceCode(code, "DtoController.java");
            MethodDeclaration method = source.getMethods().get(0);
            List<TaintFlow> flows = dataflowTracker.analyzeMethod(method, "DtoController.java", List.of(source));

            assertFalse(flows.isEmpty(), "Custom DTO request parameter must NOT be excluded from taint tracking");
            assertEquals("request", flows.get(0).getSource().getName());
        }
    }

    // =========================================================================
    // PART 2: IMPORTANT NEGATIVE / POSITIVE CONTROLS
    // =========================================================================
    @Nested
    @DisplayName("Part 2: Negative and Positive Controls")
    class NegativeAndPositiveControls {

        @Test
        @DisplayName("Control 1: @RequestParam String filename concatenation remains detectable with 0.99 confidence")
        void testControl1_RequestParamString_RemainsDetectable() {
            String code = """
                    package com.example.controller;
                    import org.springframework.web.bind.annotation.GetMapping;
                    import org.springframework.web.bind.annotation.RequestParam;
                    import org.springframework.web.bind.annotation.RestController;
                    import java.nio.file.Path;
                    import java.nio.file.Paths;

                    @RestController
                    public class ReportController {
                        private String uploadDir = "/var/reports/";

                        @GetMapping("/view")
                        public String viewReport(@RequestParam String filename) {
                            Path p = Paths.get(uploadDir + filename);
                            return p.toString();
                        }
                    }
                    """;
            InspectedSource source = inspectionService.inspectSourceCode(code, "ReportController.java");
            MethodDeclaration method = source.getMethods().get(0);
            List<TaintFlow> flows = dataflowTracker.analyzeMethod(method, "ReportController.java", List.of(source));

            assertFalse(flows.isEmpty(), "@RequestParam String must produce taint flow in DataflowTracker");
            assertEquals("filename", flows.get(0).getSource().getName());

            List<SecurityFinding> findings = reasoningFacade.evaluatePathTraversal(source);
            assertEquals(1, findings.size(), "@RequestParam String must remain detectable by ReasoningFacade");
            assertEquals(0.99, findings.get(0).getConfidence(), 0.001);
            assertTrue(findings.get(0).getCausalRationale().contains("Taint trace:"));
        }

        @Test
        @DisplayName("Control 1b: Local variable path concatenation with String filename produces taint flow in DataflowTracker")
        void testControl1b_LocalVariablePath_ProducesTaintFlowInDataflowTracker() {
            String code = """
                    package com.example.controller;
                    import org.springframework.web.bind.annotation.GetMapping;
                    import org.springframework.web.bind.annotation.RequestParam;
                    import org.springframework.web.bind.annotation.RestController;
                    import java.nio.file.Path;
                    import java.nio.file.Paths;

                    @RestController
                    public class LocalVarController {
                        private String uploadDir = "/var/reports/";

                        @GetMapping("/view")
                        public String viewReport(@RequestParam String filename) {
                            String path = uploadDir + filename;
                            Path p = Paths.get(path);
                            return p.toString();
                        }
                    }
                    """;
            InspectedSource source = inspectionService.inspectSourceCode(code, "LocalVarController.java");
            MethodDeclaration method = source.getMethods().get(0);
            List<TaintFlow> flows = dataflowTracker.analyzeMethod(method, "LocalVarController.java", List.of(source));

            assertFalse(flows.isEmpty(), "DataflowTracker must trace taint from filename -> path -> Paths.get(path)");
            assertEquals("filename", flows.get(0).getSource().getName());
            assertTrue(flows.get(0).getTraceSteps().contains("path"));
        }

        @Test
        @DisplayName("Control 2: Long id concatenated to path remains non-tainted in DataflowTracker")
        void testControl2_LongIdConcatenatedToPath_RemainsNonTainted() {
            String code = """
                    package com.example.controller;
                    import org.springframework.web.bind.annotation.GetMapping;
                    import org.springframework.web.bind.annotation.PathVariable;
                    import org.springframework.web.bind.annotation.RestController;
                    import java.nio.file.Path;
                    import java.nio.file.Paths;

                    @RestController
                    public class SafeIdController {
                        private String uploadDir = "/var/reports/";

                        @GetMapping("/view/{id}")
                        public String viewById(@PathVariable Long id) {
                            String path = uploadDir + id;
                            Path p = Paths.get(path);
                            return p.toString();
                        }
                    }
                    """;
            InspectedSource source = inspectionService.inspectSourceCode(code, "SafeIdController.java");
            MethodDeclaration method = source.getMethods().get(0);
            List<TaintFlow> flows = dataflowTracker.analyzeMethod(method, "SafeIdController.java", List.of(source));

            assertTrue(flows.isEmpty(), "uploadDir + id with Long id must have ZERO taint flows in DataflowTracker");
        }

        @Test
        @DisplayName("Control 3: UUID parameter remains non-tainted in DataflowTracker")
        void testControl3_UuidParameter_RemainsNonTainted() {
            String code = """
                    package com.example.controller;
                    import java.util.UUID;
                    import java.nio.file.Paths;
                    public class UuidController {
                        public void getByUuid(UUID documentUuid) {
                            Paths.get("/var/docs/" + documentUuid);
                        }
                    }
                    """;
            InspectedSource source = inspectionService.inspectSourceCode(code, "UuidController.java");
            MethodDeclaration method = source.getMethods().get(0);
            List<TaintFlow> flows = dataflowTracker.analyzeMethod(method, "UuidController.java", List.of(source));

            assertTrue(flows.isEmpty(), "UUID parameter must NOT create taint flow to path sink");
        }
    }

    // =========================================================================
    // PART 3: FP-2 OBSERVATION (PRESERVED FOR PHASE 4A.11)
    // =========================================================================
    @Nested
    @DisplayName("Part 3: FP-2 Constant Path Expression Observation (Preserved)")
    class Fp2ConstantPathConcatenationObservation {

        private final String exceptionHandlerCode = """
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

        @Test
        @DisplayName("FP-2: DataflowTracker reports ZERO taint flows for constant expression")
        void testFp2_DataflowTrackerReturnsZeroTaintFlows() {
            InspectedSource source = inspectionService.inspectSourceCode(exceptionHandlerCode, "GlobalExceptionHandler.java");
            MethodDeclaration method = source.getMethods().stream()
                    .filter(m -> "handleException".equals(m.getNameAsString()))
                    .findFirst()
                    .orElseThrow();

            List<TaintFlow> flows = dataflowTracker.analyzeMethod(method, "GlobalExceptionHandler.java", List.of(source));
            assertTrue(flows.isEmpty(), "DataflowTracker reports ZERO taint flows for constant concatenation");
        }

        @Test
        @DisplayName("FP-2 Preserved: ReasoningFacade emits 0.95 confidence finding (FP-2 untouched in Phase 4A.10)")
        void testFp2_PreservedFindingInReasoningFacade() {
            InspectedSource source = inspectionService.inspectSourceCode(exceptionHandlerCode, "GlobalExceptionHandler.java");
            List<SecurityFinding> findings = reasoningFacade.evaluatePathTraversal(source);

            // In Phase 4A.10, ReasoningFacade is untouched; FP-2 finding remains preserved at 0.95 confidence
            assertEquals(1, findings.size(), "FP-2 finding is preserved until Phase 4A.11");
            assertEquals(0.95, findings.get(0).getConfidence(), 0.001);
            assertFalse(findings.get(0).getCausalRationale().contains("Taint trace:"));
        }
    }
}
