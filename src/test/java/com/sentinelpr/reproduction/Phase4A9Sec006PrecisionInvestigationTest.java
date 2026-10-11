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
    // PART 3: FP-2 OBSERVATION & RESOLUTION (PHASE 4A.11)
    // =========================================================================
    @Nested
    @DisplayName("Part 3: FP-2 Constant Path Expression Resolution (Phase 4A.11)")
    class Fp2ConstantPathConcatenationResolution {

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
        @DisplayName("FP-2 Resolved: ReasoningFacade suppresses finding for provably constant path concatenation")
        void testFp2_ResolvedFindingInReasoningFacade() {
            InspectedSource source = inspectionService.inspectSourceCode(exceptionHandlerCode, "GlobalExceptionHandler.java");
            List<SecurityFinding> findings = reasoningFacade.evaluatePathTraversal(source);

            // In Phase 4A.11, ReasoningFacade suppresses provably constant path expressions
            assertTrue(findings.isEmpty(), "FP-2 finding must be suppressed because path expression is provably constant");
        }
    }

    // =========================================================================
    // PART 4: PHASE 4A.11 PRECISION HARDENING & EXPRESSION GATING (CASES A - L)
    // =========================================================================
    @Nested
    @DisplayName("Part 4: Phase 4A.11 Precision Hardening & Expression Gating (Cases A - L)")
    class Phase4A11PrecisionHardeningCases {

        // Case A: Static string literal -> no SEC-006
        @Test
        @DisplayName("Case A: Static string literal Paths.get(\"static/signature.png\") produces NO findings")
        void testCaseA_StaticStringLiteral_ProducesNoFindings() {
            String code = """
                    package com.example.service;
                    import java.nio.file.Paths;
                    import java.nio.file.Path;
                    public class StaticLiteralService {
                        public Path getSignature() {
                            return Paths.get("static/signature.png");
                        }
                    }
                    """;
            InspectedSource source = inspectionService.inspectSourceCode(code, "StaticLiteralService.java");
            List<SecurityFinding> findings = reasoningFacade.evaluatePathTraversal(source);
            assertTrue(findings.isEmpty(), "Static string literal path must produce zero findings");
        }

        // Case B: Static final String + literal -> no SEC-006
        @Test
        @DisplayName("Case B: Static final String + literal BASE + \"signature.png\" produces NO findings")
        void testCaseB_StaticFinalStringPlusLiteral_ProducesNoFindings() {
            String code = """
                    package com.example.service;
                    import java.nio.file.Paths;
                    import java.nio.file.Path;
                    public class StaticFinalFieldService {
                        private static final String BASE = "static/";
                        public Path getSignature() {
                            return Paths.get(BASE + "signature.png");
                        }
                    }
                    """;
            InspectedSource source = inspectionService.inspectSourceCode(code, "StaticFinalFieldService.java");
            List<SecurityFinding> findings = reasoningFacade.evaluatePathTraversal(source);
            assertTrue(findings.isEmpty(), "Static final String concatenated with literal must produce zero findings");
        }

        // Case C: Local constant + literal -> no SEC-006
        @Test
        @DisplayName("Case C: Local constant String path = \"static/\" + \"signature.png\" produces NO findings")
        void testCaseC_LocalConstantPlusLiteral_ProducesNoFindings() {
            String code = """
                    package com.example.service;
                    import java.nio.file.Paths;
                    import java.nio.file.Path;
                    public class LocalConstantService {
                        public Path getSignature() {
                            String path = "static/" + "signature.png";
                            return Paths.get(path);
                        }
                    }
                    """;
            InspectedSource source = inspectionService.inspectSourceCode(code, "LocalConstantService.java");
            List<SecurityFinding> findings = reasoningFacade.evaluatePathTraversal(source);
            assertTrue(findings.isEmpty(), "Local constant concatenated string must produce zero findings");
        }

        // Case D: Nested constant concatenation -> no SEC-006
        @Test
        @DisplayName("Case D: Nested constant concatenation (\"static/\" + (\"signatures/\" + \"file.png\")) produces NO findings")
        void testCaseD_NestedConstantConcatenation_ProducesNoFindings() {
            String code = """
                    package com.example.service;
                    import java.nio.file.Paths;
                    import java.nio.file.Path;
                    public class NestedConcatService {
                        public Path getSignature() {
                            return Paths.get("static/" + ("signatures/" + "file.png"));
                        }
                    }
                    """;
            InspectedSource source = inspectionService.inspectSourceCode(code, "NestedConcatService.java");
            List<SecurityFinding> findings = reasoningFacade.evaluatePathTraversal(source);
            assertTrue(findings.isEmpty(), "Nested constant concatenation must produce zero findings");
        }

        // Case E: Long parameter -> safe scalar suppression
        @Test
        @DisplayName("Case E: Long parameter in fileName = \"profile_\" + id + \".png\" is suppressed as path-safe scalar")
        void testCaseE_LongParameter_SuppressedAsPathSafeScalar() {
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

            // Verify: DataflowTracker reports zero taint flows
            List<TaintFlow> flows = dataflowTracker.analyzeMethod(method, "StudentController.java", List.of(source));
            assertTrue(flows.isEmpty(), "DataflowTracker reports zero taint flows for Long id");

            // Verify: Expression is path-safe scalar and suppressed
            List<SecurityFinding> findings = reasoningFacade.evaluatePathTraversal(source);
            assertTrue(findings.isEmpty(), "Path-safe scalar expression must be suppressed in Phase 4A.11");
        }

        // Case F: String user input -> MUST remain SEC-006 (0.99 confidence with taint trace)
        @Test
        @DisplayName("Case F: String user input @PathVariable String filename MUST remain detected with 0.99 confidence")
        void testCaseF_StringUserInput_MustRemainDetected() {
            String code = """
                    package com.example.controller;
                    import org.springframework.web.bind.annotation.GetMapping;
                    import org.springframework.web.bind.annotation.PathVariable;
                    import org.springframework.web.bind.annotation.RestController;
                    import java.nio.file.Path;
                    import java.nio.file.Paths;

                    @RestController
                    public class VulnStringController {
                        private final String uploadDirectory = "/var/data/";

                        @GetMapping("/download/{filename}")
                        public String download(@PathVariable String filename) {
                            String path = uploadDirectory + filename;
                            Path p = Paths.get(path);
                            return p.toString();
                        }
                    }
                    """;
            InspectedSource source = inspectionService.inspectSourceCode(code, "VulnStringController.java");
            List<SecurityFinding> findings = reasoningFacade.evaluatePathTraversal(source);

            assertEquals(1, findings.size(), "String user input must remain detected as PATH_TRAVERSAL");
            SecurityFinding finding = findings.get(0);
            assertEquals(SecurityRule.PATH_TRAVERSAL, finding.getRule());
            assertEquals(0.99, finding.getConfidence(), 0.001);
            assertTrue(finding.getCausalRationale().contains("Taint trace:"), "Must include taint trace");
        }

        // Case G: String user input through local variable / helper -> MUST remain detected
        @Test
        @DisplayName("Case G: String user input through helper method MUST remain detected")
        void testCaseG_StringInputThroughHelper_MustRemainDetected() {
            String code = """
                    package com.example.controller;
                    import org.springframework.web.bind.annotation.GetMapping;
                    import org.springframework.web.bind.annotation.RequestParam;
                    import org.springframework.web.bind.annotation.RestController;
                    import java.nio.file.Path;
                    import java.nio.file.Paths;

                    @RestController
                    public class HelperPathController {
                        private String buildPath(String name) {
                            return "/var/uploads/" + name;
                        }

                        @GetMapping("/get")
                        public String getFile(@RequestParam String filename) {
                            String path = buildPath(filename);
                            Path p = Paths.get(path);
                            return p.toString();
                        }
                    }
                    """;
            InspectedSource source = inspectionService.inspectSourceCode(code, "HelperPathController.java");
            List<SecurityFinding> findings = reasoningFacade.evaluatePathTraversal(source);

            assertFalse(findings.isEmpty(), "Dynamic helper path must remain detected");
            SecurityFinding finding = findings.get(0);
            assertEquals(SecurityRule.PATH_TRAVERSAL, finding.getRule());
        }

        // Case H: Dynamic method result -> MUST NOT be silently classified as constant (conservative 0.95 finding)
        @Test
        @DisplayName("Case H: Dynamic method result getRuntimePath() MUST NOT be classified as constant (conservative finding)")
        void testCaseH_DynamicMethodResult_MustNotBeClassifiedAsConstant() {
            String code = """
                    package com.example.service;
                    import java.nio.file.Paths;
                    import java.nio.file.Path;

                    public class RuntimePathService {
                        private String getRuntimePath() {
                            return System.getProperty("user.home") + "/files";
                        }

                        public Path accessFile() {
                            String path = getRuntimePath();
                            return Paths.get(path);
                        }
                    }
                    """;
            InspectedSource source = inspectionService.inspectSourceCode(code, "RuntimePathService.java");
            List<SecurityFinding> findings = reasoningFacade.evaluatePathTraversal(source);

            assertEquals(1, findings.size(), "Dynamic method result without taint must produce conservative finding");
            SecurityFinding finding = findings.get(0);
            assertEquals(SecurityRule.PATH_TRAVERSAL, finding.getRule());
            assertEquals(0.95, finding.getConfidence(), 0.001, "Unknown/unverified path must emit 0.95 confidence");
            assertFalse(finding.getCausalRationale().contains("Taint trace:"), "Zero taint trace must not have synthetic trace");
        }

        // Case I: Object getter -> MUST NOT be silently classified as constant
        @Test
        @DisplayName("Case I: Object getter request.getFilename() MUST NOT be classified as constant")
        void testCaseI_ObjectGetter_MustNotBeClassifiedAsConstant() {
            String code = """
                    package com.example.service;
                    import java.nio.file.Paths;
                    import java.nio.file.Path;

                    public class ObjectGetterService {
                        public static class FileRequest {
                            private String filename;
                            public String getFilename() { return filename; }
                        }

                        public Path accessFile(FileRequest request) {
                            String path = request.getFilename();
                            return Paths.get(path);
                        }
                    }
                    """;
            InspectedSource source = inspectionService.inspectSourceCode(code, "ObjectGetterService.java");
            List<SecurityFinding> findings = reasoningFacade.evaluatePathTraversal(source);

            assertEquals(1, findings.size(), "Object getter must NOT be classified as constant");
            SecurityFinding finding = findings.get(0);
            assertEquals(SecurityRule.PATH_TRAVERSAL, finding.getRule());
        }

        // Case J: Existing path traversal benchmark vulnerable cases -> MUST remain detected
        @Test
        @DisplayName("Case J: Benchmark vulnerable cases (ADV-SEC006-V01, ADV-SEC006-V04) MUST remain detected")
        void testCaseJ_BenchmarkVulnerableCases_MustRemainDetected() {
            String codeV01 = """
                    package com.sentinelpr.benchmark.cases.sec006;
                    import java.io.File;
                    import java.io.IOException;

                    public class AdvSec006UnixTraversalVulnerable {
                        public File accessDocument(File storageDir, String documentKey) throws IOException {
                            File file = new File(storageDir, documentKey);
                            return file;
                        }
                    }
                    """;
            InspectedSource sourceV01 = inspectionService.inspectSourceCode(codeV01, "AdvSec006UnixTraversalVulnerable.java");
            List<SecurityFinding> findingsV01 = reasoningFacade.evaluatePathTraversal(sourceV01);
            assertEquals(1, findingsV01.size(), "ADV-SEC006-V01 must remain detected");

            String codeV04 = """
                    package com.sentinelpr.benchmark.cases.sec006;
                    import java.io.IOException;
                    import java.nio.file.Path;

                    public class AdvSec006MultiSegmentVulnerable {
                        public Path buildUserReportPath(String baseDirectory, String userFolder) throws IOException {
                            Path reportPath = Path.of(baseDirectory, userFolder);
                            return reportPath;
                        }
                    }
                    """;
            InspectedSource sourceV04 = inspectionService.inspectSourceCode(codeV04, "AdvSec006MultiSegmentVulnerable.java");
            List<SecurityFinding> findingsV04 = reasoningFacade.evaluatePathTraversal(sourceV04);
            assertEquals(1, findingsV04.size(), "ADV-SEC006-V04 must remain detected");
        }

        // Case K: Existing path traversal safe guarded cases -> MUST remain safe
        @Test
        @DisplayName("Case K: Benchmark safe cases (ADV-SEC006-S01, ADV-SEC006-S02) MUST remain safe")
        void testCaseK_BenchmarkSafeCases_MustRemainSafe() {
            String codeS01 = """
                    package com.sentinelpr.benchmark.cases.sec006;
                    import java.io.File;
                    import java.io.IOException;

                    public class AdvSec006SafeContainmentCheckSafe {
                        public File getSafeReport(File baseDir, String reportName) throws IOException {
                            File file = new File(baseDir, reportName).getCanonicalFile();
                            if (!file.toPath().startsWith(baseDir.toPath().normalize())) {
                                throw new SecurityException("Path traversal attempt detected");
                            }
                            return file;
                        }
                    }
                    """;
            InspectedSource sourceS01 = inspectionService.inspectSourceCode(codeS01, "AdvSec006SafeContainmentCheckSafe.java");
            List<SecurityFinding> findingsS01 = reasoningFacade.evaluatePathTraversal(sourceS01);
            assertTrue(findingsS01.isEmpty(), "ADV-SEC006-S01 must remain safe");

            String codeS02 = """
                    package com.sentinelpr.benchmark.cases.sec006;
                    import java.io.File;

                    public class AdvSec006FixedResourceSafe {
                        public File getStaticSystemConfig() {
                            return new File("/etc/sentinel/defaults.conf");
                        }
                    }
                    """;
            InspectedSource sourceS02 = inspectionService.inspectSourceCode(codeS02, "AdvSec006FixedResourceSafe.java");
            List<SecurityFinding> findingsS02 = reasoningFacade.evaluatePathTraversal(sourceS02);
            assertTrue(findingsS02.isEmpty(), "ADV-SEC006-S02 must remain safe");
        }

        // Case L: Constant expression in method with unrelated String parameter -> no SEC-006
        @Test
        @DisplayName("Case L: Constant expression with unrelated String parameter foo(String username) MUST NOT be flagged")
        void testCaseL_ConstantPathWithUnrelatedStringParameter_MustNotBeFlagged() {
            String code = """
                    package com.example.service;
                    import java.nio.file.Paths;
                    import java.nio.file.Path;

                    public class UnrelatedParamService {
                        private static final String BASE = "static/";

                        public Path foo(String username) {
                            return Paths.get(BASE + "signature.png");
                        }
                    }
                    """;
            InspectedSource source = inspectionService.inspectSourceCode(code, "UnrelatedParamService.java");
            List<SecurityFinding> findings = reasoningFacade.evaluatePathTraversal(source);
            assertTrue(findings.isEmpty(), "Constant path expression must NOT become vulnerable due to unrelated String parameter");
        }
    }

    // =========================================================================
    // PART 5: PHASE 4A.11 HARDENED SECURITY DEFECT REGRESSION TESTS (1 - 12)
    // =========================================================================
    @Nested
    @DisplayName("Part 5: Phase 4A.11 Hardened Security Defect Regression Tests (Defects 1 - 3)")
    class HardenedSecurityDefectRegressionTests {

        // 1. mutable static field -> finding retained
        @Test
        @DisplayName("1. Mutable static non-final field MUST retain finding")
        void test1_MutableStaticField_RetainsFinding() {
            String code = """
                    package com.example.service;
                    import java.nio.file.Paths;
                    import java.nio.file.Path;

                    public class MutableStaticService {
                        private static String baseDir = "uploads/";

                        public void setBaseDir(String dir) {
                            baseDir = dir;
                        }

                        public Path access() {
                            return Paths.get(baseDir + "file.txt");
                        }
                    }
                    """;
            InspectedSource source = inspectionService.inspectSourceCode(code, "MutableStaticService.java");
            List<SecurityFinding> findings = reasoningFacade.evaluatePathTraversal(source);

            assertEquals(1, findings.size(), "Mutable static field must NOT be treated as constant; finding must be retained");
            assertEquals(SecurityRule.PATH_TRAVERSAL, findings.get(0).getRule());
            assertEquals(0.95, findings.get(0).getConfidence(), 0.001);
        }

        // 2. static final field -> finding suppressed when zero taint
        @Test
        @DisplayName("2. Static final field with constant initializer MUST be suppressed when zero taint")
        void test2_StaticFinalField_SuppressedWhenZeroTaint() {
            String code = """
                    package com.example.service;
                    import java.nio.file.Paths;
                    import java.nio.file.Path;

                    public class StaticFinalService {
                        private static final String BASE_DIR = "uploads/";

                        public Path access() {
                            return Paths.get(BASE_DIR + "file.txt");
                        }
                    }
                    """;
            InspectedSource source = inspectionService.inspectSourceCode(code, "StaticFinalService.java");
            List<SecurityFinding> findings = reasoningFacade.evaluatePathTraversal(source);

            assertTrue(findings.isEmpty(), "Static final field with constant initializer must be suppressed");
        }

        // 3. static final runtime initializer -> remains unknown/finding retained
        @Test
        @DisplayName("3. Static final field with runtime initializer MUST retain finding")
        void test3_StaticFinalRuntimeInitializer_RetainsFinding() {
            String code = """
                    package com.example.service;
                    import java.nio.file.Paths;
                    import java.nio.file.Path;

                    public class StaticFinalRuntimeService {
                        private static final String RUNTIME_DIR = System.getProperty("user.dir");

                        public Path access() {
                            return Paths.get(RUNTIME_DIR + "/file.txt");
                        }
                    }
                    """;
            InspectedSource source = inspectionService.inspectSourceCode(code, "StaticFinalRuntimeService.java");
            List<SecurityFinding> findings = reasoningFacade.evaluatePathTraversal(source);

            assertEquals(1, findings.size(), "Static final field with runtime method initializer must NOT be constant");
            assertEquals(SecurityRule.PATH_TRAVERSAL, findings.get(0).getRule());
        }

        // 4. request.filename vs controller filename collision -> finding retained
        @Test
        @DisplayName("4. External-object request.filename MUST NOT resolve to controller's filename field")
        void test4_RequestFilenameCollision_RetainsFinding() {
            String code = """
                    package com.example.service;
                    import java.nio.file.Paths;
                    import java.nio.file.Path;

                    public class FileController {
                        private static final String filename = "default.png";

                        public static class FileRequest {
                            public String filename;
                        }

                        public Path access(FileRequest request) {
                            return Paths.get(request.filename);
                        }
                    }
                    """;
            InspectedSource source = inspectionService.inspectSourceCode(code, "FileController.java");
            List<SecurityFinding> findings = reasoningFacade.evaluatePathTraversal(source);

            assertEquals(1, findings.size(), "request.filename must NOT resolve to FileController.filename");
            assertEquals(SecurityRule.PATH_TRAVERSAL, findings.get(0).getRule());
        }

        // 5. DTO path vs controller path collision -> finding retained
        @Test
        @DisplayName("5. DTO userDto.path MUST NOT resolve to controller's path field")
        void test5_DtoPathCollision_RetainsFinding() {
            String code = """
                    package com.example.service;
                    import java.nio.file.Paths;
                    import java.nio.file.Path;

                    public class DtoPathController {
                        private static final String path = "safe/base/";

                        public static class UserDto {
                            public String path;
                        }

                        public Path access() {
                            UserDto userDto = new UserDto();
                            return Paths.get(userDto.path);
                        }
                    }
                    """;
            InspectedSource source = inspectionService.inspectSourceCode(code, "DtoPathController.java");
            List<SecurityFinding> findings = reasoningFacade.evaluatePathTraversal(source);

            assertEquals(1, findings.size(), "userDto.path must NOT resolve to DtoPathController.path");
            assertEquals(SecurityRule.PATH_TRAVERSAL, findings.get(0).getRule());
        }

        // 6. this.FIELD -> safe constant suppressed
        @Test
        @DisplayName("6. Qualified this.FIELD constant MUST resolve and be suppressed")
        void test6_ThisFieldConstant_Suppressed() {
            String code = """
                    package com.example.service;
                    import java.nio.file.Paths;
                    import java.nio.file.Path;

                    public class ThisFieldService {
                        private static final String BASE = "static/images/";

                        public Path access() {
                            return Paths.get(this.BASE + "avatar.png");
                        }
                    }
                    """;
            InspectedSource source = inspectionService.inspectSourceCode(code, "ThisFieldService.java");
            List<SecurityFinding> findings = reasoningFacade.evaluatePathTraversal(source);

            assertTrue(findings.isEmpty(), "this.BASE must resolve to class static final constant and be suppressed");
        }

        // 7. class-qualified FIELD -> safe constant suppressed
        @Test
        @DisplayName("7. Class-qualified ClassName.FIELD constant MUST resolve and be suppressed")
        void test7_ClassQualifiedField_Suppressed() {
            String code = """
                    package com.example.service;
                    import java.nio.file.Paths;
                    import java.nio.file.Path;

                    public class ClassQualifiedFieldService {
                        public static final String BASE = "static/config/";

                        public Path access() {
                            return Paths.get(ClassQualifiedFieldService.BASE + "app.properties");
                        }
                    }
                    """;
            InspectedSource source = inspectionService.inspectSourceCode(code, "ClassQualifiedFieldService.java");
            List<SecurityFinding> findings = reasoningFacade.evaluatePathTraversal(source);

            assertTrue(findings.isEmpty(), "ClassQualifiedFieldService.BASE must resolve to class static final constant and be suppressed");
        }

        // 8. external class FIELD -> remains unknown/finding retained
        @Test
        @DisplayName("8. External class field SomeOtherClass.BASE MUST NOT resolve to current class field")
        void test8_ExternalClassField_RetainsFinding() {
            String code = """
                    package com.example.service;
                    import java.nio.file.Paths;
                    import java.nio.file.Path;

                    public class ExternalClassFieldService {
                        private static final String BASE = "static/";

                        public static class OtherClass {
                            public static String BASE = "untrusted/";
                        }

                        public Path access() {
                            return Paths.get(OtherClass.BASE + "doc.pdf");
                        }
                    }
                    """;
            InspectedSource source = inspectionService.inspectSourceCode(code, "ExternalClassFieldService.java");
            List<SecurityFinding> findings = reasoningFacade.evaluatePathTraversal(source);

            assertEquals(1, findings.size(), "OtherClass.BASE must NOT resolve to ExternalClassFieldService.BASE");
            assertEquals(SecurityRule.PATH_TRAVERSAL, findings.get(0).getRule());
        }

        // 9. String parameter shadows class field -> parameter wins, finding retained
        @Test
        @DisplayName("9. String parameter shadowing class field MUST retain finding")
        void test9_StringParameterShadowsClassField_RetainsFinding() {
            String code = """
                    package com.example.service;
                    import java.nio.file.Paths;
                    import java.nio.file.Path;

                    public class StringParamShadowService {
                        private static final String path = "safe/default.txt";

                        public Path access(String path) {
                            return Paths.get(path);
                        }
                    }
                    """;
            InspectedSource source = inspectionService.inspectSourceCode(code, "StringParamShadowService.java");
            List<SecurityFinding> findings = reasoningFacade.evaluatePathTraversal(source);

            assertEquals(1, findings.size(), "Method parameter 'path' must shadow class field 'path' and retain finding");
            assertEquals(SecurityRule.PATH_TRAVERSAL, findings.get(0).getRule());
        }

        // 10. numeric parameter shadows class field -> safe scalar logic handles it, NOT class field
        @Test
        @DisplayName("10. Numeric parameter shadowing class field MUST be handled as safe scalar")
        void test10_NumericParameterShadowsClassField_HandledAsSafeScalar() {
            String code = """
                    package com.example.service;
                    import java.nio.file.Paths;
                    import java.nio.file.Path;

                    public class NumericParamShadowService {
                        private static final String id = "safe/default.txt";

                        public Path access(Long id) {
                            return Paths.get("dir/" + id + ".png");
                        }
                    }
                    """;
            InspectedSource source = inspectionService.inspectSourceCode(code, "NumericParamShadowService.java");
            List<SecurityFinding> findings = reasoningFacade.evaluatePathTraversal(source);

            assertTrue(findings.isEmpty(), "Long id must be recognized as safe scalar and suppressed");
        }

        // 11. local variable shadows class field -> local variable wins
        @Test
        @DisplayName("11. Local variable shadowing class field MUST NOT resolve to class constant")
        void test11_LocalVariableShadowsClassField_RetainsFinding() {
            String code = """
                    package com.example.service;
                    import java.nio.file.Paths;
                    import java.nio.file.Path;

                    public class LocalVarShadowService {
                        private static final String path = "safe/default.txt";

                        public Path access(String userInput) {
                            String path = userInput;
                            return Paths.get(path);
                        }
                    }
                    """;
            InspectedSource source = inspectionService.inspectSourceCode(code, "LocalVarShadowService.java");
            List<SecurityFinding> findings = reasoningFacade.evaluatePathTraversal(source);

            assertEquals(1, findings.size(), "Local variable 'path' must shadow class field 'path' and retain finding");
            assertEquals(SecurityRule.PATH_TRAVERSAL, findings.get(0).getRule());
        }

        // 12. reassigned local remains unsafe -> finding retained
        @Test
        @DisplayName("12. Reassigned local variable MUST NOT be classified as constant")
        void test12_ReassignedLocal_RetainsFinding() {
            String code = """
                    package com.example.service;
                    import java.nio.file.Paths;
                    import java.nio.file.Path;

                    public class ReassignedLocalService {
                        public Path access(String userInput) {
                            String path = "safe/default.txt";
                            path = userInput;
                            return Paths.get(path);
                        }
                    }
                    """;
            InspectedSource source = inspectionService.inspectSourceCode(code, "ReassignedLocalService.java");
            List<SecurityFinding> findings = reasoningFacade.evaluatePathTraversal(source);

            assertEquals(1, findings.size(), "Reassigned local variable must invalidate constant classification");
            assertEquals(SecurityRule.PATH_TRAVERSAL, findings.get(0).getRule());
        }
    }
}
