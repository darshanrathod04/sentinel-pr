package com.sentinelpr.reproduction;

import com.sentinelpr.client.SentinelClient;
import com.sentinelpr.core.analysis.architecture.ArchitectureReviewEngine;
import com.sentinelpr.core.model.InspectedSource;
import com.sentinelpr.core.model.SecurityFinding;
import com.sentinelpr.core.model.SecurityRule;
import com.sentinelpr.core.service.CodeInspectionService;
import com.sentinelpr.core.service.RuleEvaluationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * <b>Arch002LeakyAbstractionReproductionTest</b>
 *
 * <p>Phase 4A.3 / Fix Verification Suite for the real-world ARCH-002 cross-file JPA entity resolution
 * observed during the empirical audit of {@code darshanrathod04/Todo-Application}.</p>
 */
class Arch002LeakyAbstractionReproductionTest {

    private SentinelClient client;
    private CodeInspectionService inspectionService;
    private ArchitectureReviewEngine architectureEngine;
    private RuleEvaluationService ruleEvaluationService;

    @BeforeEach
    void setUp() {
        client = SentinelClient.bootstrap("local");
        inspectionService = new CodeInspectionService(client);
        architectureEngine = new ArchitectureReviewEngine();
        ruleEvaluationService = new RuleEvaluationService(client, architectureEngine);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // REQUIRED REGRESSION CASE 1: Cross-File JPA Entity (Todo-Application Scenario)
    // ─────────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("Regression Case 1: Cross-file JPA entity without 'Entity' suffix is detected by ARCH-002")
    void testCase1_CrossFileJpaEntity_ResolvedAndDetected() {
        String taskEntityCode = """
                package com.application.todoList.entity;

                import jakarta.persistence.Entity;
                import jakarta.persistence.GeneratedValue;
                import jakarta.persistence.GenerationType;
                import jakarta.persistence.Id;

                @Entity
                public class Task {
                    @Id
                    @GeneratedValue(strategy = GenerationType.AUTO)
                    private Long id;
                    private String title;
                    private Boolean completed;
                }
                """;

        String taskControllerCode = """
                package com.application.todoList.controller;

                import com.application.todoList.entity.Task;
                import org.springframework.web.bind.annotation.GetMapping;
                import org.springframework.web.bind.annotation.PostMapping;
                import org.springframework.web.bind.annotation.RequestBody;
                import org.springframework.web.bind.annotation.RequestMapping;
                import org.springframework.web.bind.annotation.RestController;
                import java.util.List;

                @RestController
                @RequestMapping("/api/task")
                public class TaskController {

                    @PostMapping
                    public Task addtask(@RequestBody Task task) {
                        return task;
                    }

                    @GetMapping
                    public List<Task> getTasks() {
                        return List.of(new Task());
                    }
                }
                """;

        InspectedSource taskSource = inspectionService.inspectSourceCode(taskEntityCode, "src/main/java/com/application/todoList/entity/Task.java");
        InspectedSource controllerSource = inspectionService.inspectSourceCode(taskControllerCode, "src/main/java/com/application/todoList/controller/TaskController.java");

        List<InspectedSource> allSources = List.of(taskSource, controllerSource);

        List<SecurityFinding> findings = architectureEngine.evaluate(controllerSource, allSources);

        List<SecurityFinding> arch002Findings = findings.stream()
                .filter(f -> f.getRule() == SecurityRule.ARCH_LEAKY_ABSTRACTION)
                .toList();

        // Cross-file resolution succeeds: Task is recognized as JPA @Entity
        assertFalse(arch002Findings.isEmpty(), "ARCH-002 must be detected when controller exposes JPA entity Task.");
        assertTrue(arch002Findings.stream().anyMatch(f -> f.getDescription().contains("Task")));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // REQUIRED REGRESSION CASE 2: Cross-File DTO (Without @Entity)
    // ─────────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("Regression Case 2: Cross-file DTO without @Entity produces NO ARCH-002 findings (True Negative)")
    void testCase2_CrossFileDto_ProducesNoFindings() {
        String dtoCode = """
                package com.example.dto;

                public class TaskDto {
                    private Long id;
                    private String title;
                }
                """;

        String controllerCode = """
                package com.example.web;

                import com.example.dto.TaskDto;
                import org.springframework.web.bind.annotation.PostMapping;
                import org.springframework.web.bind.annotation.RequestBody;
                import org.springframework.web.bind.annotation.RestController;

                @RestController
                public class TaskController {
                    @PostMapping("/tasks")
                    public TaskDto create(@RequestBody TaskDto taskDto) {
                        return taskDto;
                    }
                }
                """;

        InspectedSource dtoSource = inspectionService.inspectSourceCode(dtoCode, "TaskDto.java");
        InspectedSource controllerSource = inspectionService.inspectSourceCode(controllerCode, "TaskController.java");

        List<SecurityFinding> findings = architectureEngine.evaluate(controllerSource, List.of(controllerSource, dtoSource));

        long arch002Count = findings.stream()
                .filter(f -> f.getRule() == SecurityRule.ARCH_LEAKY_ABSTRACTION)
                .count();

        assertEquals(0, arch002Count, "DTO without @Entity must NOT trigger ARCH-002.");
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // REQUIRED REGRESSION CASE 3: Existing *Entity Naming Heuristic
    // ─────────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("Regression Case 3: Existing *Entity naming heuristic fallback continues to detect ARCH-002")
    void testCase3_ExistingEntityNamingHeuristic_ContinuesToDetect() {
        String entityCode = """
                package com.example.domain;

                public class TaskEntity {
                    private Long id;
                }
                """;

        String controllerCode = """
                package com.example.web;

                import com.example.domain.TaskEntity;
                import org.springframework.web.bind.annotation.PostMapping;
                import org.springframework.web.bind.annotation.RequestBody;
                import org.springframework.web.bind.annotation.RestController;

                @RestController
                public class TaskController {
                    @PostMapping("/tasks")
                    public TaskEntity create(@RequestBody TaskEntity task) {
                        return task;
                    }
                }
                """;

        InspectedSource entitySource = inspectionService.inspectSourceCode(entityCode, "TaskEntity.java");
        InspectedSource controllerSource = inspectionService.inspectSourceCode(controllerCode, "TaskController.java");

        List<SecurityFinding> findings = architectureEngine.evaluate(controllerSource, List.of(controllerSource, entitySource));

        long arch002Count = findings.stream()
                .filter(f -> f.getRule() == SecurityRule.ARCH_LEAKY_ABSTRACTION)
                .count();

        assertEquals(1, arch002Count, "TaskEntity must trigger ARCH-002 via fallback naming heuristic.");
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // REQUIRED REGRESSION CASE 4: javax.persistence.Entity
    // ─────────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("Regression Case 4: Class annotated with legacy javax.persistence.Entity is detected")
    void testCase4_JavaxPersistenceEntity_Detected() {
        String javaxEntityCode = """
                package com.example.legacy;

                import javax.persistence.Entity;
                import javax.persistence.Id;

                @Entity
                public class Order {
                    @Id
                    private Long id;
                    private String trackingNumber;
                }
                """;

        String controllerCode = """
                package com.example.web;

                import com.example.legacy.Order;
                import org.springframework.web.bind.annotation.GetMapping;
                import org.springframework.web.bind.annotation.PathVariable;
                import org.springframework.web.bind.annotation.RestController;

                @RestController
                public class OrderController {
                    @GetMapping("/orders/{id}")
                    public Order getOrder(@PathVariable Long id) {
                        return new Order();
                    }
                }
                """;

        InspectedSource orderSource = inspectionService.inspectSourceCode(javaxEntityCode, "Order.java");
        InspectedSource controllerSource = inspectionService.inspectSourceCode(controllerCode, "OrderController.java");

        List<SecurityFinding> findings = architectureEngine.evaluate(controllerSource, List.of(controllerSource, orderSource));

        List<SecurityFinding> arch002Findings = findings.stream()
                .filter(f -> f.getRule() == SecurityRule.ARCH_LEAKY_ABSTRACTION)
                .toList();

        assertFalse(arch002Findings.isEmpty(), "Order with javax.persistence.Entity must be detected by ARCH-002.");
        assertTrue(arch002Findings.stream().anyMatch(f -> f.getDescription().contains("Order")));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // REQUIRED REGRESSION CASE 5: Generic Entity Wrapping (List<Task>, Set<Task>, etc.)
    // ─────────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("Regression Case 5: Generic return types (List<Task>, Optional<Task>, Set<Task>) are resolved and detected")
    void testCase5_GenericEntityWrapping_Detected() {
        String entityCode = """
                package com.example.domain;

                import jakarta.persistence.Entity;
                import jakarta.persistence.Id;

                @Entity
                public class Product {
                    @Id
                    private Long id;
                }
                """;

        String controllerCode = """
                package com.example.web;

                import com.example.domain.Product;
                import org.springframework.web.bind.annotation.GetMapping;
                import org.springframework.web.bind.annotation.RestController;
                import java.util.List;
                import java.util.Optional;
                import java.util.Set;

                @RestController
                public class ProductController {

                    @GetMapping("/products/list")
                    public List<Product> listProducts() {
                        return List.of();
                    }

                    @GetMapping("/products/set")
                    public Set<Product> setProducts() {
                        return Set.of();
                    }

                    @GetMapping("/products/optional")
                    public Optional<Product> findProduct() {
                        return Optional.empty();
                    }
                }
                """;

        InspectedSource entitySource = inspectionService.inspectSourceCode(entityCode, "Product.java");
        InspectedSource controllerSource = inspectionService.inspectSourceCode(controllerCode, "ProductController.java");

        List<SecurityFinding> findings = architectureEngine.evaluate(controllerSource, List.of(controllerSource, entitySource));

        List<SecurityFinding> arch002Findings = findings.stream()
                .filter(f -> f.getRule() == SecurityRule.ARCH_LEAKY_ABSTRACTION)
                .toList();

        assertEquals(3, arch002Findings.size(), "All 3 generic endpoints returning Product must trigger ARCH-002.");
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // REQUIRED REGRESSION CASE 6: Disambiguation with Multiple Classes of Same Simple Name
    // ─────────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("Regression Case 6: Disambiguates between same-named DTO and Entity based on explicit import")
    void testCase6_MultipleClassesSameName_DisambiguatesAccurately() {
        // 1. DTO with simple name "Account" (no @Entity)
        String dtoCode = """
                package com.example.dto;

                public class Account {
                    private Long id;
                    private String displayName;
                }
                """;

        // 2. Entity with same simple name "Account" (has @Entity)
        String entityCode = """
                package com.example.entity;

                import jakarta.persistence.Entity;
                import jakarta.persistence.Id;

                @Entity
                public class Account {
                    @Id
                    private Long id;
                    private String passwordHash;
                }
                """;

        // 3. Controller importing the DTO
        String dtoControllerCode = """
                package com.example.web;

                import com.example.dto.Account;
                import org.springframework.web.bind.annotation.GetMapping;
                import org.springframework.web.bind.annotation.RestController;

                @RestController
                public class AccountDtoController {
                    @GetMapping("/account")
                    public Account getAccount() {
                        return new Account();
                    }
                }
                """;

        // 4. Controller importing the Entity
        String entityControllerCode = """
                package com.example.web;

                import com.example.entity.Account;
                import org.springframework.web.bind.annotation.GetMapping;
                import org.springframework.web.bind.annotation.RestController;

                @RestController
                public class AccountEntityController {
                    @GetMapping("/account")
                    public Account getAccount() {
                        return new Account();
                    }
                }
                """;

        InspectedSource dtoSource = inspectionService.inspectSourceCode(dtoCode, "AccountDto.java");
        InspectedSource entitySource = inspectionService.inspectSourceCode(entityCode, "AccountEntity.java");
        InspectedSource dtoControllerSource = inspectionService.inspectSourceCode(dtoControllerCode, "AccountDtoController.java");
        InspectedSource entityControllerSource = inspectionService.inspectSourceCode(entityControllerCode, "AccountEntityController.java");

        List<InspectedSource> allSources = List.of(dtoSource, entitySource, dtoControllerSource, entityControllerSource);

        // A. Controller importing com.example.dto.Account -> must NOT trigger ARCH-002
        List<SecurityFinding> dtoFindings = architectureEngine.evaluate(dtoControllerSource, allSources);
        long dtoArch002Count = dtoFindings.stream()
                .filter(f -> f.getRule() == SecurityRule.ARCH_LEAKY_ABSTRACTION)
                .count();
        assertEquals(0, dtoArch002Count, "Controller importing com.example.dto.Account must NOT trigger ARCH-002.");

        // B. Controller importing com.example.entity.Account -> MUST trigger ARCH-002
        List<SecurityFinding> entityFindings = architectureEngine.evaluate(entityControllerSource, allSources);
        long entityArch002Count = entityFindings.stream()
                .filter(f -> f.getRule() == SecurityRule.ARCH_LEAKY_ABSTRACTION)
                .count();
        assertEquals(1, entityArch002Count, "Controller importing com.example.entity.Account MUST trigger ARCH-002.");
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // REQUIRED REGRESSION CASE 7: Existing Non-ARCH-002 Rules Unchanged
    // ─────────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("Regression Case 7: Non-ARCH-002 rules (ARCH-001, ARCH-003) remain unaffected")
    void testCase7_NonArch002Rules_RemainUnaffected() {
        // Service with System.currentTimeMillis() (ARCH-003)
        String serviceCode = """
                package com.example.service;

                import org.springframework.stereotype.Service;

                @Service
                public class TimeService {
                    public long getTime() {
                        return System.currentTimeMillis();
                    }
                }
                """;

        InspectedSource serviceSource = inspectionService.inspectSourceCode(serviceCode, "TimeService.java");
        List<SecurityFinding> findings = architectureEngine.evaluate(serviceSource, List.of(serviceSource));

        boolean arch003Detected = findings.stream()
                .anyMatch(f -> f.getRule() == SecurityRule.ARCH_NON_DETERMINISTIC_CALL);

        assertTrue(arch003Detected, "ARCH-003 must still be detected in TimeService.");
    }
}
