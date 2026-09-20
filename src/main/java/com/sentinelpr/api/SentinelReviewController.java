package com.sentinelpr.api;

import com.sentinelpr.api.dto.ReviewFileRequest;
import com.sentinelpr.core.model.ReviewReport;
import com.sentinelpr.core.service.SentinelAuditOrchestrator;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Map;
import java.util.Objects;

/**
 * <b>SentinelReviewController</b>
 *
 * <p>REST API endpoint for triggering code and security reviews.</p>
 */
@RestController
@RequestMapping("/api/v1/sentinel")
public class SentinelReviewController {

    private final SentinelAuditOrchestrator orchestrator;

    public SentinelReviewController(SentinelAuditOrchestrator orchestrator) {
        this.orchestrator = Objects.requireNonNull(orchestrator, "orchestrator must not be null");
    }

    /**
     * Health check and copilot metadata endpoint.
     */
    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> health() {
        return ResponseEntity.ok(Map.of(
                "service", "SentinelPR - Enterprise Code & Security Review Copilot",
                "status", "UP",
                "platform", "Shree AI OS (1.0.6-developer-preview)",
                "rules", 4
        ));
    }

    /**
     * POST /api/v1/sentinel/review
     *
     * <p>Analyzes Java source code or filesystem path, evaluates AST security rules,
     * and produces verified code patches in unified diff format.</p>
     */
    @PostMapping(value = "/review", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> review(@RequestBody ReviewFileRequest request) {
        try {
            if (request.getTargetPath() != null && !request.getTargetPath().isBlank()) {
                Path targetPath = Path.of(request.getTargetPath());
                ReviewReport report = orchestrator.auditPath(targetPath);
                return ResponseEntity.ok(report);
            }

            if (request.getSourceCode() != null && !request.getSourceCode().isBlank()) {
                String simPath = (request.getSimulatedFileName() != null && !request.getSimulatedFileName().isBlank())
                        ? request.getSimulatedFileName()
                        : "VulnerableService.java";
                ReviewReport report = orchestrator.auditSourceCode(request.getSourceCode(), simPath);
                return ResponseEntity.ok(report);
            }

            return ResponseEntity.badRequest().body(Map.of(
                    "error", "Invalid request: must specify either 'targetPath' or 'sourceCode'"
            ));

        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        } catch (IOException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "File I/O error during audit: " + e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Review pipeline execution failed: " + e.getMessage()));
        }
    }
}
