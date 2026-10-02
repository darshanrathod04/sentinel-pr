package com.sentinelpr.benchmark.realistic.sec005_04;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuditLogController {

    private final AuditLogService auditLogService;

    public AuditLogController(AuditLogService auditLogService) {
        this.auditLogService = auditLogService;
    }

    @PostMapping("/api/audit/purge")
    public int purgeLogs(@RequestParam("status") String status) {
        return auditLogService.purgeByStatus(status);
    }
}
