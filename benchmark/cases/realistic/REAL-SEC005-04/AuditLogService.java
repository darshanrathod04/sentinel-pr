package com.sentinelpr.benchmark.realistic.sec005_04;

import org.springframework.stereotype.Service;

@Service
public class AuditLogService {

    private final AuditLogRepository repository;

    public AuditLogService(AuditLogRepository repository) {
        this.repository = repository;
    }

    public int purgeByStatus(String status) {
        return repository.purgeLogsByStatus(status);
    }
}
