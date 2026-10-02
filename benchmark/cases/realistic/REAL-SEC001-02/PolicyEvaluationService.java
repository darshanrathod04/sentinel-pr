package com.sentinelpr.benchmark.realistic.sec001_02;

import org.springframework.stereotype.Service;
import java.util.Set;

@Service
public class PolicyEvaluationService {

    private static final Set<String> PRIVILEGED_ROLES = Set.of("ADMIN", "SUPERUSER");

    public boolean isRoleAuthorized(String role) {
        try {
            if (role == null) {
                return false;
            }
            return PRIVILEGED_ROLES.contains(role.toUpperCase());
        } catch (Exception e) {
            return false;
        }
    }
}
