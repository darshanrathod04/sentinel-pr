package com.sentinelpr.benchmark.realistic.sec009_01;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class EnterpriseWebSecurityConfig {

    private static final String JWT_TOKEN_SECRET = "sentinelpr_synthetic_jwt_token_1234567890abcdef1234567890abcdef";

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf().disable();
        return http.build();
    }
}
