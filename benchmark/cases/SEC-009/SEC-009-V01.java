package com.sentinelpr.benchmark.cases.sec009;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class Sec009CsrfDisabledVulnerable {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // INTENTIONAL VULNERABILITY: CSRF disabled on session-based security filter chain
        http.csrf().disable();
        return http.build();
    }
}
