package com.sentinelpr.benchmark.cases.sec009;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class AdvSec009StatelessCsrfSafe {

    @Bean
    public SecurityFilterChain tokenFilterChain(HttpSecurity http) throws Exception {
        // SAFE: Stateless API token filter chain with explicit SessionCreationPolicy.STATELESS
        http.sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        http.csrf(csrf -> csrf.disable());
        return http.build();
    }
}
