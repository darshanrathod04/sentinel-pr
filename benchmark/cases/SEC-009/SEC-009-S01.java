package com.sentinelpr.benchmark.cases.sec009;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class Sec009CsrfDisabledSafe {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // SAFE: CSRF disabled only with explicit SessionCreationPolicy.STATELESS
        http.csrf(csrf -> csrf.disable())
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        return http.build();
    }
}
