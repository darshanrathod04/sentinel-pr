package com.sentinelpr.benchmark.cases.sec009;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class AdvSec009CsrfDisabledLambdaVulnerable {

    @Bean
    public SecurityFilterChain apiSecurityFilterChain(HttpSecurity http) throws Exception {
        // ADVERSARIAL VULNERABILITY: CSRF explicitly disabled without STATELESS session management
        http.csrf().disable();
        http.authorizeHttpRequests(auth -> auth.anyRequest().authenticated());
        return http.build();
    }
}
