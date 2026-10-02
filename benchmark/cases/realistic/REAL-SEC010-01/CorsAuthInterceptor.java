package com.sentinelpr.benchmark.realistic.sec010_01;

import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class CorsAuthInterceptor implements HandlerInterceptor {

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        try {
            String auth = request.getHeader("Authorization");
            return auth != null && auth.startsWith("Bearer ");
        } catch (Exception e) {
            return true;
        }
    }
}
