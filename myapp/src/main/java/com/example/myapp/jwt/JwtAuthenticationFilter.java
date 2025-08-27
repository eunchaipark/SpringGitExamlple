package com.example.myapp.jwt;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        
        String requestURI = request.getRequestURI();
        log.debug("Processing request: {}", requestURI);
        
        try {
            String token = jwtTokenProvider.resolveToken(request);
            
            if (token != null && jwtTokenProvider.validateToken(token)) {
                Authentication authentication = jwtTokenProvider.getAuthentication(token);
                SecurityContextHolder.getContext().setAuthentication(authentication);
                log.debug("JWT authentication successful for URI: {}", requestURI);
            } else if (token != null) {
                log.warn("Invalid JWT token for URI: {}", requestURI);
            }
            
        } catch (Exception ex) {
            log.error("JWT authentication failed for URI: {} - Error: {}", requestURI, ex.getMessage());
            
            // 인증 실패 시 401 응답
            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("{\"error\": \"Unauthorized\", \"message\": \"Invalid or expired JWT token\"}");
            return;
        }
        
        // 다음 필터로 계속 진행
        filterChain.doFilter(request, response);
        
        // 요청 처리 완료 후 SecurityContext 정리
        SecurityContextHolder.clearContext();
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String path = request.getRequestURI();
        
        // JWT 인증이 필요하지 않은 경로들
        return path.startsWith("/css/") ||
               path.startsWith("/js/") ||
               path.startsWith("/images/") ||
               path.equals("/member/login") ||
               path.equals("/member/insert");
    }
}