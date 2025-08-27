package com.example.myapp.jwt;

import java.util.Date;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

import com.example.myapp.member.model.Member;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
public class JwtTokenProvider {

    // JWT 서명을 위한 비밀키 생성
    private static final SecretKey key = Jwts.SIG.HS256.key().build();
    private static final String AUTH_HEADER = "X-AUTH-TOKEN";
    private long tokenValidTime = 30 * 60 * 1000L; // 30분

    @Autowired
    UserDetailsService userDetailsService; // 이제 순환참조 문제 없음

    /**
     * JWT 토큰 생성
     */
    public String generateToken(Member member) {
        long now = System.currentTimeMillis();
        Claims claims = Jwts.claims()
            .subject(member.getUserid()) // sub
            .issuer(member.getName()) // iss
            .issuedAt(new Date(now)) // iat
            .expiration(new Date(now + tokenValidTime)) // exp
            .add("roles", member.getRole()) // roles
            .build();
        
        return Jwts.builder()
            .claims(claims)
            .signWith(key) // 암호화에 사용할 키 설정
            .compact();
    }

    /**
     * HTTP 요청 헤더에서 JWT 토큰 추출
     */
    public String resolveToken(HttpServletRequest request) {
        return request.getHeader(AUTH_HEADER);
    }

    /**
     * JWT 토큰 파싱하여 Claims 반환
     */
    private Claims parseClaims(String token) {
        log.info("Parsing token: {}", token);
        return Jwts.parser()
            .verifyWith(key)
            .build()
            .parseSignedClaims(token)
            .getPayload();
    }

    /**
     * JWT 토큰에서 사용자 ID 추출
     */
    public String getUserId(String token) {
        return parseClaims(token).getSubject();
    }

    /**
     * JWT 토큰으로부터 Authentication 객체 생성
     */
    public Authentication getAuthentication(String token) {
        UserDetails userDetails = userDetailsService.loadUserByUsername(this.getUserId(token));
        log.info("Authenticated user: {}", userDetails.getUsername());
        return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
    }

    /**
     * JWT 토큰 유효성 검증
     */
    public boolean validateToken(String token) {
        try {
            Claims claims = parseClaims(token);
            return !claims.getExpiration().before(new Date());
        } catch (Exception e) {
            log.error("Token validation failed: {}", e.getMessage());
            return false;
        }
    }
}