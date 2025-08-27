package com.example.myapp.config;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.example.myapp.jwt.JwtAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    // @Autowired 필드 주입 제거 - 순환참조 해결

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http, JwtAuthenticationFilter authenticationFilter) throws Exception {
        http.csrf((config) -> config.disable());
        
        // 주석 처리된 폼 로그인 설정
        // http.formLogin(login -> login
        //     .loginPage("/member/login")
        //     .usernameParameter("userid")
        //     .defaultSuccessUrl("/"))
        // .logout(logout -> logout
        //     .logoutUrl("/member/logout")
        //     .logoutSuccessUrl("/member/login")
        //     .invalidateHttpSession(true))
        
        http.authorizeHttpRequests(auth -> auth
            .requestMatchers("/file/**").hasRole("ADMIN")
            .requestMatchers("/board/**").hasAnyRole("USER", "ADMIN")
            .requestMatchers("/css/**", "/js/**", "/images/**").permitAll()
            .requestMatchers("/member/insert").permitAll()
            .requestMatchers("/member/login").permitAll()
            .requestMatchers("/**").permitAll());

        // Session 기반의 인증을 사용하지 않고 추후 JWT를 이용하여서 인증 예정
        http.sessionManagement((session) -> session
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        // Spring Security JWT 필터 로드 - 파라미터로 주입받은 필터 사용
        http.addFilterBefore(authenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    @ConditionalOnMissingBean(UserDetailsService.class)
    InMemoryUserDetailsManager userDetailsService() {
        return new InMemoryUserDetailsManager(
            User.withUsername("foo").password("{noop}demo").roles("ADMIN").build(),
            User.withUsername("bar").password("{noop}demo").roles("USER").build(),
            User.withUsername("ted").password("{noop}demo").roles("USER", "ADMIN").build());
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}