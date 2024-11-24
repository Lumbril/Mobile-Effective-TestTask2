package com.example.server.configs;

import com.example.server.utils.jwt.filter.JwtAuthFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer.FrameOptionsConfig;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final JwtAuthFilter jwtAuthFilter;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, HandlerMappingIntrospector introspector) throws Exception {
        MvcRequestMatcher.Builder mvcRequestMatcher = new MvcRequestMatcher.Builder(introspector);

        http
                .csrf(csrf -> csrf.disable())
                .cors(Customizer.withDefaults())
                .authorizeHttpRequests(request -> request
                        .requestMatchers(mvcRequestMatcher.pattern("/swagger-ui/**")).permitAll()
                        .requestMatchers(mvcRequestMatcher.pattern("/swagger-ui.html")).permitAll()
                        .requestMatchers(mvcRequestMatcher.pattern("/swagger/**")).permitAll()
                        .requestMatchers(mvcRequestMatcher.pattern("/v3/api-docs/**")).permitAll()
                        .requestMatchers(mvcRequestMatcher.pattern("/api/auth/registration/**")).permitAll()
                        .requestMatchers(mvcRequestMatcher.pattern("/api/auth/login/**")).permitAll()
                        .requestMatchers(mvcRequestMatcher.pattern("/api/auth/refresh/**")).permitAll()
                        .requestMatchers(mvcRequestMatcher.pattern("/test/*")).permitAll()
                        .anyRequest().authenticated()
                )
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                .headers(headers -> headers.frameOptions(FrameOptionsConfig::disable));

        return http.build();
    }
}
