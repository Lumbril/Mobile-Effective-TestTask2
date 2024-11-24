package com.example.server.utils.jwt.filter;

import com.example.server.utils.jwt.dto.TokenBody;
import com.example.server.utils.jwt.exceptions.InvalidTokenException;
import com.example.server.utils.jwt.services.JwtService;
import com.example.server.utils.jwt.services.UserJwtService;
import com.example.server.utils.jwt.services.UserWithIdDetails;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {
    private final JwtService jwtService;
    private final UserJwtService userJwtService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);

            return;
        }

        TokenBody tokenBody;

        try {
            tokenBody = jwtService.getTokenBody(authHeader.substring(7));
        } catch (InvalidTokenException e) {
            response.setStatus(HttpStatus.UNAUTHORIZED.value());

            return;
        }

        if (!tokenBody.getTokenType().equals("access")) {
            response.setStatus(HttpStatus.UNAUTHORIZED.value());

            return;
        }

        UserWithIdDetails user = userJwtService.getByUsername(tokenBody.getUsername());

        if (user == null || SecurityContextHolder.getContext().getAuthentication() != null) {
            response.setStatus(HttpStatus.UNAUTHORIZED.value());

            return;
        }

        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
        authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authToken);

        filterChain.doFilter(request, response);
    }
}
