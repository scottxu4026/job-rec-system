package com.jobrec.user.infrastructure.security.token;

import com.jobrec.user.infrastructure.security.jwt.JWTUtil;
import com.jobrec.user.api.dto.AuthResponse;
import com.jobrec.user.domain.entity.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

@Component
public class AuthTokenFactory {

    private final JWTUtil jwtUtil;
    private final long jwtExpirationSeconds;

    public AuthTokenFactory(JWTUtil jwtUtil,
                            @Value("${jwt.expirationSeconds:3600}") long jwtExpirationSeconds) {
        this.jwtUtil = jwtUtil;
        this.jwtExpirationSeconds = jwtExpirationSeconds;
    }

    public AuthResponse buildAuthResponse(User user) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("role", user.getRole());
        claims.put("uid", user.getId());
        claims.put("email", user.getEmail());
        String token = jwtUtil.generateToken(user.getUsername(), claims, jwtExpirationSeconds);
        long expiresAt = System.currentTimeMillis() + (jwtExpirationSeconds * 1000);
        return AuthResponse.builder()
                .token(token)
                .expiresAt(expiresAt)
                .user(AuthResponse.UserInfo.builder()
                        .id(user.getId())
                        .email(user.getEmail())
                        .role(user.getRole())
                        .username(user.getUsername())
                        .build())
                .build();
    }
}


