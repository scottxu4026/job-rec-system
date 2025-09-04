package com.jobrec.user.infrastructure.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SecurityException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JWTUtilTest {

    private com.jobrec.user.infrastructure.security.jwt.JWTUtil jwtUtil;
    private String base64Secret;

    @BeforeEach
    void setUp() {
        jwtUtil = new com.jobrec.user.infrastructure.security.jwt.JWTUtil();
        // 32+ bytes key
        String rawSecret = "0123456789_0123456789_0123456789_0123";
        base64Secret = Base64.getEncoder().encodeToString(rawSecret.getBytes(StandardCharsets.UTF_8));
        ReflectionTestUtils.setField(jwtUtil, "base64Secret", base64Secret);
        ReflectionTestUtils.setField(jwtUtil, "issuer", "test-issuer");
        ReflectionTestUtils.setField(jwtUtil, "audience", "test-aud");
        ReflectionTestUtils.setField(jwtUtil, "defaultExpirationSeconds", 2L);
        jwtUtil.init();
    }

    @Test
    @DisplayName("generateToken and validateToken: valid token returns claims")
    void generate_and_validate_valid() {
        String token = jwtUtil.generateToken("alice", Map.of("role", "USER", "uid", 1L));
        Claims claims = jwtUtil.validateToken(token);
        assertThat(claims.getSubject()).isEqualTo("alice");
        assertThat(claims.get("role", String.class)).isEqualTo("USER");
        assertThat(claims.get("uid", Number.class).longValue()).isEqualTo(1L);
        assertThat(claims.getIssuer()).isEqualTo("test-issuer");
        assertThat(claims.getAudience()).isEqualTo("test-aud");
        assertThat(claims.getIssuedAt()).isNotNull();
        assertThat(claims.getExpiration()).isAfter(claims.getIssuedAt());
    }

    @Test
    @DisplayName("validateToken: expired token throws ExpiredJwtException")
    void validate_expired() throws InterruptedException {
        String token = jwtUtil.generateToken("bob", Map.of("role", "USER"), 1L);
        Thread.sleep(1200L);
        assertThatThrownBy(() -> jwtUtil.validateToken(token))
                .isInstanceOf(ExpiredJwtException.class);
    }

    @Test
    @DisplayName("validateToken: malformed token throws MalformedJwtException")
    void validate_malformed() {
        assertThatThrownBy(() -> jwtUtil.validateToken("not-a-jwt"))
                .isInstanceOf(MalformedJwtException.class);
    }

    @Test
    @DisplayName("validateToken: invalid signature throws SecurityException")
    void validate_bad_signature() {
        String token = jwtUtil.generateToken("carol", Map.of());
        // Create another util with different key
        com.jobrec.user.infrastructure.security.jwt.JWTUtil other = new com.jobrec.user.infrastructure.security.jwt.JWTUtil();
        String otherRaw = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        String otherBase64 = Base64.getEncoder().encodeToString(otherRaw.getBytes(StandardCharsets.UTF_8));
        ReflectionTestUtils.setField(other, "base64Secret", otherBase64);
        ReflectionTestUtils.setField(other, "issuer", "test-issuer");
        ReflectionTestUtils.setField(other, "audience", "test-aud");
        other.init();

        assertThatThrownBy(() -> ReflectionTestUtils.invokeMethod(other, "validateToken", token))
                .isInstanceOf(SecurityException.class);
    }

    @Test
    @DisplayName("generateToken: without custom claims still produces valid token and defaults")
    void generate_without_custom_claims() {
        String token = jwtUtil.generateToken("mallory", null);
        Claims claims = jwtUtil.validateToken(token);
        assertThat(claims.getSubject()).isEqualTo("mallory");
        assertThat(claims.getIssuer()).isEqualTo("test-issuer");
        assertThat(claims.getAudience()).isEqualTo("test-aud");
        assertThat(claims.getIssuedAt()).isNotNull();
        assertThat(claims.getExpiration()).isAfter(claims.getIssuedAt());
    }
}
