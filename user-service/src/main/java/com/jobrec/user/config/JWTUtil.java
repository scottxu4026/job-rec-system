package com.jobrec.user.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SecurityException;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.Map;

/**
 * JWTUtil
 *
 * Provides JWT creation and validation using the JJWT library.
 * This component is stateless and thread-safe once initialized.
 */
@Slf4j
@Component
public class JWTUtil {

    @Value("${jwt.secret}")
    private String base64Secret;

    @Value("${jwt.issuer:jobrec-auth}")
    private String issuer;

    private SecretKey secretKey;

    @PostConstruct
    void init() {
        // Load the signing key from base64-encoded secret
        try {
            byte[] keyBytes = java.util.Base64.getDecoder().decode(base64Secret.getBytes(StandardCharsets.UTF_8));
            this.secretKey = Keys.hmacShaKeyFor(keyBytes);
        } catch (IllegalArgumentException ex) {
            throw new IllegalStateException("Invalid Base64 secret for JWT signing", ex);
        }
    }

    /**
     * Generates a JWT token using HS256 with the provided subject, claims and expiration.
     *
     * @param subject token subject (e.g., username)
     * @param claims custom claims to include in the token
     * @param expirationSeconds token expiration in seconds
     * @return signed JWT token string
     */
    public String generateToken(String subject, Map<String, Object> claims, long expirationSeconds) {
        Instant now = Instant.now();
        Instant expiry = now.plusSeconds(expirationSeconds);

        return Jwts.builder()
                .setSubject(subject)
                .setIssuer(issuer)
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(expiry))
                .addClaims(claims == null ? java.util.Collections.emptyMap() : claims)
                .signWith(secretKey, SignatureAlgorithm.HS256)
                .compact();
    }

    /**
     * Parses and validates a JWT token's signature and expiration.
     *
     * @param token JWT token string
     * @return decoded Claims if the token is valid
     * @throws IllegalArgumentException if token is null/blank
     * @throws SecurityException if signature validation fails
     * @throws ExpiredJwtException if the token is expired
     * @throws MalformedJwtException if the token is malformed
     */
    public Claims validateToken(String token) {
        if (token == null || token.isBlank()) {
            throw new IllegalArgumentException("JWT token must not be null or blank");
        }
        try {
            Jws<Claims> jws = Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .requireIssuer(issuer)
                    .build()
                    .parseClaimsJws(token);
            return jws.getBody();
        } catch (ExpiredJwtException ex) {
            log.warn("JWT expired: {}", ex.getMessage());
            throw ex;
        } catch (SecurityException ex) {
            log.warn("JWT signature validation failed: {}", ex.getMessage());
            throw ex;
        } catch (MalformedJwtException ex) {
            log.warn("JWT malformed: {}", ex.getMessage());
            throw ex;
        }
    }

    /**
     * Indicates whether the provided token is expired.
     *
     * @param token JWT token string
     * @return true if the token is expired, false otherwise
     */
    public boolean isTokenExpired(String token) {
        try {
            Claims claims = validateToken(token);
            Date expiration = claims.getExpiration();
            return expiration != null && expiration.before(new Date());
        } catch (ExpiredJwtException ex) {
            return true;
        }
    }
}


