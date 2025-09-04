package com.jobrec.user.infrastructure.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SecurityException;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

/**
 * JWTUtil
 *
 * Provides JWT creation and validation using the JJWT library.
 * This component is stateless and thread-safe once initialized.
 */
@Component
public class JWTUtil {
    private static final Logger log = LoggerFactory.getLogger(JWTUtil.class);

    @Value("${jwt.secret}")
    private String base64Secret;

    @Value("${jwt.issuer:jobrec-auth}")
    private String issuer;

    @Value("${jwt.audience:jobrec-client}")
    private String audience;

    @Value("${jwt.expirationSeconds:3600}")
    private long defaultExpirationSeconds;

    private SecretKey secretKey;

    @PostConstruct
    void init() {
        // Load the signing key from base64-encoded secret
        try {
            byte[] keyBytes = java.util.Base64.getDecoder().decode(base64Secret.getBytes(StandardCharsets.UTF_8));
            if (keyBytes.length < 32) { // 256-bit minimum for HS256
                throw new IllegalStateException("JWT secret must be at least 32 bytes after Base64 decoding");
            }
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
                .setId(UUID.randomUUID().toString())
                .setAudience(audience)
                .setSubject(subject)
                .setIssuer(issuer)
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(expiry))
                .addClaims(claims == null ? java.util.Collections.emptyMap() : claims)
                .signWith(secretKey, SignatureAlgorithm.HS256)
                .compact();
    }

    /**
     * Generates a JWT token using default expiration configured by jwt.expirationSeconds.
     *
     * @param subject token subject (e.g., username)
     * @param claims custom claims to include in the token
     * @return signed JWT token string
     */
    public String generateToken(String subject, Map<String, Object> claims) {
        return generateToken(subject, claims, defaultExpirationSeconds);
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
     * Extracts the subject from a valid JWT token.
     *
     * @param token JWT token string
     * @return the subject contained within the token
     * @throws IllegalArgumentException if token is null/blank
     * @throws SecurityException if signature validation fails
     * @throws ExpiredJwtException if the token is expired
     * @throws MalformedJwtException if the token is malformed
     */
    public String extractSubject(String token) {
        Claims claims = validateToken(token);
        return claims.getSubject();
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


