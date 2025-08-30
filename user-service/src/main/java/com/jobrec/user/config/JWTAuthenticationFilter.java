package com.jobrec.user.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.SecurityException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Map;

@Slf4j
@Component
@RequiredArgsConstructor
public class JWTAuthenticationFilter extends OncePerRequestFilter {

	private final JWTUtil jwtUtil;

	@Override
	protected void doFilterInternal(@NonNull HttpServletRequest request,
	                               @NonNull HttpServletResponse response,
	                               @NonNull FilterChain filterChain) throws ServletException, IOException {
		// Skip if already authenticated
		if (SecurityContextHolder.getContext().getAuthentication() != null) {
			filterChain.doFilter(request, response);
			return;
		}
		String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
		if (authHeader == null || !authHeader.startsWith("Bearer ")) {
			filterChain.doFilter(request, response);
			return;
		}

		String token = authHeader.substring(7);
		try {
			Claims claims = jwtUtil.validateToken(token);
			String username = claims.getSubject();
			String role = claims.get("role", String.class);
			Long userId = null;
			try {
				Object uidObj = claims.get("uid");
				if (uidObj instanceof Number) {
					userId = ((Number) uidObj).longValue();
				} else if (uidObj instanceof String) {
					userId = Long.parseLong((String) uidObj);
				}
			} catch (Exception ignored) {
				// ignore uid parsing failures
			}
			List<SimpleGrantedAuthority> authorities = role == null
					? Collections.emptyList()
					: List.of(new SimpleGrantedAuthority("ROLE_" + role));

			Map<String, Object> principal = userId == null
					? Map.of("username", username)
					: Map.of("username", username, "uid", userId);

			UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
					principal,
					null,
					authorities
			);
			authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
			SecurityContextHolder.getContext().setAuthentication(authentication);
		} catch (ExpiredJwtException ex) {
			log.info("JWT expired for request {} {}: {}", request.getMethod(), request.getRequestURI(), ex.getMessage());
			response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer error=\"invalid_token\", error_description=\"expired\"");
			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			SecurityContextHolder.clearContext();
		} catch (SecurityException ex) {
			log.warn("JWT signature validation failed: {}", ex.getMessage());
			response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer error=\"invalid_token\", error_description=\"signature_invalid\"");
			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			SecurityContextHolder.clearContext();
		} catch (MalformedJwtException ex) {
			log.warn("JWT malformed: {}", ex.getMessage());
			response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer error=\"invalid_token\", error_description=\"malformed\"");
			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			SecurityContextHolder.clearContext();
		} catch (IllegalArgumentException ex) {
			log.debug("JWT missing/blank: {}", ex.getMessage());
			response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer error=\"invalid_token\", error_description=\"missing_or_blank\"");
			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			SecurityContextHolder.clearContext();
		} catch (Exception ex) {
			log.debug("JWT processing failed: {}", ex.getMessage());
			response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer error=\"invalid_token\"");
			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			SecurityContextHolder.clearContext();
		}

		filterChain.doFilter(request, response);
	}
}


