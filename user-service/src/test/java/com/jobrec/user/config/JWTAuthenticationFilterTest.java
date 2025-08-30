package com.jobrec.user.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.impl.DefaultClaims;
import io.jsonwebtoken.security.SecurityException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
 
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class JWTAuthenticationFilterTest {

    private JWTUtil jwtUtil;
    private JWTAuthenticationFilter filter;
    private MockedStatic<SecurityContextHolder> mockedSch;
    private SecurityContext securityContext;

    @BeforeEach
    void setUp() {
        jwtUtil = mock(JWTUtil.class);
        filter = new JWTAuthenticationFilter(jwtUtil);
        mockedSch = Mockito.mockStatic(SecurityContextHolder.class, Mockito.CALLS_REAL_METHODS);
        securityContext = mock(SecurityContext.class);
        mockedSch.when(SecurityContextHolder::getContext).thenReturn(securityContext);
        when(securityContext.getAuthentication()).thenReturn(null);
    }

    @AfterEach
    void tearDown() {
        if (mockedSch != null) mockedSch.close();
    }

    @Test
    @DisplayName("does nothing if Authorization header is missing")
    void no_authorization_header() throws Exception {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);

        when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn(null);

        filter.doFilterInternal(request, response, chain);

        verify(chain).doFilter(request, response);
        verify(securityContext, never()).setAuthentication(any());
    }

    @Test
    @DisplayName("does nothing if Authorization header is not a Bearer token")
    void non_bearer_authorization() throws Exception {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);

        when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("Basic abc123");

        filter.doFilterInternal(request, response, chain);

        verify(chain).doFilter(request, response);
        verify(securityContext, never()).setAuthentication(any());
    }

    @Test
    @DisplayName("sets authentication for valid JWT")
    void sets_authentication_for_valid_jwt() throws Exception {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);

        when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer good.token");

        Claims claims = new DefaultClaims(Map.of(
                Claims.SUBJECT, "alice",
                "role", "USER",
                "uid", 1L
        ));
        when(jwtUtil.validateToken("good.token")).thenReturn(claims);

        filter.doFilterInternal(request, response, chain);

        verify(securityContext).setAuthentication(any(UsernamePasswordAuthenticationToken.class));
        verify(chain).doFilter(request, response);
    }

    @Test
    @DisplayName("expired token returns 401 and sets WWW-Authenticate header")
    void expired_token_unauthorized() throws Exception {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);

        when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer expired.token");
        doThrow(new ExpiredJwtException(null, null, "expired")).when(jwtUtil).validateToken("expired.token");

        filter.doFilterInternal(request, response, chain);

        verify(response).setHeader(eq(HttpHeaders.WWW_AUTHENTICATE), contains("invalid_token"));
        verify(response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        verify(securityContext, never()).setAuthentication(any());
        verify(chain).doFilter(request, response);
    }

    @Test
    @DisplayName("malformed token returns 401 with proper header")
    void malformed_token_unauthorized() throws Exception {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);

        when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer bad.token");
        doThrow(new MalformedJwtException("bad"))
                .when(jwtUtil).validateToken("bad.token");

        filter.doFilterInternal(request, response, chain);

        verify(response).setHeader(eq(HttpHeaders.WWW_AUTHENTICATE), contains("invalid_token"));
        verify(response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        verify(securityContext, never()).setAuthentication(any());
        verify(chain).doFilter(request, response);
    }

    @Test
    @DisplayName("token with invalid signature returns 401")
    void signature_invalid_unauthorized() throws Exception {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);

        when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer sig.bad");
        doThrow(new SecurityException("sig invalid"))
                .when(jwtUtil).validateToken("sig.bad");

        filter.doFilterInternal(request, response, chain);

        verify(response).setHeader(eq(HttpHeaders.WWW_AUTHENTICATE), contains("invalid_token"));
        verify(response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        verify(securityContext, never()).setAuthentication(any());
        verify(chain).doFilter(request, response);
    }
}


