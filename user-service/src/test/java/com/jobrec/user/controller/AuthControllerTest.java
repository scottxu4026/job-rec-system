package com.jobrec.user.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jobrec.user.infrastructure.security.jwt.JWTAuthenticationFilter;
import com.jobrec.user.api.dto.AuthResponse;
import com.jobrec.user.api.dto.LoginRequest;
import com.jobrec.user.api.dto.RegisterRequest;
import com.jobrec.user.application.service.AuthService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.doThrow;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(controllers = com.jobrec.user.api.controller.AuthController.class)
@AutoConfigureMockMvc(addFilters = false)
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private AuthService authService;

    @MockBean
    private JWTAuthenticationFilter jwtAuthenticationFilter;

    @Test
    @DisplayName("POST /auth/register returns 202 and verification message")
    void register_created() throws Exception {
        RegisterRequest req = RegisterRequest.builder()
                .username("alice")
                .email("alice@example.com")
                .password("pw")
                .firstName("Alice")
                .lastName("Doe")
                .termsAccepted(true)
                .build();

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.message", is("Verification email sent")));
    }

    @Test
    @DisplayName("POST /auth/login returns 200 with unified response")
    void login_ok() throws Exception {
        AuthResponse resp = AuthResponse.builder()
                .token("jwt-2")
                .expiresAt(123L)
                .user(AuthResponse.UserInfo.builder()
                        .id(2L)
                        .email("bob@example.com")
                        .role("USER")
                        .username("bob")
                        .build())
                .build();
        given(authService.login(any(LoginRequest.class))).willReturn(resp);

        LoginRequest req = LoginRequest.builder()
                .identifier("bob")
                .password("pw")
                .build();

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status", is("success")))
                .andExpect(jsonPath("$.data.user.username", is("bob")))
                .andExpect(jsonPath("$.data.token", is("jwt-2")));
    }

    @Test
    @DisplayName("POST /auth/register fails validation -> 422 with error body")
    void register_validation_errors() throws Exception {
        RegisterRequest bad = RegisterRequest.builder()
                .username("")
                .email("not-an-email")
                .password("")
                .firstName("")
                .lastName("")
                .build();

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(bad)))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.status", is("error")));
    }

    @Test
    @DisplayName("POST /auth/login handles AuthException -> 422 with message")
    void login_authException_returns400() throws Exception {
        doThrow(new AuthService.AuthException("Invalid credentials")).when(authService).login(any(LoginRequest.class));

        LoginRequest req = LoginRequest.builder()
                .identifier("unknown")
                .password("bad")
                .build();

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.message", is("Invalid credentials")));
    }
}
