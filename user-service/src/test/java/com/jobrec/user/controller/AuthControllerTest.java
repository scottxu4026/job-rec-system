package com.jobrec.user.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jobrec.user.config.JWTAuthenticationFilter;
import com.jobrec.user.dto.AuthResponse;
import com.jobrec.user.dto.LoginRequest;
import com.jobrec.user.dto.RegisterRequest;
import com.jobrec.user.service.AuthService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.doThrow;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(controllers = AuthController.class)
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
	@DisplayName("POST /auth/register returns 201 and body")
	void register_created() throws Exception {
		AuthResponse resp = AuthResponse.builder()
				.token("jwt")
				.username("alice")
				.email("alice@example.com")
				.role("USER")
				.uid(1L)
				.build();
		given(authService.register(any(RegisterRequest.class))).willReturn(resp);

		RegisterRequest req = RegisterRequest.builder()
				.username("alice")
				.email("alice@example.com")
				.password("pw")
				.firstName("Alice")
				.lastName("Doe")
				.build();

		mockMvc.perform(post("/auth/register")
					.contentType(MediaType.APPLICATION_JSON)
					.content(objectMapper.writeValueAsString(req)))
				.andExpect(status().isCreated())
				.andExpect(jsonPath("$.username", is("alice")))
				.andExpect(jsonPath("$.token", is("jwt")));
	}

	@Test
	@DisplayName("POST /auth/login returns 200 and body")
	void login_ok() throws Exception {
		AuthResponse resp = AuthResponse.builder()
				.token("jwt-2")
				.username("bob")
				.email("bob@example.com")
				.role("USER")
				.uid(2L)
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
				.andExpect(jsonPath("$.username", is("bob")))
				.andExpect(jsonPath("$.token", is("jwt-2")));
	}

	@Test
	@DisplayName("POST /auth/register fails validation (missing fields/invalid email)")
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
				.andExpect(status().isBadRequest());
	}

	@Test
	@DisplayName("POST /auth/login handles AuthException -> 400 with message")
	void login_authException_returns400() throws Exception {
		doThrow(new AuthService.AuthException("Invalid credentials")).when(authService).login(any(LoginRequest.class));

		LoginRequest req = LoginRequest.builder()
				.identifier("unknown")
				.password("bad")
				.build();

		mockMvc.perform(post("/auth/login")
					.contentType(MediaType.APPLICATION_JSON)
					.content(objectMapper.writeValueAsString(req)))
				.andExpect(status().isBadRequest())
				.andExpect(content().string("Invalid credentials"));
	}
}


