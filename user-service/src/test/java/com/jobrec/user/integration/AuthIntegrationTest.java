package com.jobrec.user.integration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jobrec.user.dto.AuthResponse;
import com.jobrec.user.dto.LoginRequest;
import com.jobrec.user.dto.RegisterRequest;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Import;
import org.springframework.http.*;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@Import(AuthIntegrationTest.TestSecuredController.class)
class AuthIntegrationTest {

    @Autowired
    private TestRestTemplate restTemplate;

    @LocalServerPort
    private int port;

    @Autowired
    private ObjectMapper objectMapper;

    private static String jwtToken;
    private static final String UNIQUE = String.valueOf(System.currentTimeMillis());
    private static final String USERNAME = "alice_" + UNIQUE;
    private static final String EMAIL = "alice_" + UNIQUE + "@example.com";

    private String url(String path) {
        return "http://localhost:" + port + path;
    }

    @Test
    @Order(1)
    void userRegistration() throws Exception {
        RegisterRequest register = RegisterRequest.builder()
                .username(USERNAME)
                .email(EMAIL)
                .password("password123")
                .firstName("Alice")
                .lastName("Doe")
                .build();

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<String> entity = new HttpEntity<>(objectMapper.writeValueAsString(register), headers);

        ResponseEntity<AuthResponse> response = restTemplate.exchange(
                url("/auth/register"),
                HttpMethod.POST,
                entity,
                AuthResponse.class
        );

        assertEquals(HttpStatus.CREATED, response.getStatusCode());
        AuthResponse body1 = response.getBody();
        assertNotNull(body1);
        assertNotNull(body1.getToken());
        assertEquals(USERNAME, body1.getUsername());
    }

    @Test
    @Order(2)
    void userLogin() throws Exception {
        LoginRequest login = LoginRequest.builder()
                .identifier(USERNAME)
                .password("password123")
                .build();

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<String> entity = new HttpEntity<>(objectMapper.writeValueAsString(login), headers);

        ResponseEntity<AuthResponse> response = restTemplate.exchange(
                url("/auth/login"),
                HttpMethod.POST,
                entity,
                AuthResponse.class
        );

        assertEquals(HttpStatus.OK, response.getStatusCode());
        AuthResponse body2 = response.getBody();
        assertNotNull(body2);
        assertNotNull(body2.getToken());
        jwtToken = body2.getToken();
    }

    @Test
    @Order(3)
    void accessSecuredEndpoint() {
        assertNotNull(jwtToken, "JWT token must be available from login step");

        HttpHeaders headers = new HttpHeaders();
        headers.set(HttpHeaders.AUTHORIZATION, "Bearer " + jwtToken);
        HttpEntity<Void> entity = new HttpEntity<>(headers);

        ResponseEntity<Map<String, Object>> response = restTemplate.exchange(
                url("/auth/test-secured"),
                HttpMethod.GET,
                entity,
                new ParameterizedTypeReference<Map<String, Object>>() {}
        );

        assertEquals(HttpStatus.OK, response.getStatusCode());
        Map<String, Object> body3 = response.getBody();
        assertNotNull(body3);
        assertEquals(USERNAME, body3.get("username"));
    }

    @RestController
    @RequestMapping("/auth")
    static class TestSecuredController {
        @GetMapping("/test-secured")
        @PreAuthorize("isAuthenticated()")
        public Map<String, Object> me(@AuthenticationPrincipal Map<String, Object> principal) {
            return principal;
        }
    }
}


