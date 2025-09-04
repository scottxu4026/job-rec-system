package com.jobrec.user.integration;

import com.fasterxml.jackson.databind.ObjectMapper;
// import removed
import com.jobrec.user.api.dto.LoginRequest;
import com.jobrec.user.api.dto.RegisterRequest;
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
import com.jobrec.user.domain.repository.UserRepository;
import com.jobrec.user.domain.entity.User;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
@TestPropertySource(properties = {
        "spring.datasource.url=jdbc:h2:mem:userdb;DB_CLOSE_DELAY=-1;MODE=PostgreSQL",
        "spring.datasource.driver-class-name=org.h2.Driver",
        "spring.jpa.hibernate.ddl-auto=create-drop",
        "spring.jpa.show-sql=false"
})
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@Import(AuthIntegrationTest.TestSecuredController.class)
class AuthIntegrationTest {

    @Autowired
    private TestRestTemplate restTemplate;

    @LocalServerPort
    private int port;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private UserRepository userRepository;

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
                .termsAccepted(true)
                .build();

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<String> entity = new HttpEntity<>(objectMapper.writeValueAsString(register), headers);

        ResponseEntity<com.jobrec.user.api.dto.ApiResponse<Void>> response = restTemplate.exchange(
                url("/auth/register"),
                HttpMethod.POST,
                entity,
                new ParameterizedTypeReference<com.jobrec.user.api.dto.ApiResponse<Void>>() {}
        );

        assertEquals(HttpStatus.ACCEPTED, response.getStatusCode());
        assertNotNull(response.getBody());
    }

    @Test
    @Order(2)
    void userLogin() throws Exception {
        // mark user as verified to allow password login
        User u = userRepository.findByUsername(USERNAME).orElseThrow();
        u.setEmailVerified(true);
        userRepository.save(u);

        LoginRequest login = LoginRequest.builder()
                .identifier(USERNAME)
                .password("password123")
                .build();

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<String> entity = new HttpEntity<>(objectMapper.writeValueAsString(login), headers);

        ResponseEntity<com.jobrec.user.api.dto.ApiResponse<Object>> response = restTemplate.exchange(
                url("/auth/login"),
                HttpMethod.POST,
                entity,
                new ParameterizedTypeReference<com.jobrec.user.api.dto.ApiResponse<Object>>() {}
        );

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        java.util.LinkedHashMap<?,?> data = (java.util.LinkedHashMap<?,?>) response.getBody().getData();
        assertNotNull(data);
        jwtToken = (String) data.get("token");
        assertNotNull(jwtToken);
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
        public Map<String, Object> me(@AuthenticationPrincipal com.jobrec.user.infrastructure.security.principal.AuthPrincipal principal) {
            return java.util.Map.of("username", principal.username());
        }
    }
}


