package com.jobrec.user.controller;

import com.jobrec.user.dto.AuthResponse;
import com.jobrec.user.dto.LoginRequest;
import com.jobrec.user.dto.RegisterRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * AuthController
 *
 * REST controller placeholder exposing authentication endpoints
 * for user registration and login.
 * Methods are stubs with no implementation yet.
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    /**
     * Registers a new user.
     * Implementation will be added later.
     *
     * @param request registration request payload
     * @return authentication response with token
     */
    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@RequestBody RegisterRequest request) {
        return null;
    }

    /**
     * Authenticates a user and returns a token.
     * Implementation will be added later.
     *
     * @param request login request payload
     * @return authentication response with token
     */
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody LoginRequest request) {
        return null;
    }
}


