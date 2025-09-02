package com.jobrec.user.controller;

import com.jobrec.user.service.AuthService;
import com.jobrec.user.dto.AuthResponse;
import com.jobrec.user.dto.LoginRequest;
import com.jobrec.user.dto.RegisterRequest;
import com.jobrec.user.dto.ResendVerificationRequest;
import com.jobrec.user.dto.LinkOAuthRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest request) {
        log.info("Registration attempt: username='{}', email='{}'", request.getUsername(), request.getEmail());
        authService.register(request);
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(java.util.Map.of("message", "Verification email sent"));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
        log.info("Login attempt: identifier='{}'", request.getUsernameOrEmail());
        AuthResponse response = authService.login(request);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/verify")
    public ResponseEntity<?> verify(@org.springframework.web.bind.annotation.RequestParam("token") String token,
                                    @org.springframework.web.bind.annotation.RequestParam(value = "autoLogin", defaultValue = "true") boolean autoLogin) {
        AuthResponse resp = authService.verifyEmail(token, autoLogin);
        if (resp == null) {
            return ResponseEntity.ok(java.util.Map.of("status", "verified"));
        }
        return ResponseEntity.ok(resp);
    }

    @PostMapping("/resend-verification")
    public ResponseEntity<?> resendVerification(@Valid @RequestBody ResendVerificationRequest request) {
        authService.resendVerification(request);
        return ResponseEntity.accepted().body(java.util.Map.of("message", "Verification email sent"));
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@RequestBody java.util.Map<String, String> body) {
        String email = body.get("email");
        authService.forgotPassword(email);
        return ResponseEntity.accepted().body(java.util.Map.of("message", "Reset email sent"));
    }

    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@RequestBody java.util.Map<String, String> body) {
        authService.resetPassword(body.get("token"), body.get("password"));
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/link-oauth")
    public ResponseEntity<AuthResponse> linkOAuth(@Valid @RequestBody LinkOAuthRequest request) {
        AuthResponse resp = authService.linkOAuth(request.getLinkToken());
        return ResponseEntity.ok(resp);
    }

    @PostMapping(value = "/link-oauth", consumes = org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<AuthResponse> linkOAuthForm(@org.springframework.web.bind.annotation.RequestParam("linkToken") String linkToken) {
        AuthResponse resp = authService.linkOAuth(linkToken);
        return ResponseEntity.ok(resp);
    }

    @GetMapping("/link-oauth")
    public ResponseEntity<AuthResponse> linkOAuthGet(@org.springframework.web.bind.annotation.RequestParam("linkToken") String linkToken) {
        AuthResponse resp = authService.linkOAuth(linkToken);
        return ResponseEntity.ok(resp);
    }

    @PutMapping("/password")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Void> setPassword(@AuthenticationPrincipal java.util.Map<String, Object> principal,
                                            @RequestBody java.util.Map<String, String> body) {
        String username = (String) principal.get("username");
        String newPassword = body.get("password");
        authService.setPassword(username, newPassword);
        return ResponseEntity.noContent().build();
    }

    @GetMapping(value = "/me", produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<java.util.Map<String, Object>> me(@AuthenticationPrincipal java.util.Map<String, Object> principal) {
        return ResponseEntity.ok(principal);
    }

    // TOTP endpoints removed per current requirements

    @ExceptionHandler(AuthService.AuthException.class)
    public ResponseEntity<String> handleAuthException(AuthService.AuthException ex) {
        return ResponseEntity.badRequest().body(ex.getMessage());
    }
}


