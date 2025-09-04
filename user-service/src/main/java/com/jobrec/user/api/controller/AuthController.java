package com.jobrec.user.api.controller;

import com.jobrec.user.application.service.AuthService;
import com.jobrec.user.api.dto.AuthResponse;
import com.jobrec.user.api.dto.ApiResponse;
import com.jobrec.user.api.dto.LoginRequest;
import com.jobrec.user.api.dto.RegisterRequest;
import com.jobrec.user.api.dto.ResendVerificationRequest;
import com.jobrec.user.api.dto.LinkOAuthRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
// removed unused import
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import com.jobrec.user.infrastructure.security.principal.AuthPrincipal;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Auth", description = "Authentication and account endpoints")
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    @Operation(summary = "Register new user", description = "Initiates registration and sends verification email",
            responses = {
                    @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "202", description = "Verification email sent",
                            content = @Content(schema = @Schema(implementation = com.jobrec.user.api.dto.ApiResponse.class)))
            })
    public ResponseEntity<ApiResponse<Void>> register(@Valid @RequestBody RegisterRequest request) {
        log.info("Registration attempt: username='{}', email='{}'", request.getUsername(), request.getEmail());
        authService.register(request);
        return ResponseEntity.status(HttpStatus.ACCEPTED)
                .body(ApiResponse.success("Verification email sent"));
    }

    @PostMapping("/login")
    @Operation(summary = "Login with username/email and password",
            responses = {
                    @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "Login successful",
                            content = @Content(schema = @Schema(implementation = com.jobrec.user.api.dto.ApiResponse.class))),
                    @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "401", description = "Unauthorized")
            })
    public ResponseEntity<ApiResponse<AuthResponse>> login(@Valid @RequestBody LoginRequest request) {
        log.info("Login attempt: identifier='{}'", request.getUsernameOrEmail());
        AuthResponse response = authService.login(request);
        return ResponseEntity.ok(ApiResponse.success("Login successful", response));
    }

    @GetMapping("/verify")
    @Operation(summary = "Verify email using token",
            responses = {@io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "Verified")})
    public ResponseEntity<ApiResponse<?>> verify(@org.springframework.web.bind.annotation.RequestParam("token") String token,
                                    @org.springframework.web.bind.annotation.RequestParam(value = "autoLogin", defaultValue = "true") boolean autoLogin) {
        AuthResponse resp = authService.verifyEmail(token, autoLogin);
        if (resp == null) {
            return ResponseEntity.ok(ApiResponse.success("Email verified"));
        }
        return ResponseEntity.ok(ApiResponse.success("Email verified", resp));
    }

    @PostMapping("/resend-verification")
    @Operation(summary = "Resend verification email",
            responses = {@io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "202", description = "Sent")})
    public ResponseEntity<ApiResponse<Void>> resendVerification(@Valid @RequestBody ResendVerificationRequest request) {
        authService.resendVerification(request);
        return ResponseEntity.accepted().body(ApiResponse.success("Verification email sent"));
    }

    @PostMapping("/forgot-password")
    @Operation(summary = "Request password reset email")
    public ResponseEntity<ApiResponse<Void>> forgotPassword(@RequestBody java.util.Map<String, String> body) {
        String email = body.get("email");
        authService.forgotPassword(email);
        return ResponseEntity.accepted().body(ApiResponse.success("Reset email sent"));
    }

    @PostMapping(path = "/register-oauth", consumes = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "Complete registration after OAuth2", description = "Provide registration token from OAuth2 flow, desired username, password, and termsAccepted")
    public ResponseEntity<ApiResponse<AuthResponse>> registerOauthJson(@RequestBody java.util.Map<String, Object> body) {
        String regToken = (String) body.get("regToken");
        String username = (String) body.get("username");
        String password = (String) body.get("password");
        boolean termsAccepted = Boolean.TRUE.equals(body.get("termsAccepted"));
        AuthResponse resp = authService.registerOAuth(regToken, username, password, termsAccepted);
        return ResponseEntity.ok(ApiResponse.success("Registration successful", resp));
    }

    @PostMapping(path = "/register-oauth", consumes = org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    @Operation(summary = "Complete registration after OAuth2 (form)")
    public ResponseEntity<ApiResponse<AuthResponse>> registerOauthForm(
            @org.springframework.web.bind.annotation.RequestParam("regToken") String regToken,
            @org.springframework.web.bind.annotation.RequestParam("username") String username,
            @org.springframework.web.bind.annotation.RequestParam("password") String password,
            @org.springframework.web.bind.annotation.RequestParam(value = "termsAccepted", defaultValue = "false") boolean termsAccepted) {
        AuthResponse resp = authService.registerOAuth(regToken, username, password, termsAccepted);
        return ResponseEntity.ok(ApiResponse.success("Registration successful", resp));
    }

    @PostMapping("/reset-password")
    @Operation(summary = "Reset password with token")
    public ResponseEntity<ApiResponse<Void>> resetPassword(@RequestBody java.util.Map<String, String> body) {
        authService.resetPassword(body.get("token"), body.get("password"));
        return ResponseEntity.status(HttpStatus.NO_CONTENT).body(null);
    }

    @PostMapping("/link-oauth")
    @Operation(summary = "Link OAuth provider to existing account")
    public ResponseEntity<ApiResponse<AuthResponse>> linkOAuth(@Valid @RequestBody LinkOAuthRequest request) {
        AuthResponse resp = authService.linkOAuth(request.getLinkToken());
        return ResponseEntity.ok(ApiResponse.success("Linked successfully", resp));
    }

    @PostMapping(value = "/link-oauth", consumes = org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    @Operation(summary = "Link OAuth (form)")
    public ResponseEntity<ApiResponse<AuthResponse>> linkOAuthForm(@org.springframework.web.bind.annotation.RequestParam("linkToken") String linkToken) {
        AuthResponse resp = authService.linkOAuth(linkToken);
        return ResponseEntity.ok(ApiResponse.success("Linked successfully", resp));
    }

    @GetMapping("/link-oauth")
    @Operation(summary = "Link OAuth (GET)")
    public ResponseEntity<ApiResponse<AuthResponse>> linkOAuthGet(@org.springframework.web.bind.annotation.RequestParam("linkToken") String linkToken) {
        AuthResponse resp = authService.linkOAuth(linkToken);
        return ResponseEntity.ok(ApiResponse.success("Linked successfully", resp));
    }

    @PutMapping("/password")
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "Set password for current user")
    public ResponseEntity<ApiResponse<Void>> setPassword(@AuthenticationPrincipal java.util.Map<String, Object> principal,
                                            @RequestBody java.util.Map<String, String> body) {
        String username = (String) principal.get("username");
        String newPassword = body.get("password");
        authService.setPassword(username, newPassword);
        return ResponseEntity.status(HttpStatus.NO_CONTENT).body(null);
    }

    @GetMapping(value = "/me", produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "Get current user from JWT")
    public ResponseEntity<ApiResponse<java.util.Map<String, Object>>> me(@AuthenticationPrincipal AuthPrincipal principal) {
        java.util.Map<String, Object> data = java.util.Map.of(
                "id", principal.id(),
                "username", principal.username(),
                "email", principal.email(),
                "role", principal.role()
        );
        return ResponseEntity.ok(ApiResponse.success("Current user", data));
    }

    // TOTP endpoints removed per current requirements

    @GetMapping("/status")
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "Check account/email verification status")
    public ResponseEntity<ApiResponse<java.util.Map<String, Object>>> status(@AuthenticationPrincipal AuthPrincipal principal) {
        return ResponseEntity.ok(ApiResponse.success("Status", java.util.Map.of("authenticated", true)));
    }
}


