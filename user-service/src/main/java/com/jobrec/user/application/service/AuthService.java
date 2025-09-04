package com.jobrec.user.application.service;

import com.jobrec.user.api.dto.AuthResponse;
import com.jobrec.user.api.dto.LoginRequest;
import com.jobrec.user.api.dto.RegisterRequest;
import com.jobrec.user.api.dto.ResendVerificationRequest;
import com.jobrec.user.domain.entity.User;
import com.jobrec.user.domain.repository.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

// no local token building helpers remain

/**
 * AuthService
 *
 * Provides registration and login functionality, producing JWT-based authentication tokens.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    private final RegistrationService registrationService;
    private final VerificationService verificationService;
    private final PasswordLoginService passwordLoginService;
    private final PasswordResetService passwordResetService;
    private final OAuthLinkService oAuthLinkService;

    public static class AuthException extends RuntimeException { public AuthException(String message) { super(message); } }

    @Transactional
    public void register(String username,
                         String email,
                         String password,
                         String firstName,
                         String lastName,
                         boolean termsAccepted) {
        registrationService.register(username, email, password, firstName, lastName, termsAccepted);
    }

    // moved to RegistrationService

    @Transactional
    public void forgotPassword(String email) { passwordResetService.forgotPassword(email); }

    @Transactional
    public void resetPassword(String token, String newPassword) { passwordResetService.resetPassword(token, newPassword); }

    public AuthResponse login(String usernameOrEmail, String rawPassword) { return passwordLoginService.login(usernameOrEmail, rawPassword); }

    public void register(RegisterRequest request) { registrationService.register(request); }

    public AuthResponse login(LoginRequest request) { return passwordLoginService.login(request.getUsernameOrEmail(), request.getPassword()); }

    @Transactional
    public AuthResponse verifyEmail(String token, boolean autoLogin) { return verificationService.verifyEmail(token, autoLogin); }

    @Transactional
    public void resendVerification(ResendVerificationRequest req) { registrationService.resendVerification(req); }

    @Transactional
    public AuthResponse linkOAuth(String linkToken) { return oAuthLinkService.linkOAuth(linkToken); }

    /**
     * Complete registration after OAuth2 by providing registration token (containing email + provider), username, and password.
     */
    @Transactional
    public AuthResponse registerOAuth(String registrationToken, String username, String rawPassword, boolean termsAccepted) { return oAuthLinkService.registerOAuth(registrationToken, username, rawPassword, termsAccepted); }

    // delegated to sub-services

    @Transactional
    public void setPassword(String username, String newPassword) {
        if (newPassword == null || newPassword.length() < 8) throw new AuthException("Password must be at least 8 characters");
        User user = userRepository.findByUsername(username).orElseThrow(() -> new AuthException("User not found"));
        user.setPassword(passwordEncoder.encode(newPassword));
        user.setPasswordLoginEnabled(true);
        userRepository.save(user);
    }

    // helpers removed

    // TOTP management removed
}
