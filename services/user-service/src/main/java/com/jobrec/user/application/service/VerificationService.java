package com.jobrec.user.application.service;

import com.jobrec.user.api.dto.AuthResponse;
import com.jobrec.user.domain.entity.User;
import com.jobrec.user.domain.entity.VerificationToken;
import com.jobrec.user.domain.repository.UserRepository;
import com.jobrec.user.domain.repository.VerificationTokenRepository;
import com.jobrec.user.infrastructure.security.token.AuthTokenFactory;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

/**
 * VerificationService
 *
 * Moved from AuthService: email verification token validation, status update, and optional auto-login.
 */
@Service
@RequiredArgsConstructor
public class VerificationService {

    private final VerificationTokenRepository verificationTokenRepository;
    private final UserRepository userRepository;
    private final AuthTokenFactory authTokenFactory;

    @Transactional
    public AuthResponse verifyEmail(String token, boolean autoLogin) {
        VerificationToken vt = verificationTokenRepository.findByToken(token).orElseThrow(() -> new AuthService.AuthException("Invalid token"));
        if (vt.getUsedAt() != null) {
            // Make verification idempotent: if token was already used, consider it success
            User alreadyVerifiedUser = vt.getUser();
            if (!autoLogin) return null;
            return authTokenFactory.buildAuthResponse(alreadyVerifiedUser);
        }
        if (vt.getExpiresAt().isBefore(LocalDateTime.now())) throw new AuthService.AuthException("Token expired");
        User user = vt.getUser();
        user.setEmailVerified(true);
        userRepository.save(user);
        vt.setUsedAt(LocalDateTime.now());
        verificationTokenRepository.save(vt);
        if (!autoLogin) return null;
        return authTokenFactory.buildAuthResponse(user);
    }
}


