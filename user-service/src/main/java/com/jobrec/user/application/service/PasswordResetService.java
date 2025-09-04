package com.jobrec.user.application.service;

import com.jobrec.user.domain.entity.PasswordResetToken;
import com.jobrec.user.domain.entity.User;
import com.jobrec.user.domain.repository.PasswordResetTokenRepository;
import com.jobrec.user.domain.repository.UserRepository;
import com.jobrec.user.infrastructure.mail.EmailService;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

/**
 * PasswordResetService
 *
 * Moved from AuthService: forgot password (issue token and email) and reset password.
 */
@Service
@RequiredArgsConstructor
public class PasswordResetService {

    private final UserRepository userRepository;
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final EmailService emailService;
    private final PasswordEncoder passwordEncoder;

    @Value("${frontend.base-url:http://localhost:5173}")
    private String frontendBaseUrl;

    @Transactional
    public void forgotPassword(String email) {
        User user = userRepository.findByEmail(email).orElseThrow(() -> new AuthService.AuthException("User not found"));
        String raw = java.util.UUID.randomUUID().toString();
        PasswordResetToken prt = PasswordResetToken.builder()
                .user(user)
                .token(raw)
                .expiresAt(LocalDateTime.now().plusHours(2))
                .build();
        passwordResetTokenRepository.save(prt);
        // Send users to the frontend reset password page; frontend will POST to backend with the token
        String link = String.format("%s/reset-password?token=%s", frontendBaseUrl, raw);
        emailService.sendVerificationEmail(user.getEmail(), link);
    }

    @Transactional
    public void resetPassword(String token, String newPassword) {
        if (newPassword == null || newPassword.length() < 8) throw new AuthService.AuthException("Password must be at least 8 characters");
        PasswordResetToken prt = passwordResetTokenRepository.findByToken(token).orElseThrow(() -> new AuthService.AuthException("Invalid token"));
        if (prt.getUsedAt() != null) throw new AuthService.AuthException("Token already used");
        if (prt.getExpiresAt().isBefore(LocalDateTime.now())) throw new AuthService.AuthException("Token expired");
        User user = prt.getUser();
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);
        prt.setUsedAt(LocalDateTime.now());
        passwordResetTokenRepository.save(prt);
    }
}


