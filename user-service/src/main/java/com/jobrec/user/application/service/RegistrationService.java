package com.jobrec.user.application.service;

import com.jobrec.user.api.dto.RegisterRequest;
import com.jobrec.user.api.dto.ResendVerificationRequest;
import com.jobrec.user.domain.entity.User;
import com.jobrec.user.domain.entity.UserProfile;
import com.jobrec.user.domain.entity.VerificationToken;
import com.jobrec.user.domain.repository.UserProfileRepository;
import com.jobrec.user.domain.repository.UserRepository;
import com.jobrec.user.domain.repository.VerificationTokenRepository;
import com.jobrec.user.infrastructure.mail.EmailService;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;

/**
 * RegistrationService
 *
 * Moved from AuthService: user registration, issuing verification token, and resending verification emails.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class RegistrationService {

    private final UserRepository userRepository;
    private final UserProfileRepository userProfileRepository;
    private final VerificationTokenRepository verificationTokenRepository;
    private final EmailService emailService;
    private final PasswordEncoder passwordEncoder;
    private final ResendThrottleService resendThrottleService;

    @Value("${frontend.base-url:http://localhost:5173}")
    private String frontendBaseUrl;

    @Transactional
    public void register(String username,
                         String email,
                         String password,
                         String firstName,
                         String lastName,
                         boolean termsAccepted) {
        log.info("Registering new user: username='{}', email='{}'", username, email);
        if (!termsAccepted) throw new AuthService.AuthException("Terms must be accepted");
        Optional<User> existingByUsername = userRepository.findByUsername(username);
        if (existingByUsername.isPresent()) throw new AuthService.AuthException("Username already exists");
        Optional<User> existingByEmail = userRepository.findByEmail(email);
        if (existingByEmail.isPresent()) throw new AuthService.AuthException("Email already exists");
        String encodedPassword = passwordEncoder.encode(password);
        User user = User.builder()
                .username(username)
                .email(email)
                .password(encodedPassword)
                .emailVerified(false)
                .termsAcceptedAt(LocalDateTime.now())
                .build();
        User savedUser = userRepository.save(user);
        UserProfile profile = UserProfile.builder()
                .user(savedUser)
                .firstName(firstName)
                .lastName(lastName)
                .build();
        userProfileRepository.save(profile);
        issueAndSendVerificationToken(savedUser);
    }

    public void register(RegisterRequest request) {
        register(request.getUsername(), request.getEmail(), request.getPassword(), request.getFirstName(), request.getLastName(), request.isTermsAccepted());
    }

    @Transactional
    public void resendVerification(ResendVerificationRequest req) {
        User user = userRepository.findByEmail(req.getEmail()).orElseThrow(() -> new AuthService.AuthException("User not found"));
        if (Boolean.TRUE.equals(user.getEmailVerified())) return;
        if (!resendThrottleService.allow(user.getEmail())) throw new AuthService.AuthException("Too many requests");
        issueAndSendVerificationToken(user);
    }

    private void issueAndSendVerificationToken(User user) {
        String raw = java.util.UUID.randomUUID().toString();
        VerificationToken vt = VerificationToken.builder()
                .user(user)
                .token(raw)
                .expiresAt(LocalDateTime.now().plusHours(24))
                .build();
        verificationTokenRepository.save(vt);
        // Send users to the frontend verification page; frontend will call backend and redirect appropriately
        String link = String.format("%s/verify?token=%s&autoLogin=false", frontendBaseUrl, raw);
        emailService.sendVerificationEmail(user.getEmail(), link);
    }
}


