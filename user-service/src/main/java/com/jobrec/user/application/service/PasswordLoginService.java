package com.jobrec.user.application.service;

import com.jobrec.user.api.dto.AuthResponse;
import com.jobrec.user.domain.entity.User;
import com.jobrec.user.domain.repository.UserRepository;
import com.jobrec.user.infrastructure.security.token.AuthTokenFactory;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.regex.Pattern;

/**
 * PasswordLoginService
 *
 * Moved from AuthService: username/email + password login, validations, audit updates, and AuthResponse creation.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class PasswordLoginService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthTokenFactory authTokenFactory;

    public AuthResponse login(String identifier, String rawPassword) {
        log.info("Login attempt for identifier='{}'", identifier);
        boolean isEmail = isEmail(identifier);
        Optional<User> userOpt = isEmail ? userRepository.findByEmail(identifier) : userRepository.findByUsername(identifier);
        User user = userOpt.orElseThrow(() -> new AuthService.AuthException("Invalid credentials"));
        if (Boolean.FALSE.equals(user.getPasswordLoginEnabled())) throw new AuthService.AuthException("Invalid credentials");
        if (user.getOauthProvider() == null && Boolean.FALSE.equals(user.getEmailVerified())) throw new AuthService.AuthException("Email not verified");
        if (!passwordEncoder.matches(rawPassword, user.getPassword())) throw new AuthService.AuthException("Invalid credentials");
        user.setLastLoginAt(java.time.LocalDateTime.now());
        user.setLastLoginIp(null);
        user.setLastLoginProvider(null);
        user.setLoginCount(java.util.Optional.ofNullable(user.getLoginCount()).orElse(0L) + 1);
        userRepository.save(user);
        return authTokenFactory.buildAuthResponse(user);
    }

    private boolean isEmail(String input) { return Pattern.compile("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+$").matcher(input).matches(); }
}


