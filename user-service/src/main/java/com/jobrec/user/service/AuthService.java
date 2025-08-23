package com.jobrec.user.service;

import com.jobrec.user.config.JWTUtil;
import com.jobrec.user.dto.AuthResponse;
import com.jobrec.user.dto.LoginRequest;
import com.jobrec.user.dto.RegisterRequest;
import com.jobrec.user.entity.User;
import com.jobrec.user.entity.UserProfile;
import com.jobrec.user.repository.UserProfileRepository;
import com.jobrec.user.repository.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;

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
    private final UserProfileRepository userProfileRepository;
    private final JWTUtil jwtUtil;
    private final BCryptPasswordEncoder passwordEncoder;

    @Value("${jwt.expirationSeconds:3600}")
    private long jwtExpirationSeconds;

    /**
     * Exception indicating an authentication or authorization failure.
     */
    public static class AuthException extends RuntimeException {
        public AuthException(String message) {
            super(message);
        }
    }

    /**
     * Registers a new user, ensuring unique username and email, and returns an AuthResponse with a JWT token.
     */
    @Transactional
    public AuthResponse register(String username,
                                 String email,
                                 String password,
                                 String firstName,
                                 String lastName) {
        log.info("Registering new user: username='{}', email='{}'", username, email);

        // Validate uniqueness
        Optional<User> existingByUsername = userRepository.findByUsername(username);
        if (existingByUsername.isPresent()) {
            throw new AuthException("Username already exists");
        }
        Optional<User> existingByEmail = userRepository.findByEmail(email);
        if (existingByEmail.isPresent()) {
            throw new AuthException("Email already exists");
        }

        // Persist user with hashed password
        String encodedPassword = passwordEncoder.encode(password);
        User user = User.builder()
                .username(username)
                .email(email)
                .password(encodedPassword)
                .build();
        User savedUser = userRepository.save(user);

        // Persist profile (1:1 mapped via @MapsId)
        UserProfile profile = UserProfile.builder()
                .user(savedUser)
                .firstName(firstName)
                .lastName(lastName)
                .build();
        userProfileRepository.save(profile);

        String token = buildTokenForUser(savedUser);
        return AuthResponse.builder()
                .id(savedUser.getId())
                .username(savedUser.getUsername())
                .email(savedUser.getEmail())
                .token(token)
                .build();
    }

    /**
     * Authenticates with username or email and returns an AuthResponse with a JWT token.
     */
    public AuthResponse login(String usernameOrEmail, String rawPassword) {
        log.info("Login attempt for identifier='{}'", usernameOrEmail);

        boolean isEmail = isEmail(usernameOrEmail);
        Optional<User> userOpt = isEmail
                ? userRepository.findByEmail(usernameOrEmail)
                : userRepository.findByUsername(usernameOrEmail);

        User user = userOpt.orElseThrow(() -> {
            log.warn("Login failed: user not found for identifier='{}'", usernameOrEmail);
            return new AuthException("Invalid credentials");
        });

        if (!passwordEncoder.matches(rawPassword, user.getPassword())) {
            log.warn("Login failed: invalid password for username='{}'", user.getUsername());
            throw new AuthException("Invalid credentials");
        }

        String token = buildTokenForUser(user);
        return AuthResponse.builder()
                .id(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .token(token)
                .build();
    }

    /**
     * Delegating overload for DTO-based registration.
     */
    public AuthResponse register(RegisterRequest request) {
        return register(request.getUsername(), request.getEmail(), request.getPassword(), request.getFirstName(), request.getLastName());
    }

    /**
     * Delegating overload for DTO-based login.
     */
    public AuthResponse login(LoginRequest request) {
        return login(request.getUsernameOrEmail(), request.getPassword());
    }

    private String buildTokenForUser(User user) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("role", user.getRole());
        claims.put("uid", user.getId());
        return jwtUtil.generateToken(user.getUsername(), claims, jwtExpirationSeconds);
    }

    private boolean isEmail(String input) {
        // Basic pattern; validation annotations handle strict checks elsewhere
        return Pattern.compile("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+$").matcher(input).matches();
    }
}
