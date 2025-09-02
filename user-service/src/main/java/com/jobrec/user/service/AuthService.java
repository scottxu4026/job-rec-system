package com.jobrec.user.service;

import com.jobrec.user.config.JWTUtil;
import com.jobrec.user.config.LinkTokenService;
import com.jobrec.user.dto.AuthResponse;
import com.jobrec.user.dto.LoginRequest;
import com.jobrec.user.dto.RegisterRequest;
import com.jobrec.user.dto.ResendVerificationRequest;
import com.jobrec.user.entity.User;
import com.jobrec.user.entity.UserProfile;
import com.jobrec.user.entity.VerificationToken;
import com.jobrec.user.entity.PasswordResetToken;
import com.jobrec.user.repository.UserProfileRepository;
import com.jobrec.user.repository.UserRepository;
import com.jobrec.user.repository.VerificationTokenRepository;
import com.jobrec.user.repository.PasswordResetTokenRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
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
    private final PasswordEncoder passwordEncoder;
    private final VerificationTokenRepository verificationTokenRepository;
    private final EmailService emailService;
    private final LinkTokenService linkTokenService;
    private final ResendThrottleService resendThrottleService;
    private final PasswordResetTokenRepository passwordResetTokenRepository;

    @Value("${jwt.expirationSeconds:3600}")
    private long jwtExpirationSeconds;

    public static class AuthException extends RuntimeException { public AuthException(String message) { super(message); } }

    @Transactional
    public void register(String username,
                         String email,
                         String password,
                         String firstName,
                         String lastName,
                         boolean termsAccepted) {
        log.info("Registering new user: username='{}', email='{}'", username, email);
        if (!termsAccepted) throw new AuthException("Terms must be accepted");
        Optional<User> existingByUsername = userRepository.findByUsername(username);
        if (existingByUsername.isPresent()) throw new AuthException("Username already exists");
        Optional<User> existingByEmail = userRepository.findByEmail(email);
        if (existingByEmail.isPresent()) throw new AuthException("Email already exists");
        String encodedPassword = passwordEncoder.encode(password);
        User user = User.builder().username(username).email(email).password(encodedPassword).emailVerified(false).termsAcceptedAt(java.time.LocalDateTime.now()).build();
        User savedUser = userRepository.save(user);
        UserProfile profile = UserProfile.builder().user(savedUser).firstName(firstName).lastName(lastName).build();
        userProfileRepository.save(profile);
        issueAndSendVerificationToken(savedUser);
    }

    private void issueAndSendVerificationToken(User user) {
        String raw = java.util.UUID.randomUUID().toString();
        VerificationToken vt = VerificationToken.builder().user(user).token(raw).expiresAt(java.time.LocalDateTime.now().plusHours(24)).build();
        verificationTokenRepository.save(vt);
        String link = String.format("http://localhost:8080/auth/verify?token=%s", raw);
        emailService.sendVerificationEmail(user.getEmail(), link);
    }

    @Transactional
    public void forgotPassword(String email) {
        User user = userRepository.findByEmail(email).orElseThrow(() -> new AuthException("User not found"));
        String raw = java.util.UUID.randomUUID().toString();
        PasswordResetToken prt = PasswordResetToken.builder()
                .user(user)
                .token(raw)
                .expiresAt(java.time.LocalDateTime.now().plusHours(2))
                .build();
        passwordResetTokenRepository.save(prt);
        String link = String.format("http://localhost:8080/auth/reset-password?token=%s", raw);
        emailService.sendVerificationEmail(user.getEmail(), link);
    }

    @Transactional
    public void resetPassword(String token, String newPassword) {
        if (newPassword == null || newPassword.length() < 8) throw new AuthException("Password must be at least 8 characters");
        PasswordResetToken prt = passwordResetTokenRepository.findByToken(token).orElseThrow(() -> new AuthException("Invalid token"));
        if (prt.getUsedAt() != null) throw new AuthException("Token already used");
        if (prt.getExpiresAt().isBefore(java.time.LocalDateTime.now())) throw new AuthException("Token expired");
        User user = prt.getUser();
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);
        prt.setUsedAt(java.time.LocalDateTime.now());
        passwordResetTokenRepository.save(prt);
    }

    public AuthResponse login(String usernameOrEmail, String rawPassword) {
        log.info("Login attempt for identifier='{}'", usernameOrEmail);
        boolean isEmail = isEmail(usernameOrEmail);
        Optional<User> userOpt = isEmail ? userRepository.findByEmail(usernameOrEmail) : userRepository.findByUsername(usernameOrEmail);
        User user = userOpt.orElseThrow(() -> new AuthException("Invalid credentials"));
        if (Boolean.FALSE.equals(user.getPasswordLoginEnabled())) throw new AuthException("Invalid credentials");
        if (user.getOauthProvider() == null && Boolean.FALSE.equals(user.getEmailVerified())) throw new AuthException("Email not verified");
        if (!passwordEncoder.matches(rawPassword, user.getPassword())) throw new AuthException("Invalid credentials");
        // TOTP removed; no OTP required
        user.setLastLoginAt(java.time.LocalDateTime.now());
        user.setLastLoginIp(null);
        user.setLastLoginProvider(null);
        user.setLoginCount(java.util.Optional.ofNullable(user.getLoginCount()).orElse(0L) + 1);
        userRepository.save(user);
        String token = buildTokenForUser(user);
        return AuthResponse.builder().token(token).username(user.getUsername()).email(user.getEmail()).role(user.getRole()).uid(user.getId()).build();
    }

    public void register(RegisterRequest request) { register(request.getUsername(), request.getEmail(), request.getPassword(), request.getFirstName(), request.getLastName(), request.isTermsAccepted()); }

    public AuthResponse login(LoginRequest request) {
        String identifier = request.getUsernameOrEmail();
        String rawPassword = request.getPassword();
        // otp ignored; TOTP not in use

        boolean isEmail = isEmail(identifier);
        Optional<User> userOpt = isEmail ? userRepository.findByEmail(identifier) : userRepository.findByUsername(identifier);
        User user = userOpt.orElseThrow(() -> new AuthException("Invalid credentials"));

        if (Boolean.FALSE.equals(user.getPasswordLoginEnabled())) throw new AuthException("Invalid credentials");
        if (user.getOauthProvider() == null && Boolean.FALSE.equals(user.getEmailVerified())) throw new AuthException("Email not verified");
        if (!passwordEncoder.matches(rawPassword, user.getPassword())) throw new AuthException("Invalid credentials");

        // TOTP not required per current requirements

        user.setLastLoginAt(java.time.LocalDateTime.now());
        user.setLastLoginIp(null);
        user.setLastLoginProvider(null);
        user.setLoginCount(java.util.Optional.ofNullable(user.getLoginCount()).orElse(0L) + 1);
        userRepository.save(user);

        String token = buildTokenForUser(user);
        return AuthResponse.builder().token(token).username(user.getUsername()).email(user.getEmail()).role(user.getRole()).uid(user.getId()).build();
    }

    @Transactional
    public AuthResponse verifyEmail(String token, boolean autoLogin) {
        VerificationToken vt = verificationTokenRepository.findByToken(token).orElseThrow(() -> new AuthException("Invalid token"));
        if (vt.getUsedAt() != null) throw new AuthException("Token already used");
        if (vt.getExpiresAt().isBefore(java.time.LocalDateTime.now())) throw new AuthException("Token expired");
        User user = vt.getUser();
        user.setEmailVerified(true); userRepository.save(user);
        vt.setUsedAt(java.time.LocalDateTime.now()); verificationTokenRepository.save(vt);
        if (!autoLogin) return null;
        String tokenJwt = buildTokenForUser(user);
        return AuthResponse.builder().token(tokenJwt).username(user.getUsername()).email(user.getEmail()).role(user.getRole()).uid(user.getId()).build();
    }

    @Transactional
    public void resendVerification(ResendVerificationRequest req) {
        User user = userRepository.findByEmail(req.getEmail()).orElseThrow(() -> new AuthException("User not found"));
        if (Boolean.TRUE.equals(user.getEmailVerified())) return;
        if (!resendThrottleService.allow(user.getEmail())) throw new AuthException("Too many requests");
        issueAndSendVerificationToken(user);
    }

    @Transactional
    public AuthResponse linkOAuth(String linkToken) {
        try {
            io.jsonwebtoken.Claims claims = linkTokenService.parse(linkToken);
            String email = claims.containsKey("email") ? (String) claims.get("email") : claims.getSubject();
            String provider = (String) claims.get("provider");
            String subject = (String) claims.get("sub");
            User user = userRepository.findByEmail(email).orElseThrow(() -> new AuthException("User not found"));
            if (user.getOauthProvider() != null) return buildAuthResponse(user);
            user.setOauthProvider(com.jobrec.user.entity.OAuthProvider.valueOf(provider.toUpperCase()));
            if (subject != null) user.setOauthSubject(subject);
            user.setEmailVerified(true);
            userRepository.save(user);
            return buildAuthResponse(user);
        } catch (io.jsonwebtoken.JwtException ex) {
            throw new AuthException("Invalid link token");
        }
    }

    private AuthResponse buildAuthResponse(User user) {
        String token = buildTokenForUser(user);
        return AuthResponse.builder().token(token).username(user.getUsername()).email(user.getEmail()).role(user.getRole()).uid(user.getId()).build();
    }

    @Transactional
    public void setPassword(String username, String newPassword) {
        if (newPassword == null || newPassword.length() < 8) throw new AuthException("Password must be at least 8 characters");
        User user = userRepository.findByUsername(username).orElseThrow(() -> new AuthException("User not found"));
        user.setPassword(passwordEncoder.encode(newPassword));
        user.setPasswordLoginEnabled(true);
        userRepository.save(user);
    }

    private String buildTokenForUser(User user) { Map<String, Object> claims = new HashMap<>(); claims.put("role", user.getRole()); claims.put("uid", user.getId()); return jwtUtil.generateToken(user.getUsername(), claims, jwtExpirationSeconds); }

    private boolean isEmail(String input) { return Pattern.compile("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+$").matcher(input).matches(); }

    // TOTP management removed
}
