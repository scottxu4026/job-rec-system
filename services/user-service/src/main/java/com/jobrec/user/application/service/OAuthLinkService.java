package com.jobrec.user.application.service;

import com.jobrec.user.api.dto.AuthResponse;
import com.jobrec.user.domain.entity.User;
import com.jobrec.user.domain.entity.UserProfile;
import com.jobrec.user.domain.repository.UserProfileRepository;
import com.jobrec.user.domain.repository.UserRepository;
import com.jobrec.user.infrastructure.security.token.AuthTokenFactory;
import com.jobrec.user.infrastructure.security.token.LinkTokenService;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * OAuthLinkService
 *
 * Moved from AuthService: OAuth2 linking to existing accounts and registration completion using regToken.
 */
@Service
@RequiredArgsConstructor
public class OAuthLinkService {

    private final UserRepository userRepository;
    private final UserProfileRepository userProfileRepository;
    private final PasswordEncoder passwordEncoder;
    private final LinkTokenService linkTokenService;
    private final AuthTokenFactory authTokenFactory;

    @Transactional
    public AuthResponse linkOAuth(String linkToken) {
        try {
            io.jsonwebtoken.Claims claims = linkTokenService.parse(linkToken);
            String email = claims.containsKey("email") ? (String) claims.get("email") : claims.getSubject();
            String provider = (String) claims.get("provider");
            String subject = (String) claims.get("sub");
            User user = userRepository.findByEmail(email).orElseThrow(() -> new AuthService.AuthException("User not found"));
            if (Boolean.FALSE.equals(user.getEmailVerified())) throw new AuthService.AuthException("Email not verified");
            if (user.getOauthProvider() != null) return authTokenFactory.buildAuthResponse(user);
            user.setOauthProvider(com.jobrec.user.domain.entity.OAuthProvider.valueOf(provider.toUpperCase()));
            if (subject != null) user.setOauthSubject(subject);
            user.setEmailVerified(true);
            userRepository.save(user);
            return authTokenFactory.buildAuthResponse(user);
        } catch (io.jsonwebtoken.JwtException ex) {
            throw new AuthService.AuthException("Invalid link token");
        }
    }

    /**
     * Complete registration after OAuth2 by providing registration token (containing email + provider), username, and password.
     */
    @Transactional
    public AuthResponse registerOAuth(String registrationToken, String username, String rawPassword, boolean termsAccepted) {
        if (!termsAccepted) throw new AuthService.AuthException("Terms must be accepted");
        try {
            io.jsonwebtoken.Claims claims = linkTokenService.parse(registrationToken);
            String email = claims.containsKey("email") ? (String) claims.get("email") : claims.getSubject();
            String provider = (String) claims.get("provider");
            String subject = (String) claims.get("sub");

            if (email == null || provider == null) throw new AuthService.AuthException("Invalid registration token");
            if (userRepository.findByUsername(username).isPresent()) throw new AuthService.AuthException("Username already exists");
            if (userRepository.findByEmail(email).isPresent()) throw new AuthService.AuthException("Email already exists");

            String encodedPassword = passwordEncoder.encode(rawPassword);
            User user = User.builder()
                    .username(username)
                    .email(email)
                    .password(encodedPassword)
                    .oauthProvider(com.jobrec.user.domain.entity.OAuthProvider.valueOf(provider.toUpperCase()))
                    .oauthSubject(subject)
                    .emailVerified(true)
                    .passwordLoginEnabled(true)
                    .termsAcceptedAt(java.time.LocalDateTime.now())
                    .build();
            user = userRepository.save(user);
            UserProfile profile = UserProfile.builder()
                    .user(user)
                    .firstName(username)
                    .lastName(username)
                    .build();
            userProfileRepository.save(profile);
            return authTokenFactory.buildAuthResponse(user);
        } catch (io.jsonwebtoken.JwtException ex) {
            throw new AuthService.AuthException("Invalid registration token");
        }
    }
}


