package com.jobrec.user.infrastructure.security.oauth;

import com.jobrec.user.domain.entity.User;
import com.jobrec.user.domain.entity.UserProfile;
import com.jobrec.user.domain.repository.UserProfileRepository;
import com.jobrec.user.domain.repository.UserRepository;
import com.jobrec.user.infrastructure.security.oauth.CustomOAuth2User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class OAuth2UserServiceImpl extends DefaultOAuth2UserService {

    private final UserRepository userRepository;
    private final UserProfileRepository userProfileRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    @Transactional
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);

        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        Map<String, Object> attributes = oAuth2User.getAttributes();

        String email = extractEmail(registrationId, attributes);
        String name = extractName(registrationId, attributes);
        String subject = attributes != null ? (String) attributes.get("sub") : null;

        if (email == null) {
            throw new OAuth2AuthenticationException("Email not provided by OAuth2 provider");
        }

        Optional<User> existingOpt = userRepository.findByEmail(email);
        if (existingOpt.isPresent()) {
            User user = existingOpt.get();
            return new CustomOAuth2User(
                    List.of(new SimpleGrantedAuthority("ROLE_" + user.getRole())),
                    attributes,
                    "sub",
                    user.getEmail(),
                    name
            );
        }

        // New user: we don't create immediately here; the success handler will present a registration page
        return new CustomOAuth2User(
                List.of(new SimpleGrantedAuthority("ROLE_ANONYMOUS")),
                attributes,
                "sub",
                email,
                name
        );
    }

    private User registerNewUser(String email, String name, String registrationId, String subject) {
        String username = generateUsername(email);
        String randomPassword = java.util.UUID.randomUUID().toString();
        User newUser = User.builder()
                .username(username)
                .email(email)
                .password(passwordEncoder.encode(randomPassword))
                .oauthProvider(resolveProvider(registrationId))
                .oauthSubject(subject)
                .emailVerified(true)
                .passwordLoginEnabled(false)
                .build();
        User saved = userRepository.save(newUser);

        UserProfile profile = UserProfile.builder()
                .user(saved)
                .firstName(name != null ? name : username)
                .lastName("")
                .build();
        userProfileRepository.save(profile);
        return saved;
    }

    private String generateUsername(String email) {
        String base = email.split("@")[0];
        String candidate = base;
        int suffix = 1;
        while (userRepository.findByUsername(candidate).isPresent()) {
            candidate = base + suffix++;
        }
        return candidate;
    }

    private String extractEmail(String registrationId, Map<String, Object> attributes) {
        if ("google".equalsIgnoreCase(registrationId)) {
            return (String) attributes.get("email");
        }
        return (String) attributes.getOrDefault("email", null);
    }

    private String extractName(String registrationId, Map<String, Object> attributes) {
        if ("google".equalsIgnoreCase(registrationId)) {
            return (String) attributes.get("name");
        }
        return (String) attributes.getOrDefault("name", null);
    }

    private com.jobrec.user.domain.entity.OAuthProvider resolveProvider(String registrationId) {
        if (registrationId == null) return com.jobrec.user.domain.entity.OAuthProvider.OTHER;
        try {
            return com.jobrec.user.domain.entity.OAuthProvider.valueOf(registrationId.toUpperCase());
        } catch (IllegalArgumentException ex) {
            return com.jobrec.user.domain.entity.OAuthProvider.OTHER;
        }
    }
}


