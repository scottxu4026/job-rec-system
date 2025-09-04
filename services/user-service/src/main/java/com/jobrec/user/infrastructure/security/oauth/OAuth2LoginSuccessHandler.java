package com.jobrec.user.infrastructure.security.oauth;

import com.jobrec.user.domain.entity.User;
import com.jobrec.user.domain.repository.UserRepository;
import com.jobrec.user.infrastructure.security.jwt.JWTUtil;
import com.jobrec.user.infrastructure.security.token.LinkTokenService;
// removed UserProfile creation from success handler to avoid detached entity issues
import com.jobrec.user.domain.entity.OAuthProvider;
import org.springframework.beans.factory.annotation.Value;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Component
@RequiredArgsConstructor
@Slf4j
public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {

    private final JWTUtil jwtUtil;
    private final UserRepository userRepository;
    private final LinkTokenService linkTokenService;

    @Value("${frontend.base-url:http://localhost:5173}")
    private String frontendBaseUrl;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        Object principal = authentication.getPrincipal();
        String email = null;
        String displayName = null;
        String providerSub = null;
        if (principal instanceof com.jobrec.user.infrastructure.security.oauth.CustomOAuth2User cu) {
            email = cu.getEmail();
            displayName = cu.getFullName();
        } else if (principal instanceof OidcUser oidcUser) {
            email = oidcUser.getEmail();
            displayName = oidcUser.getFullName();
            providerSub = oidcUser.getSubject();
        } else if (principal instanceof OAuth2User oAuth2User) {
            email = oAuth2User.getAttribute("email");
            displayName = oAuth2User.getAttribute("name");
            Object subAttr = oAuth2User.getAttribute("sub");
            providerSub = subAttr != null ? String.valueOf(subAttr) : null;
        }
        if (email == null) {
            throw new IllegalStateException("Email not present in OAuth2 principal");
        }

        User user = userRepository.findByEmail(email).orElse(null);
        String registrationId = (authentication instanceof OAuth2AuthenticationToken tok)
                ? tok.getAuthorizedClientRegistrationId() : null;
        if (user == null) {
            // New user via OAuth2: redirect to frontend completion page with short-lived regToken
            String regToken = linkTokenService.createLinkToken(email, registrationId, providerSub, 600);
            String preUsername = generateUsername(email);
            String location = frontendBaseUrl + "/complete-oauth?regToken=" + URLEncoder.encode(regToken, StandardCharsets.UTF_8)
                    + "&email=" + URLEncoder.encode(email, StandardCharsets.UTF_8)
                    + "&preUsername=" + URLEncoder.encode(preUsername, StandardCharsets.UTF_8);
            response.setStatus(HttpServletResponse.SC_FOUND);
            response.setHeader("Location", location);
            return;
        } else if (user.getOauthProvider() == null) {
            if (Boolean.FALSE.equals(user.getEmailVerified())) {
                String location = frontendBaseUrl + "/login?notice=verify_required";
                response.setStatus(HttpServletResponse.SC_FOUND);
                response.setHeader("Location", location);
                return;
            }
            // Existing user linking OAuth: redirect to frontend linking page
            String linkToken = linkTokenService.createLinkToken(email, registrationId, providerSub, 300);
            String location = frontendBaseUrl + "/link-oauth?linkToken=" + URLEncoder.encode(linkToken, StandardCharsets.UTF_8);
            response.setStatus(HttpServletResponse.SC_FOUND);
            response.setHeader("Location", location);
            return;
        }

        // Record login audit info for OAuth2
        user.setLastLoginAt(java.time.LocalDateTime.now());
        user.setLastLoginIp(request.getRemoteAddr());
        user.setLastLoginProvider(resolveProvider(registrationId));
        user.setLoginCount(java.util.Optional.ofNullable(user.getLoginCount()).orElse(0L) + 1);
        try {
            userRepository.save(user);
        } catch (Exception ex) {
            log.warn("OAuth2 audit save failed: {}", ex.getMessage());
        }

        Map<String, Object> claims = new HashMap<>();
        claims.put("role", user.getRole());
        claims.put("uid", user.getId());
        claims.put("email", user.getEmail());
        if (displayName != null) {
            claims.put("name", displayName);
        }
        String token = jwtUtil.generateToken(user.getUsername(), claims);

        long expiresAt = System.currentTimeMillis() + (java.time.Duration.ofHours(1).toMillis());
        // Redirect to frontend home with token in URL fragment so the SPA can capture it and clean up the URL
        String location = frontendBaseUrl + "/#token=" + URLEncoder.encode(token, StandardCharsets.UTF_8) + "&expiresAt=" + expiresAt;
        response.setStatus(HttpServletResponse.SC_FOUND);
        response.setHeader("Location", location);
    }

    private OAuthProvider resolveProvider(String registrationId) {
        if (registrationId == null) return OAuthProvider.OTHER;
        try {
            return OAuthProvider.valueOf(registrationId.toUpperCase());
        } catch (IllegalArgumentException ex) {
            return OAuthProvider.OTHER;
        }
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

    // removed HTML helpers as we now redirect to frontend routes instead of rendering HTML

    private String sanitizeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", " ").replace("\r", " ");
    }
}


