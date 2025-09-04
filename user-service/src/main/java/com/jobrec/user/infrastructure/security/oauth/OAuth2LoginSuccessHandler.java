package com.jobrec.user.infrastructure.security.oauth;

import com.jobrec.user.domain.entity.User;
import com.jobrec.user.domain.repository.UserRepository;
import com.jobrec.user.infrastructure.security.jwt.JWTUtil;
import com.jobrec.user.infrastructure.security.token.LinkTokenService;
// removed UserProfile creation from success handler to avoid detached entity issues
import com.jobrec.user.domain.entity.OAuthProvider;
import org.springframework.security.crypto.password.PasswordEncoder;
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
    private final PasswordEncoder passwordEncoder;
    private final LinkTokenService linkTokenService;

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
            // New user via OAuth2: present registration completion HTML with prefilled username/email and a short-lived registration token
            String regToken = linkTokenService.createLinkToken(email, registrationId, providerSub, 600);
            String preUsername = generateUsername(email);
            String html = "<!doctype html>" +
                    "<html><head><meta charset=\"utf-8\"><title>Complete registration</title>" +
                    "<style>body{font-family:system-ui,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:#0d1117;color:#c9d1d9;margin:2rem;}" +
                    ".card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:24px;max-width:560px;}" +
                    "input,button{padding:10px 12px;border-radius:6px;border:1px solid #30363d;background:#0d1117;color:#c9d1d9;width:100%;margin:6px 0;}" +
                    "label{display:block;margin:8px 0;}button.primary{background:#238636;color:#fff;border-color:#238636;cursor:pointer;}a{color:#58a6ff;}</style></head><body>" +
                    "<div class=card>" +
                    "<h2>Complete your account</h2>" +
                    "<form method=\"post\" action=\"/auth/register-oauth\">" +
                    "<input type=\"hidden\" name=\"regToken\" value=\"" + escapeHtml(regToken) + "\">" +
                    "<label>Email<input name=\"email\" value=\"" + escapeHtml(email) + "\" disabled></label>" +
                    "<label>Username<input name=\"username\" value=\"" + escapeHtml(preUsername) + "\" required></label>" +
                    "<label>Password<input type=\"password\" name=\"password\" placeholder=\"Set a password\" required></label>" +
                    "<label><input type=\"checkbox\" name=\"termsAccepted\" required> I accept the Terms of Service</label>" +
                    "<button class=\"primary\" type=\"submit\">Create account</button>" +
                    "<p style=\"margin-top:10px\"><a href=\"/\">Return to home</a></p>" +
                    "</form></div>" +
                    "</body></html>";
            response.setStatus(HttpServletResponse.SC_OK);
            response.setContentType("text/html;charset=UTF-8");
            response.getWriter().write(html);
            return;
        } else if (user.getOauthProvider() == null) {
            if (Boolean.FALSE.equals(user.getEmailVerified())) {
                String safeEmail = escapeHtml(email);
                String html = "<!doctype html>" +
                        "<html><head><meta charset=\"utf-8\"><title>Verification required</title>" +
                        "<style>body{font-family:system-ui,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:#0d1117;color:#c9d1d9;margin:2rem;}" +
                        ".card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:24px;max-width:560px;}a{color:#58a6ff;}</style></head><body>" +
                        "<div class=card>" +
                        "<h2>Verify your email</h2>" +
                        "<p>An account with <strong>" + safeEmail + "</strong> exists but is not verified. Please check your inbox for the verification email, or use the password login flow to resend verification.</p>" +
                        "<p><a href=\"/\">Return to sign in</a></p>" +
                        "</div></body></html>";
                response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                response.setContentType("text/html;charset=UTF-8");
                response.getWriter().write(html);
                return;
            }
            // Render a dedicated linking page (same tab), with working Link and Return actions
            String linkToken = linkTokenService.createLinkToken(email, registrationId, providerSub, 300);
            String safeEmail = escapeHtml(email);
            String linkUrl = "/auth/link-oauth?linkToken=" + URLEncoder.encode(linkToken, StandardCharsets.UTF_8);
            String html = "<!doctype html>" +
                    "<html><head><meta charset=\"utf-8\"><title>Link account</title>" +
                    "<style>body{font-family:system-ui,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:#0d1117;color:#c9d1d9;margin:2rem;}" +
                    ".card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:24px;max-width:560px;}" +
                    "button{padding:10px 16px;border-radius:6px;border:1px solid #30363d;background:#238636;color:#fff;cursor:pointer;}" +
                    "a{color:#58a6ff;display:inline-block;margin-top:12px;text-decoration:underline;}" +
                    "#msg{margin-top:12px;white-space:pre-wrap}</style></head><body>" +
                    "<div class=\"card\">" +
                    "<h2>Add new sign in method</h2>" +
                    "<p>" + safeEmail + " is an existing email. Do you want to enable Google sign in for this account?</p>" +
                    "<div><button id=\"linkBtn\">Link account</button></div>" +
                    "<a href=\"/\" target=\"_top\" id=\"returnLink\">Return to sign in</a>" +
                    "<pre id=\"msg\"></pre>" +
                    "</div>" +
                    "<script>\n" +
                    "document.getElementById('linkBtn').addEventListener('click', function(){ window.location.assign(" + js(linkUrl) + "); });\n" +
                    "function js(s){ return JSON.stringify(String(s)); }\n" +
                    "</script></body></html>";
            response.setStatus(HttpServletResponse.SC_OK);
            response.setContentType("text/html;charset=UTF-8");
            response.getWriter().write(html);
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

        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("application/json;charset=UTF-8");
        long expiresAt = System.currentTimeMillis() + (java.time.Duration.ofHours(1).toMillis());
        String body = String.format("{\"status\":\"success\",\"message\":\"Login successful\",\"data\":{\"token\":\"%s\",\"user\":{\"id\":%d,\"email\":\"%s\",\"role\":\"%s\",\"username\":\"%s\"},\"expiresAt\":%d}}",
                sanitizeJson(token), user.getId(), sanitizeJson(user.getEmail()), sanitizeJson(String.valueOf(user.getRole())), sanitizeJson(user.getUsername()), expiresAt);
        response.getWriter().write(body);
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

    private String escapeHtml(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&#39;");
    }

    private String js(String s) {
        return '"' + (s == null ? "" : s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r")) + '"';
    }

    private String sanitizeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", " ").replace("\r", " ");
    }
}


