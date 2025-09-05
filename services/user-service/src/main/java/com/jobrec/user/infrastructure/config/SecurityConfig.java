
package com.jobrec.user.infrastructure.config;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
// No explicit CORS imports; dev same-origin via Vite proxy to gateway
// import not required for same-package type

// import java.util.List;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

	private final com.jobrec.user.infrastructure.security.jwt.JWTAuthenticationFilter jwtAuthenticationFilter;
	private final com.jobrec.user.infrastructure.security.rateLimiting.RateLimitingFilter rateLimitingFilter;
	private final com.jobrec.user.infrastructure.security.oauth.OAuth2UserServiceImpl oAuth2UserService;
	private final com.jobrec.user.infrastructure.security.oauth.OAuth2LoginSuccessHandler oAuth2LoginSuccessHandler;
	private final com.jobrec.user.infrastructure.security.oauth.OAuth2LoginFailureHandler oAuth2LoginFailureHandler;
	private final OAuth2AuthorizationRequestResolver oAuth2AuthorizationRequestResolver;
	private final ObjectProvider<org.springframework.security.oauth2.client.registration.ClientRegistrationRepository> clientRegistrationRepositoryProvider;

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http
				.csrf(csrf -> csrf.disable())
				// No explicit CORS; rely on gateway/proxy in dev
				.cors(cors -> {})
				.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				.authorizeHttpRequests(auth -> auth
						.requestMatchers(PathRequest.toStaticResources().atCommonLocations()).permitAll()
						.requestMatchers("/", "/index.html", "/favicon.ico").permitAll()
						.requestMatchers("/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html").permitAll()
						.requestMatchers("/auth/**", "/oauth2/**", "/login/oauth2/**").permitAll()
						.anyRequest().authenticated()
				)
				.addFilterBefore(rateLimitingFilter, UsernamePasswordAuthenticationFilter.class)
				.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

		// Configure OAuth2 login only if a ClientRegistrationRepository is present (i.e., OAuth2 clients configured)
		if (clientRegistrationRepositoryProvider.getIfAvailable() != null) {
			http.oauth2Login(oauth -> oauth
					.authorizationEndpoint(aa -> aa.authorizationRequestResolver(oAuth2AuthorizationRequestResolver))
					.userInfoEndpoint(userInfo -> userInfo.userService(oAuth2UserService))
					.successHandler(oAuth2LoginSuccessHandler)
					.failureHandler(oAuth2LoginFailureHandler)
			);
		}

		return http.build();
	}

	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
		return configuration.getAuthenticationManager();
	}

	// Removed CorsConfigurationSource bean
}
