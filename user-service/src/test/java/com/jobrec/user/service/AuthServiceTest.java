package com.jobrec.user.service;

import com.jobrec.user.infrastructure.security.jwt.JWTUtil;
import com.jobrec.user.api.dto.AuthResponse;
import com.jobrec.user.api.dto.RegisterRequest;
import com.jobrec.user.infrastructure.security.token.AuthTokenFactory;
import com.jobrec.user.domain.entity.User;
import com.jobrec.user.domain.entity.UserProfile;
import com.jobrec.user.domain.entity.VerificationToken;
import com.jobrec.user.application.service.AuthService;
import com.jobrec.user.infrastructure.mail.EmailService;
import com.jobrec.user.domain.repository.UserProfileRepository;
import com.jobrec.user.domain.repository.UserRepository;
import com.jobrec.user.domain.repository.VerificationTokenRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

	@Mock
	private UserRepository userRepository;

	@Mock
	private UserProfileRepository userProfileRepository;

	@Mock
	private VerificationTokenRepository verificationTokenRepository;

	@Mock
	private JWTUtil jwtUtil;

	@Mock
	private PasswordEncoder passwordEncoder;

	@Mock
	private EmailService emailService;

	@Mock
	private AuthTokenFactory authTokenFactory;

	@InjectMocks
	private AuthService authService;

	@BeforeEach
	void setup() {
		// no global stubs; stub locally per test to avoid unnecessary stubbings
	}

	@Test
	@DisplayName("register: success with valid data (sends verification email)")
	void register_success() {
		RegisterRequest req = RegisterRequest.builder()
				.username("alice")
				.email("alice@example.com")
				.password("secret")
				.firstName("Alice")
				.lastName("Doe")
				.termsAccepted(true)
				.build();

		given(userRepository.findByUsername("alice")).willReturn(Optional.empty());
		given(userRepository.findByEmail("alice@example.com")).willReturn(Optional.empty());
		given(passwordEncoder.encode("secret")).willReturn("ENC-secret");
		User persisted = User.builder().id(1L).username("alice").email("alice@example.com").password("ENC-secret").role("USER").emailVerified(false).build();
		given(userRepository.save(any(User.class))).willReturn(persisted);
		given(userProfileRepository.save(any(UserProfile.class))).willAnswer(inv -> inv.getArgument(0));
		given(verificationTokenRepository.save(any(VerificationToken.class))).willAnswer(inv -> inv.getArgument(0));

		authService.register(req);

		verify(userRepository).findByUsername("alice");
		verify(userRepository).findByEmail("alice@example.com");
		verify(passwordEncoder).encode("secret");
		verify(userRepository).save(any(User.class));
		verify(userProfileRepository).save(any(UserProfile.class));
		verify(verificationTokenRepository).save(any(VerificationToken.class));
		verify(emailService).sendVerificationEmail(eq("alice@example.com"), anyString());
		verifyNoInteractions(jwtUtil);
	}

	@Test
	@DisplayName("register: fails on duplicate username")
	void register_duplicateUsername() {
		given(userRepository.findByUsername("bob")).willReturn(Optional.of(User.builder().id(2L).build()));

		RegisterRequest req = RegisterRequest.builder()
				.username("bob")
				.email("bob@example.com")
				.password("pw")
				.firstName("Bob")
				.lastName("Doe")
				.termsAccepted(true)
				.build();

		assertThatThrownBy(() -> authService.register(req))
				.isInstanceOf(AuthService.AuthException.class)
				.hasMessageContaining("Username already exists");

		verify(userRepository, never()).save(any(User.class));
		verify(userProfileRepository, never()).save(any(UserProfile.class));
		verify(passwordEncoder, never()).encode(anyString());
		verify(jwtUtil, never()).generateToken(anyString(), anyMap(), anyLong());
	}

	@Test
	@DisplayName("register: fails on duplicate email")
	void register_duplicateEmail() {
		given(userRepository.findByUsername("carol")).willReturn(Optional.empty());
		given(userRepository.findByEmail("carol@example.com")).willReturn(Optional.of(User.builder().id(3L).build()));

		RegisterRequest req = RegisterRequest.builder()
				.username("carol")
				.email("carol@example.com")
				.password("pw")
				.firstName("Carol")
				.lastName("Doe")
				.termsAccepted(true)
				.build();

		assertThatThrownBy(() -> authService.register(req))
				.isInstanceOf(AuthService.AuthException.class)
				.hasMessageContaining("Email already exists");

		verify(userRepository, never()).save(any(User.class));
		verify(userProfileRepository, never()).save(any(UserProfile.class));
		verify(passwordEncoder, never()).encode(anyString());
		verify(jwtUtil, never()).generateToken(anyString(), anyMap(), anyLong());
	}

	@Test
	@DisplayName("login: success with correct credentials")
	void login_success() {
		User user = User.builder().id(10L).username("dave").email("dave@example.com").password("ENC-good").role("USER").emailVerified(true).build();
		given(userRepository.findByUsername("dave")).willReturn(Optional.of(user));
		given(passwordEncoder.matches("good", "ENC-good")).willReturn(true);
		given(authTokenFactory.buildAuthResponse(eq(user))).willReturn(
				AuthResponse.builder()
					.token("jwt-token")
					.expiresAt(123L)
					.user(AuthResponse.UserInfo.builder().id(10L).email("dave@example.com").role("USER").username("dave").build())
					.build()
		);

		AuthResponse res = authService.login("dave", "good");
		assertThat(res.getUser().getUsername()).isEqualTo("dave");
		assertThat(res.getToken()).isEqualTo("jwt-token");
		assertThat(res.getUser().getId()).isEqualTo(10L);
	}

	@Test
	@DisplayName("login: success using email as identifier")
	void login_success_withEmailIdentifier() {
		User user = User.builder().id(20L).username("eve").email("eve@example.com").password("ENC-pw").role("ADMIN").emailVerified(true).build();
		given(userRepository.findByEmail("eve@example.com")).willReturn(Optional.of(user));
		given(passwordEncoder.matches("pw", "ENC-pw")).willReturn(true);
		given(authTokenFactory.buildAuthResponse(eq(user))).willReturn(
				AuthResponse.builder()
					.token("jwt-token")
					.expiresAt(123L)
					.user(AuthResponse.UserInfo.builder().id(20L).email("eve@example.com").role("ADMIN").username("eve").build())
					.build()
		);

		AuthResponse res = authService.login("eve@example.com", "pw");
		assertThat(res.getUser().getUsername()).isEqualTo("eve");
		assertThat(res.getUser().getEmail()).isEqualTo("eve@example.com");
		assertThat(res.getUser().getId()).isEqualTo(20L);
	}

	@Test
	@DisplayName("login: fails on incorrect password")
	void login_incorrectPassword() {
		User user = User.builder().id(11L).username("erin").email("erin@example.com").password("ENC-correct").emailVerified(true).build();
		given(userRepository.findByUsername("erin")).willReturn(Optional.of(user));
		given(passwordEncoder.matches("wrong", "ENC-correct")).willReturn(false);

		assertThatThrownBy(() -> authService.login("erin", "wrong"))
				.isInstanceOf(AuthService.AuthException.class)
				.hasMessageContaining("Invalid credentials");
	}

	@Test
	@DisplayName("login: fails for non-existent user")
	void login_userNotFound() {
		given(userRepository.findByUsername("frank")).willReturn(Optional.empty());

		assertThatThrownBy(() -> authService.login("frank", "pw"))
				.isInstanceOf(AuthService.AuthException.class)
				.hasMessageContaining("Invalid credentials");
	}

    @Test
    @DisplayName("login: fails for non-existent email identifier")
    void login_emailNotFound() {
        //given(userRepository.findByUsername("ghost@example.com")).willReturn(Optional.empty());
        given(userRepository.findByEmail("ghost@example.com")).willReturn(Optional.empty());

        assertThatThrownBy(() -> authService.login("ghost@example.com", "pw"))
                .isInstanceOf(AuthService.AuthException.class)
                .hasMessageContaining("Invalid credentials");
    }


}


