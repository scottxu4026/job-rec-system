package com.jobrec.user.repository;

import com.jobrec.user.entity.User;
import com.jobrec.user.entity.UserProfile;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.test.context.ActiveProfiles;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
@ActiveProfiles("test")
class UserRepositoryTest {

	@Autowired
	private UserRepository userRepository;

	@Autowired
	private UserProfileRepository userProfileRepository;

	@Test
	@DisplayName("persist and find user by username and email")
	void persist_and_find() {
		User user = User.builder()
				.username("alice")
				.email("alice@example.com")
				.password("pw")
				.role("USER")
				.build();
		User saved = userRepository.save(user);

		UserProfile profile = UserProfile.builder()
				.user(saved)
				.firstName("Alice")
				.lastName("Doe")
				.build();
		userProfileRepository.save(profile);

		Optional<User> foundByUsername = userRepository.findByUsername("alice");
		Optional<User> foundByEmail = userRepository.findByEmail("alice@example.com");
		Optional<User> either = userRepository.findByUsernameOrEmail("alice", "alice@example.com");

		assertThat(foundByUsername).isPresent();
		assertThat(foundByEmail).isPresent();
		assertThat(either).isPresent();
		assertThat(foundByUsername.get().getId()).isEqualTo(saved.getId());
	}

	@Test
	@DisplayName("queries for non-existent username/email return empty")
	void non_existent_queries() {
		assertThat(userRepository.findByUsername("nope")).isEmpty();
		assertThat(userRepository.findByEmail("nope@example.com")).isEmpty();
		assertThat(userRepository.findByUsernameOrEmail("nope", "nope@example.com")).isEmpty();
	}
}


