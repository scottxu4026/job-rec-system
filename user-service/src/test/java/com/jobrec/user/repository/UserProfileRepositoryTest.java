package com.jobrec.user.repository;

import com.jobrec.user.domain.entity.User;
import com.jobrec.user.domain.entity.UserProfile;
import com.jobrec.user.domain.repository.UserRepository;
import com.jobrec.user.domain.repository.UserProfileRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.test.context.ActiveProfiles;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
@ActiveProfiles("test")
class UserProfileRepositoryTest {

	@Autowired
	private UserRepository userRepository;

	@Autowired
	private UserProfileRepository userProfileRepository;

	@Test
	@DisplayName("persist and find by userId")
	void persist_and_find_by_userId() {
		// Persist user
		User user = User.builder()
				.username("alice")
				.email("alice@example.com")
				.password("pw")
				.role("USER")
				.build();
		User savedUser = userRepository.save(user);

		// Persist profile mapped by @MapsId to user's id
		UserProfile profile = UserProfile.builder()
				.user(savedUser)
				.firstName("Alice")
				.lastName("Doe")
				.build();
		userProfileRepository.save(profile);

		// Query by user id (same as profile id due to @MapsId)
		Optional<UserProfile> byId = userProfileRepository.findById(savedUser.getId());
		assertThat(byId).isPresent();
		assertThat(byId.get().getUser().getUsername()).isEqualTo("alice");
		assertThat(byId.get().getUser().getId()).isEqualTo(savedUser.getId());
	}

	@Test
	@DisplayName("non existent userId returns empty")
	void non_existent_userId_returns_empty() {
		Optional<UserProfile> notFound = userProfileRepository.findById(9999L);
		assertThat(notFound).isEmpty();
	}
}



