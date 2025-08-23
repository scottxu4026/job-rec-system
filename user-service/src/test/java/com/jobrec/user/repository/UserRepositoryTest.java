package com.jobrec.user.repository;

import com.jobrec.user.entity.User;
import com.jobrec.user.entity.UserProfile;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
public class UserRepositoryTest {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private UserProfileRepository userProfileRepository;

    @Test
    @DisplayName("Test User and UserProfile CRUD operations")
    @Transactional
    public void testUserAndUserProfileCRUD() {
        // Create User
        User user = User.builder()
                .username("testuser")
                .email("testuser@example.com")
                .password("password")
                .build();
        user = userRepository.save(user);
        assertNotNull(user.getId(), "User ID should not be null after save");

        // Create UserProfile
        UserProfile profile = UserProfile.builder()
                .user(user)
                .firstName("Test")
                .lastName("User")
                .build();
        profile = userProfileRepository.save(profile);
        assertNotNull(profile.getId(), "UserProfile ID should not be null after save");

        // Verify relationship
        Optional<UserProfile> foundProfile = userProfileRepository.findById(profile.getId());
        assertTrue(foundProfile.isPresent(), "UserProfile should be present");
        assertEquals(user.getId(), foundProfile.get().getUser().getId(), "User ID should match");

        // Update User
        user.setEmail("updateduser@example.com");
        user = userRepository.save(user);
        assertEquals("updateduser@example.com", user.getEmail(), "User email should be updated");

        // Delete UserProfile
        userProfileRepository.delete(profile);
        assertTrue(userProfileRepository.findById(profile.getId()).isEmpty(), "UserProfile should be deleted");

        // Delete User
        userRepository.delete(user);
        assertTrue(userRepository.findById(user.getId()).isEmpty(), "User should be deleted");
    }

    @Test
    @DisplayName("Test batch insert of Users with UserProfiles")
    @Transactional
    public void testBatchInsertUsersWithProfiles() {
        // Create Users and UserProfiles
        List<User> users = new ArrayList<>();
        for (int i = 1; i <= 5; i++) {
            User user = User.builder()
                    .username("user" + i)
                    .email("user" + i + "@example.com")
                    .password("password")
                    .build();
            users.add(user);

            UserProfile profile = UserProfile.builder()
                    .user(user)
                    .firstName("FirstName" + i)
                    .lastName("LastName" + i)
                    .location("Location" + i)
                    .skills("Skill1, Skill2")
                    .build();
            userProfileRepository.save(profile);
        }

        // Save all users
        userRepository.saveAll(users);

        // Retrieve all users
        List<User> retrievedUsers = userRepository.findAll();
        assertEquals(5, retrievedUsers.size(), "There should be 5 users in the database");

        // Assert each user has a non-null profile and valid firstName
        for (User retrievedUser : retrievedUsers) {
            UserProfile retrievedProfile = userProfileRepository.findById(retrievedUser.getId()).orElse(null);
            assertNotNull(retrievedProfile, "UserProfile should not be null");
            assertTrue(retrievedProfile.getFirstName().startsWith("FirstName"), "FirstName should be valid");
        }
    }
}
