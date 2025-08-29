package com.jobrec.user.dto;

import com.fasterxml.jackson.annotation.JsonAlias;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * LoginRequest
 *
 * DTO representing login input, including identifier (username or email) and password.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class LoginRequest {
    @NotBlank
    @JsonAlias({"usernameOrEmail", "username", "email", "identifier"})
    private String identifier;

    @NotBlank
    private String password;

    /**
     * Backward-compatible accessor used by existing service methods.
     */
    public String getUsernameOrEmail() {
        return this.identifier;
    }
}


