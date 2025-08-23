package com.jobrec.user.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * LoginRequest
 *
 * DTO placeholder for login input, including usernameOrEmail and password.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class LoginRequest {
    private String usernameOrEmail;
    private String password;
}


