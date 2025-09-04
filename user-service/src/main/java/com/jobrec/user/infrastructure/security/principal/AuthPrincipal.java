package com.jobrec.user.infrastructure.security.principal;

import java.io.Serializable;

public record AuthPrincipal(Long id, String username, String email, String role) implements Serializable {}


