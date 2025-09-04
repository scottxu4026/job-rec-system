package com.jobrec.user.infrastructure.security.oauth;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;

import java.util.Collection;
import java.util.Map;

public class CustomOAuth2User extends DefaultOAuth2User {

    private final String email;
    private final String name;

    public CustomOAuth2User(Collection<? extends GrantedAuthority> authorities,
                            Map<String, Object> attributes,
                            String nameAttributeKey,
                            String email,
                            String name) {
        super(authorities, attributes, nameAttributeKey);
        this.email = email;
        this.name = name;
    }

    public String getEmail() {
        return email;
    }

    public String getFullName() {
        return name;
    }
}


