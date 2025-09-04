package com.jobrec.user.domain.entity;

import java.time.LocalDateTime;

import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import jakarta.persistence.Column;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "users")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank
    @Column(unique = true, nullable = false)
    private String username;

    @Email
    @NotBlank
    @Column(unique = true, nullable = false)
    private String email;

    @NotBlank
    @Column(nullable = false)
    private String password;

    @Builder.Default
    @Column(nullable = false, columnDefinition = "varchar(255) default 'USER'")
    private String role = "USER";

    @Builder.Default
    @Column(nullable = false, columnDefinition = "boolean default true")
    private Boolean enabled = true;

    private String phoneNumber;

    @Builder.Default
    @Column(nullable = false, columnDefinition = "varchar(255) default 'ACTIVE'")
    private String accountStatus = "ACTIVE";

    private String profilePictureUrl;

    @Enumerated(EnumType.STRING)
    @Column(name = "oauth_provider")
    private OAuthProvider oauthProvider;

    // --- Login audit fields ---
    private LocalDateTime lastLoginAt;

    private String lastLoginIp;

    @Enumerated(EnumType.STRING)
    @Column(name = "last_login_provider")
    private OAuthProvider lastLoginProvider;

    @Builder.Default
    @Column(name = "login_count", nullable = false, columnDefinition = "bigint default 0")
    private Long loginCount = 0L;

    @Builder.Default
    @Column(name = "password_login_enabled", nullable = false, columnDefinition = "boolean default true")
    private Boolean passwordLoginEnabled = true;

    @Builder.Default
    @Column(name = "email_verified", nullable = false, columnDefinition = "boolean default false")
    private Boolean emailVerified = false;

    @Column(name = "terms_accepted_at")
    private LocalDateTime termsAcceptedAt;

    @Column(name = "oauth_subject")
    private String oauthSubject;

    @CreationTimestamp
    private LocalDateTime createdAt;

    @UpdateTimestamp
    private LocalDateTime updatedAt;

    @PrePersist
    protected void onCreate() {
        if(this.createdAt == null) {
            this.createdAt = LocalDateTime.now();
        }
        if(this.updatedAt == null) {
            this.updatedAt = LocalDateTime.now();
        }
        if(this.accountStatus == null) {
            this.accountStatus = "ACTIVE";
        }
        if(this.role == null) {
            this.role = "USER";
        }
        if(this.enabled == null) {
            this.enabled = true;
        }
        if(this.passwordLoginEnabled == null) {
            this.passwordLoginEnabled = true;
        }
        if(this.emailVerified == null) {
            this.emailVerified = false;
        }
        
    }

    @PreUpdate
    protected void onUpdate() {
        this.updatedAt = LocalDateTime.now();
    }

    
}

