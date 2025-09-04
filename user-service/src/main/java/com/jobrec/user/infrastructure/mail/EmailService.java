package com.jobrec.user.infrastructure.mail;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class EmailService {
    private final JavaMailSender mailSender;

    @Value("${mail.from:no-reply@jobrec.local}")
    private String from;

    public void sendVerificationEmail(String email, String link) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(from);
        message.setTo(email);
        message.setSubject("Verify your email");
        message.setText("Click to verify: " + link);
        try {
            mailSender.send(message);
        } catch (Exception ex) {
            log.warn("Email send failed, falling back to log: {}", ex.getMessage());
            log.info("[EmailService] Verification email to {}: {}", email, link);
        }
    }
}


