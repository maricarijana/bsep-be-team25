package com.example.bsep_team25.service;

import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailService {
    private final JavaMailSender mailSender;

    public EmailService(JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }

    public void sendActivationEmail(String to, String token) {
        String subject = "Activate your account";
        String link = "http://localhost:8080/api/auth/activate/" + token;
        String text = "Hello,\n\nClick the link below to activate your account:\n" + link + "\n\nThis link is valid for 24h.";

        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(to);
        message.setSubject(subject);
        message.setText(text);

        mailSender.send(message);
    }

}
