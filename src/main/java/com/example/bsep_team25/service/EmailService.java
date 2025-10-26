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
    public void sendSimpleEmail(String to, String subject, String text) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(to);
        message.setSubject(subject);
        message.setText(text);
        mailSender.send(message);
    }

    public void sendCAUserCredentials(String email, String temporaryPassword, String organization) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(email);
        message.setSubject("Your CA User Account - " + organization);
        message.setText(
                "Hello,\n\n" +
                        "An administrator has created a CA User account for you.\n\n" +
                        "Organization: " + organization + "\n" +
                        "Email: " + email + "\n" +
                        "Temporary Password: " + temporaryPassword + "\n\n" +
                        "IMPORTANT: You must change this password upon first login.\n\n" +
                        "Login at: http://localhost:4200/login\n\n" +
                        "Best regards,\n" +
                        "PKI System Team"
        );

        mailSender.send(message);
    }

}
