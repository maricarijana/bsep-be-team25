package com.example.bsep_team25.service;

import com.example.bsep_team25.irepository.IPasswordResetTokenRepository;
import com.example.bsep_team25.irepository.IUserRepository;
import com.example.bsep_team25.iservice.IPasswordResetTokenService;
import com.example.bsep_team25.model.PasswordResetToken;
import com.example.bsep_team25.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Service
public class PasswordResetService implements IPasswordResetTokenService{

    @Autowired
    private IPasswordResetTokenRepository tokenRepo;

    @Autowired
    private IUserRepository userRepo;

    @Autowired
    private EmailService emailService;

    @Override
    public void createPasswordResetToken(String email) {
        User user = userRepo.findByEmail(email);
        if (user == null) return;

        PasswordResetToken token = new PasswordResetToken();
        token.setToken(UUID.randomUUID().toString());
        token.setUser(user);
        token.setExpiryDate(LocalDateTime.now().plusMinutes(15)); // token traje 15 min
        tokenRepo.save(token);

        String resetLink = "http://localhost:4200/reset-password/" + token.getToken();
        emailService.sendSimpleEmail(user.getEmail(),
                "Password Reset Request",
                "Kliknite na sledeći link da resetujete lozinku:\n" + resetLink);
    }

    @Override
    public boolean resetPassword(String tokenValue, String newPassword) {
        Optional<PasswordResetToken> tokenOpt = tokenRepo.findByToken(tokenValue);
        if (tokenOpt.isEmpty()) return false;

        PasswordResetToken token = tokenOpt.get();

        if (token.isUsed() || token.getExpiryDate().isBefore(LocalDateTime.now()))
            return false;

        User user = token.getUser();
        user.setPassword(new BCryptPasswordEncoder().encode(newPassword));
        userRepo.save(user);

        token.setUsed(true);
        tokenRepo.save(token);
        return true;
    }

}
