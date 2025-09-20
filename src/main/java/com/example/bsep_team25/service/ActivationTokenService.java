package com.example.bsep_team25.service;

import com.example.bsep_team25.irepository.IActivationTokenRepository;
import com.example.bsep_team25.model.ActivationToken;
import com.example.bsep_team25.model.User;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

import java.util.Optional;
import java.util.UUID;

@Service
public class ActivationTokenService {

    private final IActivationTokenRepository tokenRepository;
    private final UserService userService;

    public ActivationTokenService(IActivationTokenRepository tokenRepository, UserService userService) {
        this.tokenRepository = tokenRepository;
        this.userService = userService;
    }

    public ActivationToken createToken(User user) {
        String tokenValue = UUID.randomUUID().toString();
        LocalDateTime expiry = LocalDateTime.now().plusHours(24); // 24h važenje

        ActivationToken token = new ActivationToken(tokenValue, user, expiry);
        return tokenRepository.save(token);
    }

    public boolean activateUser(String tokenValue) {
        Optional<ActivationToken> tokenOpt = tokenRepository.findByToken(tokenValue);
        if (tokenOpt.isEmpty()) return false;

        ActivationToken token = tokenOpt.get();

        // Ako je token istekao → fail
        if (token.getExpiryDate().isBefore(LocalDateTime.now())) {
            tokenRepository.delete(token);
            return false;
        }

        // Aktiviraj korisnika
        User user = token.getUser();
        user.setActive(true);
        userService.save(user);

        // Obriši token (jednokratna upotreba)
        tokenRepository.delete(token);
        return true;
    }
}
