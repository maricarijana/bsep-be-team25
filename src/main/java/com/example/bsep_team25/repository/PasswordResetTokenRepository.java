package com.example.bsep_team25.repository;

import com.example.bsep_team25.irepository.IPasswordResetTokenRepository;
import com.example.bsep_team25.model.PasswordResetToken;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public class PasswordResetTokenRepository {

    private final IPasswordResetTokenRepository iPasswordResetTokenRepository;

    public PasswordResetTokenRepository(IPasswordResetTokenRepository iPasswordResetTokenRepository) {
        this.iPasswordResetTokenRepository = iPasswordResetTokenRepository;
    }

    public PasswordResetToken save(PasswordResetToken token) {
        return iPasswordResetTokenRepository.save(token);
    }

    public Optional<PasswordResetToken> findByToken(String token) {
        return iPasswordResetTokenRepository.findByToken(token);
    }
}
