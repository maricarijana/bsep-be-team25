package com.example.bsep_team25.irepository;

import com.example.bsep_team25.model.ActivationToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface IActivationTokenRepository extends JpaRepository<ActivationToken, Long> {

    Optional<ActivationToken> findByToken(String token);
}
