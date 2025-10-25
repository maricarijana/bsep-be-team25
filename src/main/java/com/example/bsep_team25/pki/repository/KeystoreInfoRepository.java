package com.example.bsep_team25.pki.repository;

import com.example.bsep_team25.pki.domain.KeyStoreInfo;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;

@Repository
public interface KeystoreInfoRepository extends JpaRepository<KeyStoreInfo, Long> {

    Optional<KeyStoreInfo> findByAlias(String alias);

    void deleteByAlias(String alias);
}
