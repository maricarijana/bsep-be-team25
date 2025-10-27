package com.example.bsep_team25.pki.repository;
import com.example.bsep_team25.model.User;
import com.example.bsep_team25.pki.domain.CertificateTemplate;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface CertificateTemplateRepository extends JpaRepository<CertificateTemplate, Long> {

    Optional<CertificateTemplate> findByName(String name);

    List<CertificateTemplate> findByCaIssuer_SerialNumber(String issuerSerial);

    List<CertificateTemplate> findByCreatedBy(User user);

    boolean existsByName(String name);


}
