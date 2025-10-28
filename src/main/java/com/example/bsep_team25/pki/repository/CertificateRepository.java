package com.example.bsep_team25.pki.repository;

import com.example.bsep_team25.pki.domain.Certificate;
import com.example.bsep_team25.pki.domain.CertificateType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface CertificateRepository extends JpaRepository<Certificate, Long> {

    Optional<Certificate> findBySerialNumber(String serialNumber);

    List<Certificate> findByOwnerId(Long ownerId);

    List<Certificate> findByIsCATrue();

    List<Certificate> findByCertificateType(CertificateType type);

    List<Certificate> findByOwnerOrganization(String organization);

    // Pronaći sve CA sertifikate koji nisu povučeni
    @Query("SELECT c FROM Certificate c WHERE c.isCA = true AND c.isRevoked = false")
    List<Certificate> findActiveCA();

    // Pronaći sve sertifikate koje je izdao određeni CA
    List<Certificate> findByIssuerCertificate(Certificate issuer);

    @Query("SELECT c FROM Certificate c WHERE c.owner.id = :ownerId AND c.isCA = true AND c.isRevoked = false ORDER BY c.createdAt DESC")
    List<Certificate> findActiveCACertificatesByOwner(@Param("ownerId") Long ownerId);

    /**
     * Pronalazi sve sertifikate izdane od strane određenog CA-a
     */
    List<Certificate> findByIssuerCertificateId(Long issuerCertificateId);

    // Pronađi sve povučene sertifikate
    List<Certificate> findByIsRevokedTrue();

    // Pronađi sve povučene sertifikate izdane od strane određenog CA-a
    @Query("SELECT c FROM Certificate c WHERE c.isRevoked = true AND c.issuerCertificate.serialNumber = :issuerSerial")
    List<Certificate> findRevokedByIssuer(@Param("issuerSerial") String issuerSerial);

    /**
     * Pronalazi aktivni END_ENTITY sertifikat korisnika
     */
    @Query("""
    SELECT c FROM Certificate c
    WHERE c.owner.id = :ownerId
      AND c.certificateType = com.example.bsep_team25.pki.domain.CertificateType.END_ENTITY
      AND c.isRevoked = false
      AND c.validFrom <= CURRENT_TIMESTAMP
      AND c.validUntil > CURRENT_TIMESTAMP
    ORDER BY c.createdAt DESC
    """)
    Optional<Certificate> findActiveEndEntityCertificateByOwner(@Param("ownerId") Long ownerId);
}
