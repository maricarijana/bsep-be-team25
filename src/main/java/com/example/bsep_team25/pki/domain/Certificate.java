package com.example.bsep_team25.pki.domain;

import com.example.bsep_team25.model.User;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.*;

import jdk.jfr.DataAmount;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Entity
@Table(name= "certificate")
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class Certificate {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String serialNumber;

    // X500Name podaci
    @Column(nullable = false)
    private String commonName;

    @Column(nullable = false)
    private String organization;

    @Column
    private String organizationalUnit;

    @Column(nullable = false, length = 2)
    private String country;

    @Column
    private String state;

    @Column
    private String locality;

    @Column
    private String email;

    // Validnost
    @Column(nullable = false)
    private LocalDateTime validFrom;

    @Column(nullable = false)
    private LocalDateTime validUntil;

    // Tip sertifikata
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private CertificateType certificateType;

    // Da li je CA sertifikat
    @Column(nullable = false)
    @JsonProperty("isCA")
    private boolean isCA = false;

    // Sertifikat u PEM formatu
    @Column(columnDefinition = "TEXT", nullable = false)
    private String pemCertificate;

    // Javni ključ u PEM formatu (za lakše preuzimanje)
    @Column(columnDefinition = "TEXT")
    private String publicKeyPem;

    // Lanac - ko je izdao ovaj sertifikat
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "issuer_certificate_id")
    private Certificate issuerCertificate;

    // Vlasnik sertifikata
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "owner_id", nullable = false)
    private User owner;

    // Revocation status
    @Column(nullable = false)
    private boolean isRevoked = false;

    @Column
    private LocalDateTime revokedAt;

    @Column
    private String revocationReason;

    // Ekstenzije - čuvamo kao JSON string
    @Column(columnDefinition = "TEXT")
    private String extensions; // {"keyUsage": ["keyCertSign"], "basicConstraints": {"ca": true, "pathLen": 2}}

    @Column(nullable = false)
    private LocalDateTime createdAt = LocalDateTime.now();

    @PrePersist
    protected void onCreate() {
        if (createdAt == null) {
            createdAt = LocalDateTime.now();
        }
    }

}
