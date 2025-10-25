package com.example.bsep_team25.pki.dto;

import com.example.bsep_team25.pki.domain.CertificateType;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CertificateResponse {

    private Long id;
    private String serialNumber;
    private String commonName;
    private String organization;
    private String country;
    private LocalDateTime validFrom;
    private LocalDateTime validUntil;
    private CertificateType certificateType;
    private boolean isCA;
    private boolean isRevoked;
    private String revocationReason;
    private LocalDateTime revokedAt;

    // Issuer info
    private String issuerSerialNumber;
    private String issuerCommonName;

    // Owner info
    private Long ownerId;
    private String ownerEmail;

    // PEM certificate (za download)
    private String pemCertificate;
    private String publicKeyPem;

    private LocalDateTime createdAt;
}
