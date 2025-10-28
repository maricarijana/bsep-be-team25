package com.example.bsep_team25.passwordManager.dto;

import lombok.Builder;
import lombok.Value;

import java.time.Instant;

@Value
@Builder
public class PasswordItemResponse {
    Long id;
    String website;
    String username;

    /** Base64 RSA-OAEP ciphertext (kako je snimljeno u bazi) */
    String ciphertextB64;

    /** Meta: vlasnik i cert referenca (lightweight) */
    Long encryptionCertificateId;
    String encryptionCertificateSerialNumber;
    String encryptionCertificateCommonName;

    Long ownerId;
    String ownerEmail;

    Instant createdAt;
}
