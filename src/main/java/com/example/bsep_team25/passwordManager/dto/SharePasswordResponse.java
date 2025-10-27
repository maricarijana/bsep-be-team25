package com.example.bsep_team25.passwordManager.dto;

import lombok.Builder;
import lombok.Value;

import java.time.Instant;

@Value
@Builder
public class SharePasswordResponse {
    Long id;

    /** referenca na original */
    Long sourceItemId;

    /** duplicirani meta-podaci radi lakšeg prikaza */
    String siteLabel;
    String loginHandle;

    /** Base64 RSA-OAEP ciphertext enkriptovan javnim ključem PRIMAOCA */
    String ciphertextB64;

    /** ko je podelio / kome je podeljeno */
    Long sharedByUserId;
    String sharedByEmail;

    Long sharedWithUserId;
    String sharedWithEmail;

    /** cert primaoca (koristi se njegov PUBLIC key) */
    Long recipientCertificateId;
    String recipientCertificateSerialNumber;

    Instant createdAt;
}
