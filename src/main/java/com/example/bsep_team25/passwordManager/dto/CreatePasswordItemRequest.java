package com.example.bsep_team25.passwordManager.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class CreatePasswordItemRequest {

    @NotBlank
    @Size(max = 255)
    private String website;

    @NotBlank
    @Size(max = 255)
    private String username;

    /** Base64 RSA-OAEP ciphertext šifrovan JAVNIM ključem vlasnika (FE side) */
    @NotBlank
    @Size(max = 4096)
    private String ciphertextB64;

    /** Serijski broj X.509 sertifikata vlasnika (iz tvoje PKI šeme) */
    @NotBlank
    private String certificateSerialNumber;
}
