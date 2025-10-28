package com.example.bsep_team25.passwordManager.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class SharePasswordRequest {

    /** ID originalnog PasswordItem-a */
    @NotNull
    private Long passwordItemId;

    /** Kom korisniku delimo */
    @NotNull
    private Long sharedWithUserId;

    /** Serijski broj cert-a PRIMAOCA – njegov PUBLIC key koristimo za enkripciju kopije */
    @NotBlank
    private String sharedWithCertificateSerialNumber;

    /** Base64 RSA-OAEP ciphertext za PRIMAOCA (kreiran na FE) */
    @NotBlank
    @Size(max = 4096)
    private String ciphertextForRecipientB64;
}
