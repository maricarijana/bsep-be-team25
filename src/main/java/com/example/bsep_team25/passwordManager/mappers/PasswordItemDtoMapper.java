package com.example.bsep_team25.passwordManager.mappers;

import com.example.bsep_team25.passwordManager.domain.PasswordItem;
import com.example.bsep_team25.passwordManager.dto.PasswordItemResponse;

public final class PasswordItemDtoMapper {
    private PasswordItemDtoMapper() {}

    public static PasswordItemResponse toResponse(PasswordItem e) {
        return PasswordItemResponse.builder()
                .id(e.getId())
                .website(e.getWebsite())
                .username(e.getUsername())
                .ciphertextB64(e.getCiphertextB64())
                .encryptionCertificateId(
                        e.getEncryptionCertificate() != null ? e.getEncryptionCertificate().getId() : null)
                .encryptionCertificateSerialNumber(
                        e.getEncryptionCertificate() != null ? e.getEncryptionCertificate().getSerialNumber() : null)
                .encryptionCertificateCommonName(
                        e.getEncryptionCertificate() != null ? e.getEncryptionCertificate().getCommonName() : null)
                .ownerId(e.getOwner() != null ? e.getOwner().getId() : null)
                .ownerEmail(e.getOwner() != null ? e.getOwner().getEmail() : null)
                .createdAt(e.getCreatedAt())
                .build();
    }
}
