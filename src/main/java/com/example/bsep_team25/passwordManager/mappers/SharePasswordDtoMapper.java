package com.example.bsep_team25.passwordManager.mappers;

import com.example.bsep_team25.passwordManager.domain.PasswordShare;
import com.example.bsep_team25.passwordManager.dto.SharePasswordResponse;

public final class SharePasswordDtoMapper {
    private SharePasswordDtoMapper() {}

    public static SharePasswordResponse toResponse(PasswordShare sp) {
        return SharePasswordResponse.builder()
                .id(sp.getId())
                .sourceItemId(sp.getSourceItem() != null ? sp.getSourceItem().getId() : null)

                // ✅ ISPRAVKA: Koristi .siteLabel() i .loginHandle() kao u DTO-u!
                .siteLabel(sp.getSourceItem() != null ? sp.getSourceItem().getWebsite() : null)
                .loginHandle(sp.getSourceItem() != null ? sp.getSourceItem().getUsername() : null)

                .ciphertextB64(sp.getCiphertextB64())

                .sharedByUserId(sp.getSharedBy() != null ? sp.getSharedBy().getId() : null)
                .sharedByEmail(sp.getSharedBy() != null ? sp.getSharedBy().getEmail() : null)

                .sharedWithUserId(sp.getSharedWith() != null ? sp.getSharedWith().getId() : null)
                .sharedWithEmail(sp.getSharedWith() != null ? sp.getSharedWith().getEmail() : null)

                .recipientCertificateId(
                        sp.getRecipientCertificate() != null ? sp.getRecipientCertificate().getId() : null)
                .recipientCertificateSerialNumber(
                        sp.getRecipientCertificate() != null ? sp.getRecipientCertificate().getSerialNumber() : null)

                .createdAt(sp.getCreatedAt())
                .build();
    }
}