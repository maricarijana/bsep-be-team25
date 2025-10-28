package com.example.bsep_team25.passwordManager.service;

import com.example.bsep_team25.model.User;
import com.example.bsep_team25.passwordManager.iservice.PasswordShareService;
import com.example.bsep_team25.passwordManager.domain.PasswordItem;
import com.example.bsep_team25.passwordManager.domain.PasswordShare;
import com.example.bsep_team25.passwordManager.dto.SharePasswordRequest;
import com.example.bsep_team25.passwordManager.dto.SharePasswordResponse;
import com.example.bsep_team25.passwordManager.mappers.SharePasswordDtoMapper;
import com.example.bsep_team25.passwordManager.repository.PasswordItemRepository;
import com.example.bsep_team25.passwordManager.repository.PasswordShareRepository;
import com.example.bsep_team25.passwordManager.support.CurrentUserProvider;
import com.example.bsep_team25.pki.domain.Certificate;
import com.example.bsep_team25.pki.repository.CertificateRepository;
import com.example.bsep_team25.repository.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class PasswordShareServiceImpl implements PasswordShareService {

    private final PasswordShareRepository shares;
    private final PasswordItemRepository items;
    private final UserRepository users;
    private final CertificateRepository certificates;
    private final CurrentUserProvider currentUser;


    @Override
    @Transactional
    public SharePasswordResponse share(SharePasswordRequest req) {
        User me = currentUser.currentUser();

        PasswordItem source = items.findById(req.getPasswordItemId())
                .orElseThrow(() -> new NotFound("Password item not found"));
        if (!source.getOwner().getId().equals(me.getId())) {
            throw new Forbidden("Only the owner can share this password");
        }

        User recipient = users.findById(req.getSharedWithUserId())
                .orElseThrow(() -> new NotFound("User not found"));

        Certificate recipientCert = certificates.findBySerialNumber(req.getSharedWithCertificateSerialNumber())
                .orElseThrow(() -> new NotFound("Certificate not found"));

        if (!recipientCert.getOwner().getId().equals(recipient.getId())) {
            throw new Forbidden("Selected certificate does not belong to the target user");
        }

        PasswordShare entity = PasswordShare.builder()
                .sourceItem(source)
                // ❌ OBRISANO: .siteLabel() i .loginHandle()
                .ciphertextB64(req.getCiphertextForRecipientB64())  // ✅ ISPRAVKA!
                .sharedBy(me)
                .sharedWith(recipient)
                .recipientCertificate(recipientCert)
                .build();

        PasswordShare saved = shares.save(entity);
        return SharePasswordDtoMapper.toResponse(saved);
    }

    @Override
    @Transactional
    public List<SharePasswordResponse> listReceived() {
        Long meId = currentUser.currentUser().getId();
        return shares.findReceivedForList(meId).stream()
                .map(SharePasswordDtoMapper::toResponse)
                .toList();
    }

    @Override
    @Transactional
    public List<SharePasswordResponse> listSent() {
        Long meId = currentUser.currentUser().getId();
        return shares.findSentForList(meId).stream()
                .map(SharePasswordDtoMapper::toResponse)
                .toList();
    }

    @Override
    @Transactional
    public void delete(Long shareId) {
        Long meId = currentUser.currentUser().getId();
        boolean allowed = shares.canUserDeleteShare(meId, shareId);
        if (!allowed) throw new Forbidden("Not allowed to delete this share");
        shares.deleteById(shareId);
    }

    @Override
    @Transactional
    public SharePasswordResponse getReceivedDetail(Long shareId) {
        User me = currentUser.currentUser();

        PasswordShare share = shares.findReceivedDetail(me.getId(), shareId)
                .orElseThrow(() -> new NotFound("Shared password not found or access denied"));

        return SharePasswordDtoMapper.toResponse(share);
    }

    // — exceptions —
    public static class NotFound extends RuntimeException { public NotFound(String m){super(m);} }
    public static class Forbidden extends RuntimeException { public Forbidden(String m){super(m);} }
  //  public static class CryptoFailure extends RuntimeException { public CryptoFailure(String m, Throwable c){super(m,c);} }
}
