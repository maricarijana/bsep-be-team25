package com.example.bsep_team25.passwordManager.service;

import com.example.bsep_team25.model.User;
import com.example.bsep_team25.passwordManager.domain.PasswordItem;
import com.example.bsep_team25.passwordManager.dto.CreatePasswordItemRequest;
import com.example.bsep_team25.passwordManager.dto.PasswordItemResponse;
import com.example.bsep_team25.passwordManager.mappers.PasswordItemDtoMapper;
import com.example.bsep_team25.passwordManager.repository.PasswordItemRepository;
import com.example.bsep_team25.passwordManager.iservice.PasswordItemService;
import com.example.bsep_team25.passwordManager.support.CurrentUserProvider;
import com.example.bsep_team25.pki.domain.Certificate;
import com.example.bsep_team25.pki.repository.CertificateRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.List;
@Service
@RequiredArgsConstructor
@Slf4j
public class PasswordItemServiceImpl implements PasswordItemService {

    private final PasswordItemRepository items;
    private final CertificateRepository certificates;
    private final CurrentUserProvider currentUser;

    private static final boolean USE_SHA256 = true; // default sigurniji hash

    @Override
    @Transactional
    public PasswordItemResponse create(CreatePasswordItemRequest req) {
        User me = currentUser.currentUser();

        Certificate cert = certificates.findBySerialNumber(req.getCertificateSerialNumber())
                .orElseThrow(() -> new NotFound("Certificate not found"));

        if (!cert.getOwner().getId().equals(me.getId())) {
            throw new Forbidden("You can only use your own certificates");
        }

//        // PEM → X509 → RSA-OAEP
//        X509Certificate x509 = rsa.parseX509FromPem(cert.getPemCertificate());
//        final String ciphertextB64;
//        try {
//            ciphertextB64 = rsa.encryptWithCertificate(req.getPassword(), x509, USE_SHA256);
//        } catch (GeneralSecurityException e) {
//            throw new CryptoFailure("RSA-OAEP encryption failed", e);
//        }

        PasswordItem entity = PasswordItem.builder()
                .website(req.getWebsite())
                .username(req.getUsername())
                .ciphertextB64(req.getCiphertextB64())
                .owner(me)
                .encryptionCertificate(cert)
                .build();

        PasswordItem saved = items.save(entity);
        return PasswordItemDtoMapper.toResponse(saved);
    }

    @Override
    @Transactional
    public List<PasswordItemResponse> listMine() {
        Long meId =currentUser.currentUser().getId();
        return items.findForList(meId).stream()
                .map(PasswordItemDtoMapper::toResponse)
                .toList();
    }

    @Override
    @Transactional
    public void delete(Long itemId) {
        Long meId = currentUser.currentUser().getId();
        boolean isOwner = items.existsByIdAndOwnerId(itemId, meId);
        if (!isOwner) throw new Forbidden("You can only delete your own password items");
        items.deleteById(itemId);
    }
    @Override
    @Transactional
    public PasswordItemResponse getDetail(Long itemId) {
        User me = currentUser.currentUser();

        PasswordItem item = items.findDetail(me.getId(), itemId)
                .orElseThrow(() -> new NotFound("Password item not found or access denied"));

        return PasswordItemDtoMapper.toResponse(item);
    }

    // — exceptions —
    public static class NotFound extends RuntimeException { public NotFound(String m){super(m);} }
    public static class Forbidden extends RuntimeException { public Forbidden(String m){super(m);} }
   // public static class CryptoFailure extends RuntimeException { public CryptoFailure(String m, Throwable c){super(m,c);} }
}
