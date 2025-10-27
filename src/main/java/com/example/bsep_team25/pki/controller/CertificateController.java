package com.example.bsep_team25.pki.controller;

import com.example.bsep_team25.model.Role;
import com.example.bsep_team25.model.User;
import com.example.bsep_team25.pki.domain.Certificate;
import com.example.bsep_team25.pki.domain.KeyStoreInfo;
import com.example.bsep_team25.pki.dto.CertificateResponse;
import com.example.bsep_team25.pki.dto.CreateCertificateRequest;
import com.example.bsep_team25.pki.dto.RevokeCertificateRequest;
import com.example.bsep_team25.pki.repository.KeystoreInfoRepository;
import com.example.bsep_team25.pki.service.CRLService;
import com.example.bsep_team25.pki.service.CertificateService;
import com.example.bsep_team25.pki.service.CertificateTemplateService;
import com.example.bsep_team25.pki.service.EncryptionService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.security.cert.X509CRL;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/pki/certificates")
@RequiredArgsConstructor
@Slf4j
public class CertificateController {

    private final CRLService crlService;
    private final CertificateService certificateService;
    private final KeystoreInfoRepository keystoreInfoRepository;
    private final EncryptionService encryptionService;
    private final CertificateTemplateService certificateTemplateService;

    /**
     * Admin kreira ROOT CA sertifikat
     */
    @PostMapping("/root")
   @PreAuthorize("hasAuthority('ADMIN')") // možeš uključiti kasnije kad bude radio JWT
    public ResponseEntity<?> createRootCA(
           //@AuthenticationPrincipal User admin,
            @RequestBody CreateCertificateRequest request) {
        try {
            Certificate cert = certificateService.createRootCACertificate(
                    request.getCommonName(),
                    request.getOrganization(),
                    request.getCountry(),
                    request.getValidityYears() != null ? request.getValidityYears() : 10
            );

            return ResponseEntity.ok(mapToResponse(cert));
        } catch (Exception e) {
            log.error("Error creating ROOT CA: ", e);
            return ResponseEntity.badRequest().body("Error: " + e.getMessage());
        }
    }


    /**
     * Admin ili CA_USER kreira INTERMEDIATE CA sertifikat
     */
    @PostMapping("/intermediate")
    @PreAuthorize("hasAuthority('ADMIN') or hasAuthority('CA_USER')")
    public ResponseEntity<?> createIntermediateCA(
            @AuthenticationPrincipal User currentUser,
            @RequestBody CreateCertificateRequest request) {
        try {
            Certificate cert = certificateService.createIntermediateCACertificate(
                    request.getOwnerId(),      // Long (može biti null)
                    currentUser,               // trenutno ulogovani
                    request.getCommonName(),
                    request.getOrganization(),
                    request.getCountry(),
                    request.getValidityYears() != null ? request.getValidityYears() : 5,
                    request.getIssuerSerialNumber(),
                    request.getPathLength()
            );

            return ResponseEntity.ok(mapToResponse(cert));

        } catch (SecurityException e) {
            log.error("Security error: ", e);
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(e.getMessage());
        } catch (IllegalArgumentException e) {
            log.error("Validation error: ", e);
            return ResponseEntity.badRequest().body(e.getMessage());
        } catch (Exception e) {
            log.error("Error creating INTERMEDIATE CA: ", e);
            return ResponseEntity.badRequest().body("Error: " + e.getMessage());
        }
    }


    /**
     * Kreiranje END ENTITY sertifikata iz upload-ovanog CSR-a
     * SA OPCIONALNOM PODRŠKOM ZA ŠABLONE
     */
    @PostMapping("/end-entity/from-csr")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> createEndEntityFromCSR(
            @AuthenticationPrincipal User user,
            @RequestParam("csr") MultipartFile csrFile,
            @RequestParam("issuerSerialNumber") String issuerSerialNumber,
            @RequestParam("validityYears") Integer validityYears,
            @RequestParam(value = "templateName", required = false) String templateName) { // ✅ NOVO

        try {
            if (csrFile.isEmpty()) {
                return ResponseEntity.badRequest().body(Map.of("error", "CSR file is required"));
            }

            String csrPem = new String(csrFile.getBytes(), java.nio.charset.StandardCharsets.UTF_8);

            // ✅ NOVA LOGIKA - Validacija prema šablonu ako je naveden
            if (templateName != null && !templateName.isBlank()) {
                log.info("Validating CSR against template: {}", templateName);

                // Parsiramo CSR da izvučemo CN i SAN
                Map<String, Object> csrData = certificateService.parseCSR(csrPem);

                // Validacija prema šablonu
                certificateTemplateService.validateCSRAgainstTemplate(
                        templateName,
                        (String) csrData.get("commonName"),
                        (List<String>) csrData.get("subjectAlternativeNames"),
                        validityYears
                );
            }

            // Standardna logika za kreiranje sertifikata iz CSR-a
            Certificate cert = certificateService.createEndEntityFromCSR(
                    user,
                    csrPem,
                    issuerSerialNumber,
                    validityYears != null ? validityYears : 1
            );

            return ResponseEntity.ok(Map.of(
                    "message", "Certificate issued successfully from CSR!",
                    "certificate", mapToResponse(cert)
            ));

        } catch (IllegalArgumentException e) {
            log.error("CSR validation error: ", e);
            return ResponseEntity.badRequest().body(Map.of("error", "CSR validation failed: " + e.getMessage()));
        } catch (Exception e) {
            log.error("Error creating certificate from CSR: ", e);
            return ResponseEntity.badRequest().body(Map.of("error", "Failed to create certificate: " + e.getMessage()));
        }
    }
    /**
     * Admin vidi sve sertifikate
     */
    @GetMapping("/all")
    @PreAuthorize("hasAuthority('ADMIN')")
    public ResponseEntity<List<CertificateResponse>> getAllCertificates() {
        List<Certificate> certificates = certificateService.getAllCertificates();
        return ResponseEntity.ok(
                certificates.stream()
                        .map(this::mapToResponse)
                        .collect(Collectors.toList())
        );
    }

    /**
     * Korisnik vidi svoje sertifikate
     */
    /**
     * Korisnik vidi svoje sertifikate
     * CA_USER vidi sertifikate iz svog lanca, ostali samo direktno svoje
     */
    @GetMapping("/my")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<List<CertificateResponse>> getMyCertificates(
            @AuthenticationPrincipal User user) {

        List<Certificate> certificates;

        // CA_USER vidi sertifikate iz svog lanca, ostali samo direktno svoje
        if (user.getRole() == Role.CA_USER) {
            certificates = certificateService.getCertificatesInUserChain(user);
        } else {
            certificates = certificateService.getCertificatesForUser(user);
        }

        return ResponseEntity.ok(
                certificates.stream()
                        .map(this::mapToResponse)
                        .collect(Collectors.toList())
        );
    }

    /**
     * Dobavi aktivne CA sertifikate (za dropdown pri izdavanju)
     */
    @GetMapping("/active-cas")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<List<CertificateResponse>> getActiveCAs() {
        List<Certificate> caCertificates = certificateService.getActiveCACertificates();
        return ResponseEntity.ok(
                caCertificates.stream()
                        .map(this::mapToResponse)
                        .collect(Collectors.toList())
        );
    }

    /**
     * Preuzmi sertifikat po serial number
     */
    @GetMapping("/{serialNumber}")
//@PreAuthorize("hasRole('ADMIN')")  // Samo admin može videti lozinke
    public ResponseEntity<?> getKeystorePassword(
            @PathVariable String serialNumber,
            @AuthenticationPrincipal User user) {
        try {
            // Učitaj keystore info
            KeyStoreInfo keystoreInfo = keystoreInfoRepository.findByAlias(serialNumber)
                    .orElseThrow(() -> new RuntimeException("Keystore not found"));

            // Dekriptuj lozinke
            String keystorePassword = encryptionService.decrypt(
                    keystoreInfo.getEncryptedKeystorePassword(),
                    user.getId(),
                    keystoreInfo.getSalt(),
                    keystoreInfo.getIv()
            );

            String keyPassword = encryptionService.decrypt(
                    keystoreInfo.getEncryptedKeyPassword(),
                    user.getId(),
                    keystoreInfo.getSalt(),
                    keystoreInfo.getIv()
            );

            return ResponseEntity.ok(Map.of(
                    "keystorePath", keystoreInfo.getKeystorePath(),
                    "keystorePassword", keystorePassword,
                    "keyPassword", keyPassword,
                    "alias", serialNumber
            ));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error: " + e.getMessage());
        }
    }

    /**
     * Povuci sertifikat (revoke)
     */
    @PostMapping("/revoke")
    @PreAuthorize("hasAuthority('ADMIN') or hasAuthority('CA_USER')")
    public ResponseEntity<?> revokeCertificate(@RequestBody RevokeCertificateRequest request) {
        try {
            certificateService.revokeCertificate(request.getSerialNumber(), request.getReason());

            // ✅ Vrati JSON objekat umesto plain text
            return ResponseEntity.ok(Map.of(
                    "message", "Certificate revoked successfully",
                    "serialNumber", request.getSerialNumber(),
                    "reason", request.getReason()
            ));

        } catch (Exception e) {
            log.error("Error revoking certificate: ", e);

            // ✅ I error vrati kao JSON
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "Failed to revoke certificate",
                    "message", e.getMessage()
            ));
        }
    }

    // Helper method za mapiranje
    private CertificateResponse mapToResponse(Certificate cert) {
        CertificateResponse.CertificateResponseBuilder builder = CertificateResponse.builder()
                .id(cert.getId())
                .serialNumber(cert.getSerialNumber())
                .commonName(cert.getCommonName())
                .organization(cert.getOrganization())
                .country(cert.getCountry())
                .validFrom(cert.getValidFrom())
                .validUntil(cert.getValidUntil())
                .certificateType(cert.getCertificateType())
                .isCA(cert.isCA())
                .isRevoked(cert.isRevoked())
                .revocationReason(cert.getRevocationReason())
                .revokedAt(cert.getRevokedAt())
                .ownerId(cert.getOwner().getId())
                .ownerEmail(cert.getOwner().getEmail())
                .pemCertificate(cert.getPemCertificate())
                .publicKeyPem(cert.getPublicKeyPem())
                .createdAt(cert.getCreatedAt());

        if (cert.getIssuerCertificate() != null) {
            builder.issuerSerialNumber(cert.getIssuerCertificate().getSerialNumber())
                    .issuerCommonName(cert.getIssuerCertificate().getCommonName());
        }

        return builder.build();
    }

    /**
     * Javno dostupan endpoint za preuzimanje CRL liste
     * Ne zahteva autentifikaciju jer klijenti moraju moći da provere povučenost
     */
    @GetMapping(value = "/crl", produces = "application/pkix-crl")
    public ResponseEntity<byte[]> getCRL(
            @RequestParam(required = false) String issuer) {
        try {
            X509CRL crl;

            if (issuer != null) {
                // Pronađi CA vlasnika
                Certificate caCert = certificateService.getCertificateBySerialNumber(issuer);
                crl = crlService.generateCRL(issuer, caCert.getOwner());
            } else {
                // Generiši ROOT CA CRL
                crl = crlService.generateRootCRL();
            }

            byte[] crlBytes = crl.getEncoded();

            log.info("CRL downloaded: {} bytes", crlBytes.length);

            return ResponseEntity.ok()
                    .header("Content-Disposition", "attachment; filename=\"ca.crl\"")
                    .header("Cache-Control", "max-age=3600") // Cache 1 sat
                    .body(crlBytes);

        } catch (Exception e) {
            log.error("Error generating CRL: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(("Error: " + e.getMessage()).getBytes());
        }
    }

    /**
     * Admin pregled CRL sadržaja u JSON formatu
     */
    @GetMapping("/crl/info")
    @PreAuthorize("hasAuthority('ADMIN')")
    public ResponseEntity<?> getCRLInfo(@RequestParam(required = false) String issuer) {
        try {
            List<Certificate> revokedCerts;

            if (issuer != null) {
                revokedCerts = certificateService.getRevokedCertificatesByIssuer(issuer);
            } else {
                revokedCerts = certificateService.getAllRevokedCertificates();
            }

            return ResponseEntity.ok(Map.of(
                    "totalRevoked", revokedCerts.size(),
                    "certificates", revokedCerts.stream()
                            .map(cert -> Map.of(
                                    "serialNumber", cert.getSerialNumber(),
                                    "commonName", cert.getCommonName(),
                                    "revokedAt", cert.getRevokedAt(),
                                    "reason", cert.getRevocationReason()
                            ))
                            .collect(Collectors.toList())
            ));

        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error: " + e.getMessage());
        }
    }
}
