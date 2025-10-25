package com.example.bsep_team25.pki.service;
import com.example.bsep_team25.pki.domain.Certificate;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.util.Base64;

@Service
@Slf4j
public class CertificateValidationService {

    public void validateIssuerBeforeSigning(Certificate issuerCert) {
        // 1. Provera da li je CA sertifikat
        if (!issuerCert.isCA()) {
            throw new IllegalArgumentException("Issuer certificate must be a CA certificate");
        }

        // 2. Provera validnosti perioda
        LocalDateTime now = LocalDateTime.now();
        if (now.isBefore(issuerCert.getValidFrom()) || now.isAfter(issuerCert.getValidUntil())) {
            throw new IllegalArgumentException("Issuer certificate is not valid (expired or not yet valid)");
        }

        // 3. Provera da li je povučen
        if (issuerCert.isRevoked()) {
            throw new IllegalArgumentException("Issuer certificate has been revoked");
        }

        // 4. Provera digitalnog potpisa (ako ima issuer-a)
        if (issuerCert.getIssuerCertificate() != null) {
            validateDigitalSignature(issuerCert);
        }

        log.info("Issuer certificate validation passed for: {}", issuerCert.getSerialNumber());
    }

    public void validateDigitalSignature(Certificate cert) {
        try {
            // Učitaj sertifikat iz PEM formata
            X509Certificate x509Cert = pemToX509Certificate(cert.getPemCertificate());

            // Ako je self-signed, verifikuj sa svojim javnim ključem
            if (cert.getIssuerCertificate() == null) {
                x509Cert.verify(x509Cert.getPublicKey());
            } else {
                // Inače, verifikuj sa javnim ključem izdavaoca
                X509Certificate issuerX509 = pemToX509Certificate(cert.getIssuerCertificate().getPemCertificate());
                x509Cert.verify(issuerX509.getPublicKey());
            }

            log.info("Digital signature valid for certificate: {}", cert.getSerialNumber());
        } catch (Exception e) {
            throw new IllegalArgumentException("Digital signature validation failed: " + e.getMessage());
        }
    }

    public void validateCertificateChain(Certificate cert) {
        Certificate current = cert;
        int depth = 0;

        while (current != null) {
            // Proveri validnost svakog sertifikata u lancu
            LocalDateTime now = LocalDateTime.now();
            if (now.isBefore(current.getValidFrom()) || now.isAfter(current.getValidUntil())) {
                throw new IllegalArgumentException("Certificate in chain is not valid: " + current.getSerialNumber());
            }

            if (current.isRevoked()) {
                throw new IllegalArgumentException("Certificate in chain is revoked: " + current.getSerialNumber());
            }

            // Proveri potpis
            if (current.getIssuerCertificate() != null) {
                validateDigitalSignature(current);
            }

            current = current.getIssuerCertificate();
            depth++;

            if (depth > 10) {
                throw new IllegalArgumentException("Certificate chain too deep (possible loop)");
            }
        }

        log.info("Certificate chain validation passed");
    }

    private X509Certificate pemToX509Certificate(String pem) throws Exception {
        String cleanPem = pem.replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s", "");

        byte[] certBytes = Base64.getDecoder().decode(cleanPem);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));
    }
}
