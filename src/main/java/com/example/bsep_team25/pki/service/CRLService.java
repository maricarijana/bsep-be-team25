package com.example.bsep_team25.pki.service;

import com.example.bsep_team25.model.User;
import com.example.bsep_team25.pki.domain.Certificate;
import com.example.bsep_team25.pki.repository.CertificateRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.cert.X509CRL;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class CRLService {

    private final CertificateRepository certificateRepository;
    private final KeystoreService keystoreService;

    /**
     * Generiše CRL listu za određeni CA sertifikat
     */
    public X509CRL generateCRL(String issuerSerialNumber, User caOwner) throws Exception {
        log.info("Generating CRL for issuer: {}", issuerSerialNumber);

        // Učitaj CA sertifikat
        Certificate caCert = certificateRepository.findBySerialNumber(issuerSerialNumber)
                .orElseThrow(() -> new RuntimeException("CA certificate not found: " + issuerSerialNumber));

        if (!caCert.isCA()) {
            throw new IllegalArgumentException("Only CA certificates can issue CRL");
        }

        // Učitaj privatni ključ CA-a
        PrivateKey caPrivateKey = keystoreService.loadPrivateKey(
                caCert.getSerialNumber(),
                caOwner
        );

        // Kreiraj X500Name za CA
        X500Name issuerName = new X500Name(
                "CN=" + caCert.getCommonName() +
                        ", O=" + caCert.getOrganization() +
                        ", C=" + caCert.getCountry()
        );

        // Postavi validnost CRL-a
        Date thisUpdate = new Date();
        Date nextUpdate = Date.from(
                LocalDateTime.now().plusDays(7).atZone(ZoneId.systemDefault()).toInstant()
        );

        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(issuerName, thisUpdate);
        crlBuilder.setNextUpdate(nextUpdate);

        // Pronađi sve povučene sertifikate koje je izdao ovaj CA
        List<Certificate> revokedCerts = certificateRepository
                .findRevokedByIssuer(issuerSerialNumber);

        log.info("Found {} revoked certificates for CA: {}", revokedCerts.size(), issuerSerialNumber);

        // Dodaj svaki povučeni sertifikat u CRL
        for (Certificate cert : revokedCerts) {
            BigInteger serialNumber = new BigInteger(cert.getSerialNumber());
            Date revocationDate = Date.from(
                    cert.getRevokedAt().atZone(ZoneId.systemDefault()).toInstant()
            );

            int reasonCode = mapReasonToCode(cert.getRevocationReason());

            crlBuilder.addCRLEntry(serialNumber, revocationDate, reasonCode);

            log.info("Added to CRL: Serial={}, Reason={}, Date={}",
                    cert.getSerialNumber(),
                    cert.getRevocationReason(),
                    cert.getRevokedAt());
        }

        // Potpiši CRL privatnim ključem CA-a
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(caPrivateKey);

        X509CRLHolder crlHolder = crlBuilder.build(signer);

        X509CRL crl = new JcaX509CRLConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCRL(crlHolder);

        log.info("CRL generated successfully. Contains {} revoked certificates", revokedCerts.size());
        return crl;
    }

    /**
     * Generiše CRL za ROOT CA (za javni pristup)
     */
    public X509CRL generateRootCRL() throws Exception {
        // Pronađi ROOT CA sertifikat
        Certificate rootCA = certificateRepository.findActiveCA().stream()
                .filter(cert -> cert.getIssuerCertificate() == null) // Root nema issuer-a
                .findFirst()
                .orElseThrow(() -> new RuntimeException("ROOT CA not found"));

        return generateCRL(rootCA.getSerialNumber(), rootCA.getOwner());
    }

    /**
     * Mapira string razlog na X.509 CRLReason code
     */
    private int mapReasonToCode(String reason) {
        if (reason == null || reason.isEmpty()) {
            return CRLReason.unspecified;
        }

        switch (reason.toUpperCase().replace(" ", "_")) {
            case "KEY_COMPROMISE":
                return CRLReason.keyCompromise;
            case "CA_COMPROMISE":
                return CRLReason.cACompromise;
            case "AFFILIATION_CHANGED":
                return CRLReason.affiliationChanged;
            case "SUPERSEDED":
                return CRLReason.superseded;
            case "CESSATION_OF_OPERATION":
                return CRLReason.cessationOfOperation;
            case "CERTIFICATE_HOLD":
                return CRLReason.certificateHold;
            case "REMOVE_FROM_CRL":
                return CRLReason.removeFromCRL;
            case "PRIVILEGE_WITHDRAWN":
                return CRLReason.privilegeWithdrawn;
            case "AA_COMPROMISE":
                return CRLReason.aACompromise;
            default:
                log.warn("Unknown revocation reason: {}, using 'unspecified'", reason);
                return CRLReason.unspecified;
        }
    }
}