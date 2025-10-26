package com.example.bsep_team25.pki.service;

import com.example.bsep_team25.model.Role;
import com.example.bsep_team25.model.User;
import com.example.bsep_team25.pki.domain.*;
import com.example.bsep_team25.pki.repository.CertificateRepository;
import com.example.bsep_team25.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;


@Service
@Slf4j
@RequiredArgsConstructor
public class CertificateService {

    private final CertificateRepository certificateRepository;
    private final UserRepository userRepository;
    private final CertificateGenerator certificateGenerator;
    private final CertificateValidationService validationService;
    private final KeystoreService keystoreService;

    @Transactional
    public Certificate createRootCACertificate( String commonName, String organization,
                                               String country, int validityYears) throws Exception {

        log.info("Creating ROOT CA certificate for: {}", commonName);
        User admin = userRepository.findFirstByRole(Role.ADMIN)
                .orElseThrow(() -> new IllegalStateException("Admin user not found"));

        // Generiši key pair
        KeyPair keyPair = certificateGenerator.generateKeyPair();

        // Kreiraj Subject (za ROOT, Subject = Issuer)
        Subject subject = new Subject();
        subject.setCommonName(commonName);
        subject.setOrganization(organization);
        subject.setCountry(country);
        subject.setPublicKey(keyPair.getPublic());

        // Kreiraj Issuer (self-signed)
        X500Name x500Name = subject.toX500Name();
        Issuer issuer = new Issuer(keyPair.getPrivate(), x500Name);

        // Validnost
        LocalDateTime validFrom = LocalDateTime.now();
        LocalDateTime validUntil = validFrom.plusYears(validityYears);

        // Serial number
        String serialNumber = generateSerialNumber();

        // Generiši sertifikat
        X509Certificate x509Cert = certificateGenerator.generateCertificate(
                subject,
                issuer,
                validFrom,
                validUntil,
                serialNumber,
                true, // isCA
                null, // pathLength (unlimited za ROOT)
                List.of("keyCertSign", "cRLSign"),
                null,
                null
        );

        // Konvertuj u PEM
        String pemCert = x509ToPem(x509Cert);
        String publicKeyPem = publicKeyToPem(keyPair.getPublic());

        // Sačuvaj u bazu
        Certificate certificate = Certificate.builder()
                .serialNumber(serialNumber)
                .commonName(commonName)
                .organization(organization)
                .country(country)
                .validFrom(validFrom)
                .validUntil(validUntil)
                .certificateType(CertificateType.ROOT_CA)
                .isCA(true)
                .pemCertificate(pemCert)
                .publicKeyPem(publicKeyPem)
                .issuerCertificate(null) // self-signed
                .owner(admin)
                .extensions("{\"keyUsage\": [\"keyCertSign\", \"cRLSign\"], \"basicConstraints\": {\"ca\": true}}")
                .build();

        certificate = certificateRepository.save(certificate);

        // Sačuvaj privatni ključ u keystore
        keystoreService.savePrivateKeyAndCertificate(
                serialNumber,
                keyPair.getPrivate(),
                x509Cert,
                new java.security.cert.Certificate[]{x509Cert},
                admin
        );

        log.info("ROOT CA certificate created with serial: {}", serialNumber);
        return certificate;
    }

    @Transactional
    public Certificate createIntermediateCACertificate(
            User caUser,
            String commonName,
            String organization,
            String country,
            int validityYears,
            String issuerSerialNumber,
            Integer pathLength) throws Exception {

        log.info("Creating INTERMEDIATE CA certificate for: {}", commonName);

        // Učitaj CA izdavaoca
        Certificate issuerCert = certificateRepository.findBySerialNumber(issuerSerialNumber)
                .orElseThrow(() -> new IllegalArgumentException("Issuer certificate not found"));

        // Validacija izdavaoca
        validationService.validateIssuerBeforeSigning(issuerCert);

        // Proveri da li trajanje ne prelazi trajanje izdavaoca
        LocalDateTime validFrom = LocalDateTime.now();
        LocalDateTime validUntil = validFrom.plusYears(validityYears);

        if (validUntil.isAfter(issuerCert.getValidUntil())) {
            throw new IllegalArgumentException("Certificate validity period exceeds issuer's validity");
        }

        // Generiši key pair
        KeyPair keyPair = certificateGenerator.generateKeyPair();

        // Subject
        Subject subject = new Subject();
        subject.setCommonName(commonName);
        subject.setOrganization(organization);
        subject.setCountry(country);
        subject.setPublicKey(keyPair.getPublic());

        // Issuer
        PrivateKey issuerPrivateKey = keystoreService.loadPrivateKey(issuerSerialNumber, issuerCert.getOwner());
        X500Name issuerX500Name = buildX500Name(issuerCert);
        Issuer issuer = new Issuer(issuerPrivateKey, issuerX500Name);

        // Serial number
        String serialNumber = generateSerialNumber();

        // Generiši sertifikat
        X509Certificate x509Cert = certificateGenerator.generateCertificate(
                subject,
                issuer,
                validFrom,
                validUntil,
                serialNumber,
                true,
                pathLength,
                List.of("keyCertSign", "cRLSign"),
                null,
                null
        );

        String pemCert = x509ToPem(x509Cert);
        String publicKeyPem = publicKeyToPem(keyPair.getPublic());

        // Build certificate chain
        List<java.security.cert.Certificate> chain = buildCertificateChain(issuerCert, caUser);
        chain.add(0, x509Cert);

        // Sačuvaj u bazu
        Certificate certificate = Certificate.builder()
                .serialNumber(serialNumber)
                .commonName(commonName)
                .organization(organization)
                .country(country)
                .validFrom(validFrom)
                .validUntil(validUntil)
                .certificateType(CertificateType.INTERMEDIATE_CA)
                .isCA(true)
                .pemCertificate(pemCert)
                .publicKeyPem(publicKeyPem)
                .issuerCertificate(issuerCert)
                .owner(caUser)
                .extensions("{\"keyUsage\": [\"keyCertSign\", \"cRLSign\"], \"basicConstraints\": {\"ca\": true, \"pathLen\": " + pathLength + "}}")
                .build();

        certificate = certificateRepository.save(certificate);

        // Sačuvaj privatni ključ + lanac
        keystoreService.savePrivateKeyAndCertificate(
                serialNumber,
                keyPair.getPrivate(),
                x509Cert,
                chain.toArray(new java.security.cert.Certificate[0]),
                caUser
        );

        log.info("INTERMEDIATE CA certificate created with serial: {}", serialNumber);
        return certificate;
    }

    @Transactional
    public Certificate createEndEntityCertificate(
            User endUser,
            String commonName,
            String organization,
            String country,
            int validityYears,
            String issuerSerialNumber,
            List<String> keyUsage,
            List<String> extendedKeyUsage,
            List<String> subjectAlternativeNames) throws Exception {

        log.info("Creating END ENTITY certificate for: {}", commonName);

        Certificate issuerCert = certificateRepository.findBySerialNumber(issuerSerialNumber)
                .orElseThrow(() -> new IllegalArgumentException("Issuer certificate not found"));

        validationService.validateIssuerBeforeSigning(issuerCert);

        LocalDateTime validFrom = LocalDateTime.now();
        LocalDateTime validUntil = validFrom.plusYears(validityYears);

        if (validUntil.isAfter(issuerCert.getValidUntil())) {
            throw new IllegalArgumentException("Certificate validity period exceeds issuer's validity");
        }

        KeyPair keyPair = certificateGenerator.generateKeyPair();

        Subject subject = new Subject();
        subject.setCommonName(commonName);
        subject.setOrganization(organization);
        subject.setCountry(country);
        subject.setPublicKey(keyPair.getPublic());

        PrivateKey issuerPrivateKey = keystoreService.loadPrivateKey(issuerSerialNumber, issuerCert.getOwner());
        X500Name issuerX500Name = buildX500Name(issuerCert);
        Issuer issuer = new Issuer(issuerPrivateKey, issuerX500Name);

        String serialNumber = generateSerialNumber();

        X509Certificate x509Cert = certificateGenerator.generateCertificate(
                subject,
                issuer,
                validFrom,
                validUntil,
                serialNumber,
                false, // not CA
                null,
                keyUsage,
                extendedKeyUsage,
                subjectAlternativeNames
        );

        String pemCert = x509ToPem(x509Cert);
        String publicKeyPem = publicKeyToPem(keyPair.getPublic());

        Certificate certificate = Certificate.builder()
                .serialNumber(serialNumber)
                .commonName(commonName)
                .organization(organization)
                .country(country)
                .validFrom(validFrom)
                .validUntil(validUntil)
                .certificateType(CertificateType.END_ENTITY)
                .isCA(false)
                .pemCertificate(pemCert)
                .publicKeyPem(publicKeyPem)
                .issuerCertificate(issuerCert)
                .owner(endUser)
                .build();

        certificate = certificateRepository.save(certificate);

        // Za EE sertifikat NE čuvamo privatni ključ na serveru!
        log.info("END ENTITY certificate created with serial: {}", serialNumber);
        return certificate;
    }

    private String generateSerialNumber() {
        SecureRandom random = new SecureRandom();
        BigInteger serialNumber = new BigInteger(64, random);
        return serialNumber.toString(); // Samo broj bez hex
    }

    private String x509ToPem(X509Certificate cert) throws Exception {
        StringWriter sw = new StringWriter();
        sw.write("-----BEGIN CERTIFICATE-----\n");
        sw.write(Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(cert.getEncoded()));
        sw.write("\n-----END CERTIFICATE-----\n");
        return sw.toString();
    }

    private String publicKeyToPem(java.security.PublicKey publicKey) throws Exception {
        StringWriter sw = new StringWriter();
        sw.write("-----BEGIN PUBLIC KEY-----\n");
        sw.write(Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(publicKey.getEncoded()));
        sw.write("\n-----END PUBLIC KEY-----\n");
        return sw.toString();
    }

    private X500Name buildX500Name(Certificate cert) {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.CN, cert.getCommonName());
        builder.addRDN(BCStyle.O, cert.getOrganization());
        if (cert.getCountry() != null) builder.addRDN(BCStyle.C, cert.getCountry());
        return builder.build();
    }

    private List<java.security.cert.Certificate> buildCertificateChain(Certificate issuerCert, User user) throws Exception {
        List<java.security.cert.Certificate> chain = new ArrayList<>();
        Certificate current = issuerCert;

        while (current != null) {
            java.security.cert.Certificate cert = keystoreService.loadCertificate(current.getSerialNumber(), current.getOwner());
            chain.add(cert);
            current = current.getIssuerCertificate();
        }

        return chain;
    }

    public List<Certificate> getAllCertificates() {
        return certificateRepository.findAll();
    }

    public List<Certificate> getCertificatesForUser(User user) {
        return certificateRepository.findByOwnerId(user.getId());
    }

    public List<Certificate> getActiveCACertificates() {
        return certificateRepository.findActiveCA();
    }

    @Transactional
    public void revokeCertificate(String serialNumber, String reason) {
        Certificate cert = certificateRepository.findBySerialNumber(serialNumber)
                .orElseThrow(() -> new IllegalArgumentException("Certificate not found"));

        cert.setRevoked(true);
        cert.setRevokedAt(LocalDateTime.now());
        cert.setRevocationReason(reason);

        certificateRepository.save(cert);
        log.info("Certificate revoked: {} - Reason: {}", serialNumber, reason);
    }
}
