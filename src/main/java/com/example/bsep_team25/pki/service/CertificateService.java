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
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x500.RDN;
import java.io.StringReader;
import java.util.ArrayList;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.openssl.PEMParser;
import java.util.Base64;
import java.util.HashMap;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.util.*;


@Service
@Slf4j
@RequiredArgsConstructor
public class CertificateService {

    private final CertificateRepository certificateRepository;
    private final UserRepository userRepository;
    private final CertificateGenerator certificateGenerator;
    private final CertificateValidationService validationService;
    private final KeystoreService keystoreService;
    private final CSRProcessingService csrProcessingService;

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

        validateOrganization(caUser, organization);

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

//    @Transactional
//    public Certificate createEndEntityCertificate(
//            User endUser,
//            String commonName,
//            String organization,
//            String country,
//            int validityYears,
//            String issuerSerialNumber,
//            List<String> keyUsage,
//            List<String> extendedKeyUsage,
//            List<String> subjectAlternativeNames) throws Exception {
//
//        log.info("Creating END ENTITY certificate for: {}", commonName);
//
//        Certificate issuerCert = certificateRepository.findBySerialNumber(issuerSerialNumber)
//                .orElseThrow(() -> new IllegalArgumentException("Issuer certificate not found"));
//
//        validationService.validateIssuerBeforeSigning(issuerCert);
//
//        validateOrganization(endUser, organization);
//
//        LocalDateTime validFrom = LocalDateTime.now();
//        LocalDateTime validUntil = validFrom.plusYears(validityYears);
//
//        if (validUntil.isAfter(issuerCert.getValidUntil())) {
//            throw new IllegalArgumentException("Certificate validity period exceeds issuer's validity");
//        }
//
//        KeyPair keyPair = certificateGenerator.generateKeyPair();
//
//        Subject subject = new Subject();
//        subject.setCommonName(commonName);
//        subject.setOrganization(organization);
//        subject.setCountry(country);
//        subject.setPublicKey(keyPair.getPublic());
//
//        PrivateKey issuerPrivateKey = keystoreService.loadPrivateKey(issuerSerialNumber, issuerCert.getOwner());
//        X500Name issuerX500Name = buildX500Name(issuerCert);
//        Issuer issuer = new Issuer(issuerPrivateKey, issuerX500Name);
//
//        String serialNumber = generateSerialNumber();
//
//        X509Certificate x509Cert = certificateGenerator.generateCertificate(
//                subject,
//                issuer,
//                validFrom,
//                validUntil,
//                serialNumber,
//                false, // not CA
//                null,
//                keyUsage,
//                extendedKeyUsage,
//                subjectAlternativeNames
//        );
//
//        String pemCert = x509ToPem(x509Cert);
//        String publicKeyPem = publicKeyToPem(keyPair.getPublic());
//
//        Certificate certificate = Certificate.builder()
//                .serialNumber(serialNumber)
//                .commonName(commonName)
//                .organization(organization)
//                .country(country)
//                .validFrom(validFrom)
//                .validUntil(validUntil)
//                .certificateType(CertificateType.END_ENTITY)
//                .isCA(false)
//                .pemCertificate(pemCert)
//                .publicKeyPem(publicKeyPem)
//                .issuerCertificate(issuerCert)
//                .owner(endUser)
//                .build();
//
//        certificate = certificateRepository.save(certificate);
//
//        // Za EE sertifikat NE čuvamo privatni ključ na serveru!
//        log.info("END ENTITY certificate created with serial: {}", serialNumber);
//        return certificate;
//    }

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

    @Transactional
    public Certificate createIntermediateCACertificate(
            Long ownerId,                    // ✅ LONG
            User currentUser,
            String commonName,
            String organization,
            String country,
            int validityYears,
            String issuerSerialNumber,
            Integer pathLength) throws Exception {

        log.info("Creating INTERMEDIATE CA certificate with ownerId: {} by user: {}",
                ownerId, currentUser.getEmail());

        // Odredi vlasnika
        User owner = determineOwner(ownerId, currentUser);

        // Pozovi originalnu metodu
        return createIntermediateCACertificate(
                owner,
                commonName,
                organization,
                country,
                validityYears,
                issuerSerialNumber,
                pathLength
        );
    }

    /**
     * Određuje ko će biti vlasnik sertifikata na osnovu uloge trenutnog korisnika.
     *
     * @param ownerId ID željenog vlasnika (null = currentUser)
     * @param currentUser Trenutno ulogovani korisnik
     * @return User koji će biti vlasnik sertifikata
     * @throws SecurityException Ako korisnik nema permisiju
     * @throws IllegalArgumentException Ako korisnik nije pronađen ili nema ispravnu ulogu
     */
    private User determineOwner(Long ownerId, User currentUser) {   // ✅ LONG
        if (currentUser.getRole() == Role.ADMIN) {
            // Admin može kreirati za druge korisnike
            if (ownerId != null) {
                log.info("Admin {} creating certificate for user ID: {}",
                        currentUser.getEmail(), ownerId);

                User owner = userRepository.findById(ownerId)
                        .orElseThrow(() -> new IllegalArgumentException(
                                "User not found with ID: " + ownerId));

                // Provera da je target user CA_USER ili ADMIN
                if (owner.getRole() != Role.CA_USER && owner.getRole() != Role.ADMIN) {
                    throw new IllegalArgumentException(
                            "Owner must be a CA_USER or ADMIN, but found: " + owner.getRole());
                }

                log.info("Certificate will be owned by: {} ({})",
                        owner.getEmail(), owner.getRole());
                return owner;
            } else {
                // Ako ownerId nije poslat, admin kreira za sebe
                log.info("Admin {} creating certificate for themselves", currentUser.getEmail());
                return currentUser;
            }
        } else if (currentUser.getRole() == Role.CA_USER) {
            // CA_USER može kreirati samo za sebe
            if (ownerId != null && !ownerId.equals(currentUser.getId())) {
                log.error("CA_USER {} attempted to create certificate for user ID: {}",
                        currentUser.getEmail(), ownerId);
                throw new SecurityException(
                        "CA_USER can only create certificates for themselves. " +
                                "Attempted to create for user ID: " + ownerId);
            }
            log.info("CA_USER {} creating certificate for themselves", currentUser.getEmail());
            return currentUser;
        } else {
            log.error("User {} with role {} attempted to create INTERMEDIATE CA",
                    currentUser.getEmail(), currentUser.getRole());
            throw new SecurityException(
                    "Insufficient permissions. User role: " + currentUser.getRole());
        }
    }
    /**
     * Validira da CA korisnik može kreirati sertifikate samo za svoju organizaciju
     */
    private void validateOrganization(User user, String requestedOrganization) {
        if (user.getRole() == Role.CA_USER) {
            // Pronađi CA sertifikat korisnika
            List<Certificate> userCACerts = certificateRepository
                    .findActiveCACertificatesByOwner(user.getId());

            if (!userCACerts.isEmpty()) {
                String userOrganization = userCACerts.get(0).getOrganization();

                // Proveri da li je organization ista
                if (!userOrganization.equalsIgnoreCase(requestedOrganization)) {
                    throw new SecurityException(
                            String.format(
                                    "CA users can only issue certificates for their own organization. " +
                                            "Your organization: '%s', Requested: '%s'",
                                    userOrganization,
                                    requestedOrganization
                            )
                    );
                }

                log.info("Organization validation passed for user {} - organization: {}",
                        user.getEmail(), userOrganization);
            }
        }
    }

    /**
     * Pronalazi sve sertifikate u lancu korisnika (za CA_USER)
     */
    public List<Certificate> getCertificatesInUserChain(User user) {
        // 1. Pronađi sve CA sertifikate korisnika
        List<Certificate> userCAs = certificateRepository
                .findActiveCACertificatesByOwner(user.getId());

        Set<Long> chainCertIds = new HashSet<>();

        // 2. Za svaki CA, pronađi sve sertifikate izdane njime (rekurzivno)
        for (Certificate ca : userCAs) {
            chainCertIds.add(ca.getId());
            findDescendantCertificates(ca, chainCertIds);
        }

        // 3. Vrati sve sertifikate iz lanca
        return certificateRepository.findAllById(chainCertIds);
    }
    private void findDescendantCertificates(Certificate parent, Set<Long> result) {
        List<Certificate> children = certificateRepository
                .findByIssuerCertificateId(parent.getId());

        for (Certificate child : children) {
            result.add(child.getId());
            if (child.isCA()) {
                // Rekurzivno prolazi kroz lanac
                findDescendantCertificates(child, result);
            }
        }
    }


    /**
     * Kreira END_ENTITY sertifikat iz upload-ovanog CSR-a.
     * Korisnik je generisao ključeve lokalno - server dobija samo javni ključ kroz CSR.
     *
     * POKRIVA SPECIFIKACIJU:
     * - "End-entity korisnici prave CSR putem eksterne generacije"
     * - "korisnik sam generiše ključeve"
     * - "upload-uje kroz formu na PKI sistemu"
     * - "odabere CA za digitalni potpis"
     * - "unese trajanje sertifikata pri čemu se mora poštovati trajanje sertifikata odabranog CA"
     */
    /**
     * Kreira END_ENTITY sertifikat iz upload-ovanog CSR-a.
     * Korisnik je generisao ključeve lokalno - server dobija samo javni ključ kroz CSR.
     *
     * POKRIVA SPECIFIKACIJU:
     * - "End-entity korisnici prave CSR putem eksterne generacije"
     * - "korisnik sam generiše ključeve"
     * - "CSR sadrži sve podatke o vlasniku sertifikata (X500Name), javni ključ i ekstenzije"
     * - "upload-uje kroz formu na PKI sistemu"
     * - "odabere CA za digitalni potpis"
     * - "unese trajanje sertifikata pri čemu se mora poštovati trajanje odabranog CA"
     */
    @Transactional
    public Certificate createEndEntityFromCSR(
            User owner,
            String csrPem,
            String issuerSerialNumber,
            int validityYears) throws Exception {

        log.info("Creating END_ENTITY certificate from CSR for user: {}", owner.getEmail());

        // 1. PARSIRANJE CSR-a - izvlači Subject podatke i javni ključ
        // POKRIVA: "CSR sadrži sve podatke o vlasniku sertifikata (X500Name), javni ključ"
        Subject subject = csrProcessingService.extractSubjectFromCSR(csrPem);

        // 1b. Parsira CSR objekat za ekstenzije
        PKCS10CertificationRequest csr = csrProcessingService.parseCSR(csrPem);

        // 1c. Izvuci EKSTENZIJE iz CSR-a
        // POKRIVA: "CSR sadrži... ekstenzije"
        List<String> keyUsage = csrProcessingService.extractKeyUsageFromCSR(csr);
        List<String> extendedKeyUsage = csrProcessingService.extractExtendedKeyUsageFromCSR(csr);
        List<String> subjectAlternativeNames = csrProcessingService.extractSANFromCSR(csr);

        log.info("Extracted extensions from CSR - KeyUsage: {}, ExtendedKeyUsage: {}, SAN: {}",
                keyUsage, extendedKeyUsage, subjectAlternativeNames);

        // 2. VALIDACIJA CSR sadržaja
        csrProcessingService.validateCSRContent(subject);

        // 3. UČITAJ CA ISSUER
        // POKRIVA: "omogućiti korisniku da odabere CA za digitalni potpis"
        Certificate issuerCert = certificateRepository.findBySerialNumber(issuerSerialNumber)
                .orElseThrow(() -> new IllegalArgumentException("Issuer certificate not found"));

        // 4. VALIDACIJA ISSUER-a
        validationService.validateIssuerBeforeSigning(issuerCert);

        // 5. VALIDACIJA ORGANIZACIJE (ako je CA_USER)
        validateOrganization(owner, subject.getOrganization());

        // 6. VALIDACIJA TRAJANJA
        // POKRIVA: "unese trajanje sertifikata pri čemu se mora poštovati trajanje odabranog CA"
        LocalDateTime validFrom = LocalDateTime.now();
        LocalDateTime validUntil = validFrom.plusYears(validityYears);

        if (validUntil.isAfter(issuerCert.getValidUntil())) {
            throw new IllegalArgumentException(
                    String.format(
                            "Certificate validity (%s) cannot exceed issuer's validity (%s). " +
                                    "Maximum allowed: %d years",
                            validUntil,
                            issuerCert.getValidUntil(),
                            java.time.temporal.ChronoUnit.YEARS.between(validFrom, issuerCert.getValidUntil())
                    )
            );
        }

        // 7. ISSUER - učitaj privatni ključ CA-a za potpisivanje
        PrivateKey issuerPrivateKey = keystoreService.loadPrivateKey(
                issuerSerialNumber,
                issuerCert.getOwner()
        );
        X500Name issuerX500Name = buildX500Name(issuerCert);
        Issuer issuer = new Issuer(issuerPrivateKey, issuerX500Name);

        // 8. GENERIŠI SERIAL NUMBER
        String serialNumber = generateSerialNumber();

        // 9. GENERIŠI SERTIFIKAT koristeći JAVNI KLJUČ I EKSTENZIJE IZ CSR-A!
        // KLJUČNA RAZLIKA: subject.getPublicKey() i ekstenzije dolaze iz CSR-a, ne generišemo KeyPair!
        X509Certificate x509Cert = certificateGenerator.generateCertificate(
                subject,  // ← subject.publicKey je iz CSR-a!
                issuer,
                validFrom,
                validUntil,
                serialNumber,
                false,  // nije CA
                null,   // pathLength
                keyUsage.isEmpty() ? null : keyUsage,  // ← keyUsage iz CSR-a
                extendedKeyUsage.isEmpty() ? null : extendedKeyUsage,  // ← extendedKeyUsage iz CSR-a
                subjectAlternativeNames.isEmpty() ? null : subjectAlternativeNames  // ← SAN iz CSR-a
        );

        // 10. KONVERTUJ U PEM
        String pemCert = x509ToPem(x509Cert);
        String publicKeyPem = publicKeyToPem(subject.getPublicKey());

        // 11. SAČUVAJ U BAZI (BEZ privatnog ključa!)
        Certificate certificate = Certificate.builder()
                .serialNumber(serialNumber)
                .commonName(subject.getCommonName())
                .organization(subject.getOrganization())
                .organizationalUnit(subject.getOrganizationalUnit())
                .country(subject.getCountry())
                .state(subject.getState())
                .locality(subject.getLocality())
                .email(subject.getEmail())
                .validFrom(validFrom)
                .validUntil(validUntil)
                .certificateType(CertificateType.END_ENTITY)
                .isCA(false)
                .pemCertificate(pemCert)
                .publicKeyPem(publicKeyPem)
                .issuerCertificate(issuerCert)
                .owner(owner)
                .build();

        certificate = certificateRepository.save(certificate);

        // 12. NE poziva keystoreService.savePrivateKeyAndCertificate!
        // Privatni ključ ostaje kod korisnika!

        log.info("END_ENTITY certificate created from CSR: {}", serialNumber);
        log.info("Certificate issued with extensions from CSR - KeyUsage: {}, EKU: {}, SAN: {}",
                keyUsage, extendedKeyUsage, subjectAlternativeNames);
        log.warn("Private key was NOT provided and remains with the user locally!");

        return certificate;
    }

    public Certificate getCertificateBySerialNumber(String serialNumber) {
        return certificateRepository.findBySerialNumber(serialNumber)
                .orElseThrow(() -> new RuntimeException("Certificate not found: " + serialNumber));
    }

    public List<Certificate> getAllRevokedCertificates() {
        return certificateRepository.findByIsRevokedTrue();
    }

    public List<Certificate> getRevokedCertificatesByIssuer(String issuerSerial) {
        return certificateRepository.findRevokedByIssuer(issuerSerial);
    }

    /**
     * Parsira CSR i izvlači CN, SAN i druge podatke
     */
    public Map<String, Object> parseCSR(String csrPem) {
        try {
            // Očisti PEM format
            String cleanPem = csrPem
                    .replace("-----BEGIN CERTIFICATE REQUEST-----", "")
                    .replace("-----END CERTIFICATE REQUEST-----", "")
                    .replace("-----BEGIN NEW CERTIFICATE REQUEST-----", "")
                    .replace("-----END NEW CERTIFICATE REQUEST-----", "")
                    .replaceAll("\\s", "");

            byte[] csrBytes = Base64.getDecoder().decode(cleanPem);

            // ✅ Koristi direktno BouncyCastle PKCS10CertificationRequest
            PKCS10CertificationRequest csr = new PKCS10CertificationRequest(csrBytes);

            X500Name subject = csr.getSubject();

            // Izvuci CN iz subject-a
            String commonName = extractCNFromX500Name(subject);

            // Izvuci SAN ekstenziju
            List<String> sans = extractSANsFromCSR(csr);

            Map<String, Object> result = new HashMap<>();
            result.put("commonName", commonName);
            result.put("subjectAlternativeNames", sans);
            result.put("subject", subject.toString());

            log.info("Parsed CSR - CN: {}, SANs: {}", commonName, sans);
            return result;

        } catch (Exception e) {
            log.error("Error parsing CSR: ", e);
            throw new IllegalArgumentException("Invalid CSR format: " + e.getMessage());
        }
    }

    /**
     * Helper metoda za izvlačenje CN iz X500Name
     */
    private String extractCNFromX500Name(X500Name x500Name) {
        RDN[] rdns = x500Name.getRDNs(BCStyle.CN);
        if (rdns.length > 0) {
            return IETFUtils.valueToString(rdns[0].getFirst().getValue());
        }
        throw new IllegalArgumentException("CSR does not contain Common Name (CN)");
    }

    /**
     * Helper metoda za izvlačenje SAN ekstenzija iz CSR-a
     */
    private List<String> extractSANsFromCSR(PKCS10CertificationRequest csr) {
        List<String> sans = new ArrayList<>();

        try {
            Attribute[] attributes = csr.getAttributes();

            for (Attribute attr : attributes) {
                // Tražimo extensionRequest attribute
                if (attr.getAttrType().equals(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest)) {
                    Extensions extensions = Extensions.getInstance(attr.getAttrValues().getObjectAt(0));
                    Extension sanExtension = extensions.getExtension(Extension.subjectAlternativeName);

                    if (sanExtension != null) {
                        GeneralNames generalNames = GeneralNames.getInstance(sanExtension.getParsedValue());

                        for (GeneralName generalName : generalNames.getNames()) {
                            String sanValue = generalName.getName().toString();

                            // Formatiraj prema tipu
                            switch (generalName.getTagNo()) {
                                case GeneralName.dNSName:
                                    sans.add("DNS:" + sanValue);
                                    break;
                                case GeneralName.iPAddress:
                                    sans.add("IP:" + sanValue);
                                    break;
                                case GeneralName.rfc822Name:
                                    sans.add("EMAIL:" + sanValue);
                                    break;
                                case GeneralName.uniformResourceIdentifier:
                                    sans.add("URI:" + sanValue);
                                    break;
                                default:
                                    sans.add(sanValue);
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            log.warn("Could not extract SANs from CSR: {}", e.getMessage());
        }

        return sans;
    }

    /**
     * Vraća javni ključ EE korisnika u PEM formatu (za password manager enkripciju)
     */
    public String getUserPublicKeyPem(Long userId) {
        log.info("Fetching public key for user ID: {}", userId);

        // Pronađi aktivni END_ENTITY sertifikat korisnika
        Certificate cert = certificateRepository
                .findActiveEndEntityCertificateByOwner(userId)
                .orElseThrow(() -> new IllegalStateException(
                        "User does not have an active END_ENTITY certificate. " +
                                "Password manager requires EE certificate with public key."
                ));

        // Vrati već sačuvani publicKeyPem
        return cert.getPublicKeyPem();
    }
    public Certificate getUserEndEntityCertificate(Long userId) {
        return certificateRepository.findActiveEndEntityCertificateByOwner(userId)
                .orElseThrow(() -> new RuntimeException("User doesn't have an active END_ENTITY certificate"));
    }



}
