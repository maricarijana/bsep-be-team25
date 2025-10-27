package com.example.bsep_team25.pki.service;

import com.example.bsep_team25.pki.domain.Subject;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCSException;
import org.springframework.stereotype.Service;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import java.util.ArrayList;

import java.io.IOException;
import java.io.StringReader;
import java.security.PublicKey;
import java.util.List;

@Service
@Slf4j
public class CSRProcessingService {

    /**
     * Parsira PEM format CSR i izvlači Subject podatke
     *
     * POKRIVA: "CSR sadrži sve podatke o vlasniku sertifikata (pogledati X500Name), javni ključ"
     */
    public Subject extractSubjectFromCSR(String csrPem) throws Exception {
        // 1. Parsira CSR iz PEM formata
        PKCS10CertificationRequest csr = parseCSR(csrPem);

        // 2. Validira CSR potpis (da je potpisan odgovarajućim privatnim ključem)
        if (!validateCSRSignature(csr)) {
            throw new IllegalArgumentException("CSR signature is invalid");
        }

        // 3. Izvlači Subject podatke (X500Name)
        X500Name x500Name = csr.getSubject();

        // 4. Izvlači javni ključ
        PublicKey publicKey = extractPublicKey(csr);

        // 5. Kreira Subject objekat
        Subject subject = new Subject();
        subject.setPublicKey(publicKey);
        subject.setCommonName(extractRDN(x500Name, BCStyle.CN));
        subject.setOrganization(extractRDN(x500Name, BCStyle.O));
        subject.setOrganizationalUnit(extractRDN(x500Name, BCStyle.OU));
        subject.setCountry(extractRDN(x500Name, BCStyle.C));
        subject.setState(extractRDN(x500Name, BCStyle.ST));
        subject.setLocality(extractRDN(x500Name, BCStyle.L));
        subject.setEmail(extractRDN(x500Name, BCStyle.E));

        log.info("Successfully extracted subject from CSR: CN={}, O={}, C={}",
                subject.getCommonName(), subject.getOrganization(), subject.getCountry());

        return subject;
    }

    /**
     * Parsira CSR iz PEM formata
     *
     * POKRIVA: "Tako generisani csr se potom čuva u enkodovanom .pem formatu"
     */
    public PKCS10CertificationRequest parseCSR(String csrPem) throws IOException {
        try (PEMParser pemParser = new PEMParser(new StringReader(csrPem))) {
            Object parsedObj = pemParser.readObject();

            if (!(parsedObj instanceof PKCS10CertificationRequest)) {
                throw new IllegalArgumentException(
                        "Invalid CSR format - expected PKCS10CertificationRequest"
                );
            }

            log.info("CSR successfully parsed from PEM format");
            return (PKCS10CertificationRequest) parsedObj;
        }
    }

    /**
     * Validira digitalni potpis CSR-a
     * Ovo dokazuje da korisnik poseduje privatni ključ koji odgovara javnom ključu u CSR-u
     *
     * POKRIVA: "korisnik sam generiše ključeve" - CSR potpis dokazuje da poseduje privatni ključ
     */
    public boolean validateCSRSignature(PKCS10CertificationRequest csr) {
        try {
            SubjectPublicKeyInfo subjectPublicKeyInfo = csr.getSubjectPublicKeyInfo();
            ContentVerifierProvider verifierProvider = new JcaContentVerifierProviderBuilder()
                    .setProvider("BC")
                    .build(subjectPublicKeyInfo);

            boolean isValid = csr.isSignatureValid(verifierProvider);

            if (isValid) {
                log.info("CSR signature is VALID - user possesses the private key");
            } else {
                log.warn("CSR signature is INVALID - possible tampering or incorrect key pair");
            }

            return isValid;

        } catch (OperatorCreationException | PKCSException e) {
            log.error("Error validating CSR signature: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Izvlači javni ključ iz CSR-a
     *
     * POKRIVA: "CSR sadrži ... javni ključ"
     */
    public PublicKey extractPublicKey(PKCS10CertificationRequest csr) throws Exception {
        SubjectPublicKeyInfo publicKeyInfo = csr.getSubjectPublicKeyInfo();
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
        PublicKey publicKey = converter.getPublicKey(publicKeyInfo);

        log.info("Public key extracted from CSR: {} ({})",
                publicKey.getAlgorithm(),
                publicKey.getFormat());

        return publicKey;
    }

    /**
     * Helper metod za izvlačenje RDN vrednosti iz X500Name
     *
     * POKRIVA: "CSR sadrži sve podatke o vlasniku sertifikata (pogledati X500Name)"
     */
    private String extractRDN(X500Name x500Name, org.bouncycastle.asn1.ASN1ObjectIdentifier attribute) {
        RDN[] rdns = x500Name.getRDNs(attribute);
        if (rdns.length > 0) {
            return rdns[0].getFirst().getValue().toString();
        }
        return null;
    }

    /**
     * Validira da li CSR sadrži sve obavezne podatke
     *
     * POKRIVA: Bezbednosna validacija sadržaja CSR-a
     */
    public void validateCSRContent(Subject subject) {
        if (subject.getCommonName() == null || subject.getCommonName().isEmpty()) {
            throw new IllegalArgumentException("CSR must contain Common Name (CN)");
        }

        if (subject.getOrganization() == null || subject.getOrganization().isEmpty()) {
            throw new IllegalArgumentException("CSR must contain Organization (O)");
        }

        if (subject.getCountry() == null || subject.getCountry().isEmpty()) {
            throw new IllegalArgumentException("CSR must contain Country (C)");
        }

        if (subject.getPublicKey() == null) {
            throw new IllegalArgumentException("CSR must contain valid public key");
        }

        log.info("CSR content validation passed for CN={}", subject.getCommonName());
    }

    /**
     * Izvlači KeyUsage ekstenziju iz CSR-a
     */
    public List<String> extractKeyUsageFromCSR(PKCS10CertificationRequest csr) throws Exception {
        List<String> keyUsageList = new ArrayList<>();

        Attribute[] attributes = csr.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
        if (attributes.length == 0) {
            log.warn("No extension request found in CSR");
            return keyUsageList;
        }

        Extensions extensions = Extensions.getInstance(attributes[0].getAttrValues().getObjectAt(0));
        Extension keyUsageExt = extensions.getExtension(Extension.keyUsage);

        if (keyUsageExt != null) {
            KeyUsage keyUsage = KeyUsage.getInstance(keyUsageExt.getParsedValue());

            if (keyUsage.hasUsages(KeyUsage.digitalSignature)) keyUsageList.add("digitalSignature");
            if (keyUsage.hasUsages(KeyUsage.keyEncipherment)) keyUsageList.add("keyEncipherment");
            if (keyUsage.hasUsages(KeyUsage.dataEncipherment)) keyUsageList.add("dataEncipherment");
            if (keyUsage.hasUsages(KeyUsage.keyAgreement)) keyUsageList.add("keyAgreement");
            if (keyUsage.hasUsages(KeyUsage.keyCertSign)) keyUsageList.add("keyCertSign");
            if (keyUsage.hasUsages(KeyUsage.cRLSign)) keyUsageList.add("cRLSign");
            if (keyUsage.hasUsages(KeyUsage.nonRepudiation)) keyUsageList.add("nonRepudiation");

            log.info("Extracted KeyUsage from CSR: {}", keyUsageList);
        }

        return keyUsageList;
    }

    /**
     * Izvlači ExtendedKeyUsage ekstenziju iz CSR-a
     */
    public List<String> extractExtendedKeyUsageFromCSR(PKCS10CertificationRequest csr) throws Exception {
        List<String> ekuList = new ArrayList<>();

        Attribute[] attributes = csr.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
        if (attributes.length == 0) {
            return ekuList;
        }

        Extensions extensions = Extensions.getInstance(attributes[0].getAttrValues().getObjectAt(0));
        Extension ekuExt = extensions.getExtension(Extension.extendedKeyUsage);

        if (ekuExt != null) {
            ExtendedKeyUsage eku = ExtendedKeyUsage.getInstance(ekuExt.getParsedValue());
            KeyPurposeId[] purposes = eku.getUsages();

            for (KeyPurposeId purpose : purposes) {
                if (purpose.equals(KeyPurposeId.id_kp_serverAuth)) ekuList.add("serverAuth");
                if (purpose.equals(KeyPurposeId.id_kp_clientAuth)) ekuList.add("clientAuth");
                if (purpose.equals(KeyPurposeId.id_kp_codeSigning)) ekuList.add("codeSigning");
                if (purpose.equals(KeyPurposeId.id_kp_emailProtection)) ekuList.add("emailProtection");
                if (purpose.equals(KeyPurposeId.id_kp_timeStamping)) ekuList.add("timeStamping");
            }

            log.info("Extracted ExtendedKeyUsage from CSR: {}", ekuList);
        }

        return ekuList;
    }

    /**
     * Izvlači SubjectAlternativeNames iz CSR-a
     */
    public List<String> extractSANFromCSR(PKCS10CertificationRequest csr) throws Exception {
        List<String> sanList = new ArrayList<>();

        Attribute[] attributes = csr.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
        if (attributes.length == 0) {
            return sanList;
        }

        Extensions extensions = Extensions.getInstance(attributes[0].getAttrValues().getObjectAt(0));
        Extension sanExt = extensions.getExtension(Extension.subjectAlternativeName);

        if (sanExt != null) {
            GeneralNames gns = GeneralNames.getInstance(sanExt.getParsedValue());
            for (GeneralName gn : gns.getNames()) {
                switch (gn.getTagNo()) {
                    case GeneralName.dNSName:
                        sanList.add("DNS:" + gn.getName().toString());
                        break;
                    case GeneralName.iPAddress:
                        sanList.add("IP:" + gn.getName().toString());
                        break;
                    case GeneralName.rfc822Name:
                        sanList.add("EMAIL:" + gn.getName().toString());
                        break;
                }
            }

            log.info("Extracted SAN from CSR: {}", sanList);
        }

        return sanList;
    }
}