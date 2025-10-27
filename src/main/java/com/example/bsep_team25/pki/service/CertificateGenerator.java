package com.example.bsep_team25.pki.service;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import com.example.bsep_team25.pki.domain.Issuer;
import com.example.bsep_team25.pki.domain.Subject;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.List;

@Service
@Slf4j
public class CertificateGenerator {

    public CertificateGenerator() {
        Security.addProvider(new BouncyCastleProvider());
    }

    public KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }

    public X509Certificate generateCertificate(
            Subject subject,
            Issuer issuer,
            LocalDateTime validFrom,
            LocalDateTime validUntil,
            String serialNumber,
            boolean isCA,
            Integer pathLength,
            List<String> keyUsage,
            List<String> extendedKeyUsage,
            List<String> subjectAlternativeNames) throws Exception {

        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA")
                .setProvider("BC")
                .build(issuer.getPrivateKey());

        Date notBefore = Date.from(validFrom.atZone(ZoneId.systemDefault()).toInstant());
        Date notAfter = Date.from(validUntil.atZone(ZoneId.systemDefault()).toInstant());

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer.getX500Name(),
                new BigInteger(serialNumber),
                notBefore,
                notAfter,
                subject.toX500Name(),
                subject.getPublicKey()
        );

        // BasicConstraints ekstenzija
        if (isCA) {
            if (pathLength != null) {
                certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(pathLength));
            } else {
                certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            }
        } else {
            certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        }

        // KeyUsage ekstenzija
        if (keyUsage != null && !keyUsage.isEmpty()) {
            int keyUsageValue = 0;
            for (String usage : keyUsage) {
                switch (usage.toLowerCase()) {
                    case "digitalsignature": keyUsageValue |= KeyUsage.digitalSignature; break;
                    case "keycertsign": keyUsageValue |= KeyUsage.keyCertSign; break;
                    case "crlsign": keyUsageValue |= KeyUsage.cRLSign; break;
                    case "keyencipherment": keyUsageValue |= KeyUsage.keyEncipherment; break;
                    case "dataencipherment": keyUsageValue |= KeyUsage.dataEncipherment; break;
                    case "keyagreement": keyUsageValue |= KeyUsage.keyAgreement; break;
                    case "nonrepudiation": keyUsageValue |= KeyUsage.nonRepudiation; break;
                }
            }
            certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(keyUsageValue));
        }

        // ExtendedKeyUsage ekstenzija
        if (extendedKeyUsage != null && !extendedKeyUsage.isEmpty()) {
            KeyPurposeId[] purposes = extendedKeyUsage.stream()
                    .map(eku -> {
                        switch (eku.toLowerCase()) {
                            case "serverauth": return KeyPurposeId.id_kp_serverAuth;
                            case "clientauth": return KeyPurposeId.id_kp_clientAuth;
                            case "codesigning": return KeyPurposeId.id_kp_codeSigning;
                            case "emailprotection": return KeyPurposeId.id_kp_emailProtection;
                            case "timestamping": return KeyPurposeId.id_kp_timeStamping;
                            default: return KeyPurposeId.anyExtendedKeyUsage;
                        }
                    })
                    .toArray(KeyPurposeId[]::new);

            certBuilder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(purposes));
        }

        // SubjectAlternativeNames
        if (subjectAlternativeNames != null && !subjectAlternativeNames.isEmpty()) {
            GeneralName[] altNames = subjectAlternativeNames.stream()
                    .map(san -> {
                        if (san.startsWith("DNS:")) {
                            return new GeneralName(GeneralName.dNSName, san.substring(4));
                        } else if (san.startsWith("IP:")) {
                            return new GeneralName(GeneralName.iPAddress, san.substring(3));
                        } else if (san.startsWith("EMAIL:")) {
                            return new GeneralName(GeneralName.rfc822Name, san.substring(6));
                        } else {
                            return new GeneralName(GeneralName.dNSName, san);
                        }
                    })
                    .toArray(GeneralName[]::new);

            certBuilder.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(altNames));
        }
        String crlUrl = "http://localhost:8080/api/pki/certificates/crl";
        DistributionPointName distPointName = new DistributionPointName(
                new GeneralNames(
                        new GeneralName(GeneralName.uniformResourceIdentifier, crlUrl)
                )
        );
        DistributionPoint[] distPoints = new DistributionPoint[]{
                new DistributionPoint(distPointName, null, null)
        };
        certBuilder.addExtension(
                Extension.cRLDistributionPoints,
                false,
                new CRLDistPoint(distPoints)
        );

        log.info("Added CRL Distribution Point: {}", crlUrl);

        X509CertificateHolder certHolder = certBuilder.build(signer);

        return new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(certHolder);
    }
}
