package com.example.bsep_team25.pki.service;

import com.example.bsep_team25.model.User;
import com.example.bsep_team25.pki.domain.KeyStoreInfo;
import com.example.bsep_team25.pki.repository.KeystoreInfoRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;

@Service
@Slf4j
@RequiredArgsConstructor
public class KeystoreService {

    @Value("${pki.keystore.path}")
    private String keystoreBasePath;

    private final KeystoreInfoRepository keystoreInfoRepository;
    private final EncryptionService encryptionService;

    @Transactional
    public void savePrivateKeyAndCertificate(
            String alias,
            PrivateKey privateKey,
            Certificate certificate,
            Certificate[] chain,
            User user) throws Exception {

        // Kreiraj keystores direktorijum ako ne postoji
        Path keystoreDir = Paths.get(keystoreBasePath);
        if (!Files.exists(keystoreDir)) {
            Files.createDirectories(keystoreDir);
        }

        // Generiši lozinke
        String keystorePassword = encryptionService.generateRandomPassword(16);
        String keyPassword = encryptionService.generateRandomPassword(16);

        // Kreiraj keystore fajl
        String keystoreFilename = alias + ".p12";
        Path keystorePath = keystoreDir.resolve(keystoreFilename);

        KeyStore keystore = KeyStore.getInstance("PKCS12");
        keystore.load(null, null);

        // Sačuvaj privatni ključ + lanac sertifikata
        keystore.setKeyEntry(alias, privateKey, keyPassword.toCharArray(), chain);

        // Snimi keystore na disk
        try (FileOutputStream fos = new FileOutputStream(keystorePath.toFile())) {
            keystore.store(fos, keystorePassword.toCharArray());
        }

        // Enkriptuj lozinke
        String salt = encryptionService.generateSalt();
        String iv = encryptionService.generateIV();

        String encryptedKeystorePass = encryptionService.encrypt(keystorePassword, user.getId(), salt, iv);
        String encryptedKeyPass = encryptionService.encrypt(keyPassword, user.getId(), salt, iv);

        // Snimi u bazu
        KeyStoreInfo info = KeyStoreInfo.builder()
                .alias(alias)
                .keystorePath(keystorePath.toString())
                .encryptedKeystorePassword(encryptedKeystorePass)
                .encryptedKeyPassword(encryptedKeyPass)
                .salt(salt)
                .iv(iv)
                .user(user)
                .build();

        keystoreInfoRepository.save(info);

        log.info("Keystore saved for alias: {} at path: {}", alias, keystorePath);
    }

    public PrivateKey loadPrivateKey(String alias, User user) throws Exception {
        KeyStoreInfo info = keystoreInfoRepository.findByAlias(alias)
                .orElseThrow(() -> new RuntimeException("Keystore info not found for alias: " + alias));

        // Dekriptuj lozinke
        String keystorePassword = encryptionService.decrypt(
                info.getEncryptedKeystorePassword(),
                user.getId(),
                info.getSalt(),
                info.getIv()
        );
        String keyPassword = encryptionService.decrypt(
                info.getEncryptedKeyPassword(),
                user.getId(),
                info.getSalt(),
                info.getIv()
        );

        // Učitaj keystore
        KeyStore keystore = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(info.getKeystorePath())) {
            keystore.load(fis, keystorePassword.toCharArray());
        }

        return (PrivateKey) keystore.getKey(alias, keyPassword.toCharArray());
    }

    public Certificate loadCertificate(String alias, User user) throws Exception {
        KeyStoreInfo info = keystoreInfoRepository.findByAlias(alias)
                .orElseThrow(() -> new RuntimeException("Keystore info not found for alias: " + alias));

        String keystorePassword = encryptionService.decrypt(
                info.getEncryptedKeystorePassword(),
                user.getId(),
                info.getSalt(),
                info.getIv()
        );

        KeyStore keystore = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(info.getKeystorePath())) {
            keystore.load(fis, keystorePassword.toCharArray());
        }

        return keystore.getCertificate(alias);
    }
}
