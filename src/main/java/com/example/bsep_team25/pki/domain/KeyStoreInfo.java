package com.example.bsep_team25.pki.domain;

import com.example.bsep_team25.model.User;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Entity
@Table(name = "keystore_info")
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class KeyStoreInfo {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Alias u keystore-u (npr. serial number sertifikata)
    @Column(nullable = false, unique = true)
    private String alias;

    // Putanja do keystore fajla
    @Column(nullable = false)
    private String keystorePath;

    // Enkriptovana lozinka za keystore
    @Column(nullable = false)
    private String encryptedKeystorePassword;

    // Enkriptovana lozinka za privatni ključ
    @Column(nullable = false)
    private String encryptedKeyPassword;

    // Salt za PBKDF2
    @Column(nullable = false)
    private String salt;

    // IV za AES enkripciju
    @Column(nullable = false)
    private String iv;

    // Korisnik kojem pripada ovaj keystore
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(nullable = false)
    private LocalDateTime createdAt = LocalDateTime.now();

    @PrePersist
    protected void onCreate() {
        if (createdAt == null) {
            createdAt = LocalDateTime.now();
        }
    }
}
