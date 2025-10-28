package com.example.bsep_team25.passwordManager.domain;


import com.example.bsep_team25.model.User;
import com.example.bsep_team25.pki.domain.Certificate;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.Instant;

@Getter @Setter
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
@ToString(exclude = {"ciphertextB64", "owner", "encryptionCertificate"})
@Entity
@Table(name = "password_items",
        indexes = {
                @Index(name = "ix_password_items_owner", columnList = "owner_id"),
                @Index(name = "ix_password_items_cert", columnList = "encryption_certificate_id")
        })
@Builder @AllArgsConstructor @NoArgsConstructor
public class PasswordItem {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    @EqualsAndHashCode.Include
    private Long id;

    @NotBlank @Size(max = 255)
    @Column(nullable = false, length = 255)
    private String website;

    @NotBlank @Size(max = 255)
    @Column(nullable = false, length = 255)
    private String username;

    /** Base64 RSA-OAEP ciphertext (šifrovana lozinka javnim ključem vlasnika) */
    @NotBlank
    @Lob
    @Column(name = "ciphertext_b64", nullable = false, columnDefinition = "TEXT")
    private String ciphertextB64;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "owner_id", nullable = false)
    private User owner;

    /** Sertifikat vlasnika iz kog čitamo PUBLIC KEY za enkripciju */
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "encryption_certificate_id", nullable = false)
    private Certificate encryptionCertificate;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;
}
