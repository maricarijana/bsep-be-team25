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
@ToString(exclude = {"ciphertextB64", "sourceItem", "sharedBy", "sharedWith", "recipientCertificate"})
@Entity
@Table(name = "password_shares",
        indexes = {
                @Index(name = "ix_password_shares_source", columnList = "source_item_id"),
                @Index(name = "ix_password_shares_with", columnList = "shared_with_id"),
                @Index(name = "ix_password_shares_by", columnList = "shared_by_id"),
                @Index(name = "ix_password_shares_cert", columnList = "recipient_certificate_id")
        })
@Builder @AllArgsConstructor @NoArgsConstructor
public class PasswordShare {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    @EqualsAndHashCode.Include
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "source_item_id", nullable = false)
    private PasswordItem sourceItem;

//    @NotBlank @Size(max = 255)
//    @Column(name = "site_label", nullable = false, length = 255)
//    private String siteLabel;
//
//    @NotBlank @Size(max = 255)
//    @Column(name = "login_handle", nullable = false, length = 255)
//    private String loginHandle;

    /** Base64 RSA-OAEP ciphertext (šifrovana lozinka javnim ključem PRIMAOCA) */
    @NotBlank
    @Lob
    @Column(name = "ciphertext_b64", nullable = false, columnDefinition = "TEXT")
    private String ciphertextB64;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "shared_by_id", nullable = false)
    private User sharedBy;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "shared_with_id", nullable = false)
    private User sharedWith;

    /** Sertifikat primaoca iz kog čitamo PUBLIC KEY za re-enkripciju */
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "recipient_certificate_id", nullable = false)
    private Certificate recipientCertificate;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    public String getWebsite() {
        return sourceItem.getWebsite();
    }

    public String getUsername() {
        return sourceItem.getUsername();
    }
}
