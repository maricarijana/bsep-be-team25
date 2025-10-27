package com.example.bsep_team25.pki.domain;
import com.example.bsep_team25.model.User;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "certificate_template")
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class CertificateTemplate {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String name; // Naziv šablona

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "ca_issuer_serial", nullable = false)
    private Certificate caIssuer; // CA koji će izdavati sertifikate

    @Column(nullable = false)
    private String cnValidationRegex; // Regex za CN (npr. .*\.ftn\.com)

    @Column
    private String sanValidationRegex; // Regex za SAN

    @Column(nullable = false)
    private Integer maxTTLDays; // Maksimalno trajanje u danima

    // Čuvamo kao JSON string jer može biti lista
    @Column(name = "key_usage", columnDefinition = "TEXT")
    private String keyUsage; // JSON: ["digitalSignature", "keyCertSign"]

    @Column(name = "extended_key_usage", columnDefinition = "TEXT")
    private String extendedKeyUsage; // JSON: ["serverAuth", "clientAuth"]

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "created_by", nullable = false)
    private User createdBy; // CA korisnik

    @Column(nullable = false)
    private LocalDateTime createdAt = LocalDateTime.now();

    @PrePersist
    protected void onCreate() {
        if (createdAt == null) {
            createdAt = LocalDateTime.now();
        }
    }
}
