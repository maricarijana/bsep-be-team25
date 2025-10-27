package com.example.bsep_team25.passwordManager.repository;

import com.example.bsep_team25.passwordManager.domain.PasswordShare;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface PasswordShareRepository extends JpaRepository<PasswordShare, Long> {

    // Primljene (list) — bez sertifikata (brže listanje)
    @Query("""
           SELECT DISTINCT ps FROM PasswordShare ps
           LEFT JOIN FETCH ps.sharedBy
           LEFT JOIN FETCH ps.sharedWith
           WHERE ps.sharedWith.id = :userId
           """)
    List<PasswordShare> findReceivedForList(@Param("userId") Long userId);

    // Primljene (detail) — sa cert-om primaoca
    @Query("""
           SELECT DISTINCT ps FROM PasswordShare ps
           LEFT JOIN FETCH ps.sharedBy
           LEFT JOIN FETCH ps.sharedWith
           LEFT JOIN FETCH ps.recipientCertificate
           WHERE ps.id = :shareId AND ps.sharedWith.id = :userId
           """)
    Optional<PasswordShare> findReceivedDetail(@Param("userId") Long userId,
                                               @Param("shareId") Long shareId);

    // Poslate (list) — bez cert-a (brže)
    @Query("""
   SELECT DISTINCT ps FROM PasswordShare ps
   LEFT JOIN FETCH ps.sourceItem si
   LEFT JOIN FETCH ps.sharedBy
   LEFT JOIN FETCH ps.sharedWith
   WHERE ps.sharedWith.id = :userId
   """)
    List<PasswordShare> findSentForList(@Param("userId") Long userId);

    // Poslate (detail) — sa cert-om primaoca
    @Query("""
           SELECT DISTINCT ps FROM PasswordShare ps
           LEFT JOIN FETCH ps.sharedBy
           LEFT JOIN FETCH ps.sharedWith
           LEFT JOIN FETCH ps.recipientCertificate
           WHERE ps.id = :shareId AND ps.sharedBy.id = :userId
           """)
    Optional<PasswordShare> findSentDetail(@Param("userId") Long userId,
                                           @Param("shareId") Long shareId);

    // Brza autorizacija za brisanje: vlasnik deljenja ili primalac
    @Query("""
           SELECT COUNT(ps) > 0 FROM PasswordShare ps
           WHERE ps.id = :shareId
             AND (ps.sharedBy.id = :userId OR ps.sharedWith.id = :userId)
           """)
    boolean canUserDeleteShare(@Param("userId") Long userId, @Param("shareId") Long shareId);
}
