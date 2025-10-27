package com.example.bsep_team25.passwordManager.repository;

import com.example.bsep_team25.passwordManager.domain.PasswordItem;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface PasswordItemRepository extends JpaRepository<PasswordItem, Long> {

    // LIST (bez sertifikata) — izbegavaj učitavanje velikih PEM/TEXT polja
    @Query("""
           SELECT DISTINCT pi FROM PasswordItem pi
           LEFT JOIN FETCH pi.owner
           WHERE pi.owner.id = :ownerId
           """)
    List<PasswordItem> findForList(@Param("ownerId") Long ownerId);

    // DETAIL (sa sertifikatom) — koristi kad stvarno treba cert
    @Query("""
           SELECT DISTINCT pi FROM PasswordItem pi
           LEFT JOIN FETCH pi.owner
           LEFT JOIN FETCH pi.encryptionCertificate
           WHERE pi.id = :itemId AND pi.owner.id = :ownerId
           """)
    Optional<PasswordItem> findDetail(@Param("ownerId") Long ownerId,
                                      @Param("itemId") Long itemId);

    // Autorizacija u jednom upitu (delete/update)
    @Query("SELECT COUNT(pi) > 0 FROM PasswordItem pi WHERE pi.id = :itemId AND pi.owner.id = :ownerId")
    boolean existsByIdAndOwnerId(@Param("itemId") Long itemId, @Param("ownerId") Long ownerId);
}
