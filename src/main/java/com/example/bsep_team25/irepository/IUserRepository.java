package com.example.bsep_team25.irepository;

import com.example.bsep_team25.model.Role;
import com.example.bsep_team25.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface IUserRepository extends JpaRepository<User, Long> {

    User findByEmail(String email);
    boolean existsByEmail(String email);
    Optional<User> findFirstByRole(Role role);
    List<User> findByRole(Role role);
}
