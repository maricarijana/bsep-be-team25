package com.example.bsep_team25.iservice;

import com.example.bsep_team25.model.User;

import java.util.List;
import java.util.Optional;

public interface IUserService {

    User save(User user);
    Optional<User> findById(Long id);
    User findByEmail(String email);
    boolean existsByEmail(String email);
    List<User> findAll();
    void deleteById(Long id);
}
