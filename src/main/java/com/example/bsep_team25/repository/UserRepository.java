package com.example.bsep_team25.repository;

import com.example.bsep_team25.irepository.IUserRepository;
import com.example.bsep_team25.model.User;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public class UserRepository {

private final IUserRepository iUserRepository;

public UserRepository(IUserRepository iUserRepository) {
    this.iUserRepository = iUserRepository;

}
    public User save(User user) {
        return iUserRepository.save(user);
    }

    public Optional<User> findById(Long id) {
        return iUserRepository.findById(id);
    }

    public Optional<User> findByEmail(String email) {
        return iUserRepository.findByEmail(email);
    }

    public boolean existsByEmail(String email) {
        return iUserRepository.existsByEmail(email);
    }

    public List<User> findAll() {
        return iUserRepository.findAll();
    }

    public void deleteById(Long id) {
        iUserRepository.deleteById(id);
    }
}
