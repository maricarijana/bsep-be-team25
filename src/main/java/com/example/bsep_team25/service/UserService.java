package com.example.bsep_team25.service;


import com.example.bsep_team25.dto.UserResponseDTO;
import com.example.bsep_team25.irepository.IUserRepository;
import com.example.bsep_team25.iservice.IUserService;
import com.example.bsep_team25.model.User;
import com.example.bsep_team25.pki.domain.Certificate;
import com.example.bsep_team25.pki.repository.CertificateRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;
import com.example.bsep_team25.model.Role;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class UserService implements IUserService {

    @Autowired
    private  IUserRepository userRepository;
    @Autowired
    private CertificateRepository certificateRepository;

    @Override
    public User save(User user) {
        return userRepository.save(user);
    }

    @Override
    public Optional<User> findById(Long id) {
        return userRepository.findById(id);
    }

    @Override
    public User findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    @Override
    public boolean existsByEmail(String email) {
        return userRepository.existsByEmail(email);
    }

    @Override
    public List<User> findAll() {
        return userRepository.findAll();
    }

    @Override
    public void deleteById(Long id) {
        userRepository.deleteById(id);
    }

    @Override
    public List<User> findByRole(Role role) {return userRepository.findByRole(role);}

    @Override
    public Optional<User> findFirstByRole(Role role) {
        return userRepository.findFirstByRole(role);
    }
    @Override
    public List<UserResponseDTO> getUsersWithEndEntityCertificates() {
        return userRepository.findAll().stream()
                .filter(user -> {
                    Optional<Certificate> cert = certificateRepository
                            .findActiveEndEntityCertificateByOwner(user.getId());
                    return cert.isPresent();
                })
                .map(user -> UserResponseDTO.builder()
                        .id(user.getId())
                        .email(user.getEmail())
                        .name(user.getName())           // ← Ime
                        .surname(user.getSurname())     // ← Prezime
                        .organization(user.getOrganization())
                        .build())
                .collect(Collectors.toList());
    }
}
