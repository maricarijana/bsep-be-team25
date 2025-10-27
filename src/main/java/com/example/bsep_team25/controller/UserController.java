package com.example.bsep_team25.controller;

import com.example.bsep_team25.dto.UserResponseDTO;
import com.example.bsep_team25.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/user")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    /**
     * Vraća sve korisnike koji imaju END_ENTITY sertifikat
     * (za password sharing)
     */
    @GetMapping("/with-ee-certificates")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<List<UserResponseDTO>> getUsersWithEECertificates() {
        List<UserResponseDTO> users = userService.getUsersWithEndEntityCertificates();
        return ResponseEntity.ok(users);
    }
}