package com.example.bsep_team25.controller;

import com.example.bsep_team25.dto.CreateCAUserDTO;
import com.example.bsep_team25.dto.CAUserResponseDTO;
import com.example.bsep_team25.model.Role;
import com.example.bsep_team25.model.User;
import com.example.bsep_team25.service.EmailService;
import com.example.bsep_team25.service.UserService;
import com.example.bsep_team25.util.PasswordValidator;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/admin")
@PreAuthorize("hasAuthority('ADMIN')")
public class AdminController {

    @Autowired
    private UserService userService;

    @Autowired
    private EmailService emailService;

    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    @PostMapping("/ca-users")
    public ResponseEntity<?> createCAUser(@Valid @RequestBody CreateCAUserDTO dto) {

        if (userService.existsByEmail(dto.getEmail())) {
            return ResponseEntity.badRequest()
                    .body(Map.of("message", "Email already in use"));
        }

        String temporaryPassword = PasswordValidator.generateSecurePassword();
        String hashedPassword = passwordEncoder.encode(temporaryPassword);

        String[] nameParts = dto.getFullName().trim().split("\\s+", 2);
        String name = nameParts[0];
        String surname = nameParts.length > 1 ? nameParts[1] : "";

        User caUser = new User();
        caUser.setEmail(dto.getEmail());
        caUser.setPassword(hashedPassword);
        caUser.setName(name);
        caUser.setSurName(surname);
        caUser.setOrganization(dto.getOrganization());
        caUser.setRole(Role.CA_USER);
        caUser.setActive(true);
        caUser.setMustChangePassword(true);

        userService.save(caUser);

        emailService.sendCAUserCredentials(
                caUser.getEmail(),
                temporaryPassword,
                dto.getOrganization()
        );

        CAUserResponseDTO response = new CAUserResponseDTO(
                caUser.getId(),
                caUser.getEmail(),
                dto.getFullName(),
                caUser.getOrganization(),
                temporaryPassword,
                true,
                "CA_USER",
                true
        );

        return ResponseEntity.ok(response);
    }

    @GetMapping("/ca-users")
    public ResponseEntity<List<CAUserResponseDTO>> getAllCAUsers() {

        List<User> caUsers = userService.findByRole(Role.CA_USER);

        List<CAUserResponseDTO> response = caUsers.stream()
                .map(user -> new CAUserResponseDTO(
                        user.getId(),
                        user.getEmail(),
                        user.getName() + " " + user.getSurname(),
                        user.getOrganization(),
                        null,
                        user.isMustChangePassword(),
                        "CA_USER",
                        user.isActive()
                ))
                .collect(Collectors.toList());

        return ResponseEntity.ok(response);
    }
}