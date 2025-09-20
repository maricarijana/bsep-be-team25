package com.example.bsep_team25.controller;

import com.example.bsep_team25.dto.UserDTO;
import com.example.bsep_team25.model.ActivationToken;
import com.example.bsep_team25.model.Role;
import com.example.bsep_team25.model.User;
import com.example.bsep_team25.service.ActivationTokenService;
import com.example.bsep_team25.service.UserService;
import com.example.bsep_team25.util.PasswordValidator;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UserService userService;
    private final ActivationTokenService activationTokenService;
    public AuthController(UserService userService, ActivationTokenService activationTokenService) {
        this.userService = userService;
        this.activationTokenService= activationTokenService;
    }

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody UserDTO userDto) {

        // 1. Password == ConfirmPassword
        if (!userDto.getPassword().equals(userDto.getConfirmPassword())) {
            return ResponseEntity.badRequest().body("Passwords do not match");
        }

        // 2. Password strength (OWASP minimal)
        if (!PasswordValidator.isValid(userDto.getPassword())) {
            return ResponseEntity.badRequest().body("Password does not meet OWASP requirements");
        }
        // 3. Hashuj lozinku
        String hashedPassword = new BCryptPasswordEncoder().encode(userDto.getPassword());

        // Napravi novog korisnika
        User user = new User();
        user.setEmail(userDto.getEmail());
        user.setPassword(hashedPassword);
        user.setName(userDto.getName());
        user.setSurName(userDto.getSurname());
        user.setOrganization(userDto.getOrganization());
        user.setActive(false); // nije aktivan dok ne uvedemo aktivaciju
        user.setRole(Role.USER); // samo obicni korisnici se registruju

        // Sačuvaj u bazi
        userService.save(user);

        ActivationToken token = activationTokenService.createToken(user);
        return ResponseEntity.ok("User registered. Activation token: " + token.getToken());

    }

    @GetMapping("/activate/{token}")
    public ResponseEntity<String> activateAccount(@PathVariable String token) {
        boolean success = activationTokenService.activateUser(token);
        if (success) {
            return ResponseEntity.ok("Account activated successfully!");
        }
        return ResponseEntity.badRequest().body("Activation link is invalid or expired");
    }

}
