package com.example.bsep_team25.controller;

import com.example.bsep_team25.dto.UserDTO;
import com.example.bsep_team25.model.ActivationToken;
import com.example.bsep_team25.model.Role;
import com.example.bsep_team25.model.User;
import com.example.bsep_team25.service.ActivationTokenService;
import com.example.bsep_team25.service.EmailService;
import com.example.bsep_team25.service.UserService;
import com.example.bsep_team25.util.PasswordValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {


    @Autowired
    private UserService userService;

    @Autowired
    private ActivationTokenService activationTokenService;

    @Autowired
    private EmailService emailService;

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody UserDTO userDto) {

        if (!userDto.getPassword().equals(userDto.getConfirmPassword())) {
            return ResponseEntity.badRequest().body(Map.of("message", "Passwords do not match"));
        }

        if (!PasswordValidator.isValid(userDto.getPassword())) {
            return ResponseEntity.badRequest().body(Map.of("message", "Password does not meet OWASP requirements"));
        }

        if (userService.existsByEmail(userDto.getEmail())) {
            return ResponseEntity.badRequest().body(Map.of("message", "Email already in use"));
        }

        String hashedPassword = new BCryptPasswordEncoder().encode(userDto.getPassword());

        User user = new User();
        user.setEmail(userDto.getEmail());
        user.setPassword(hashedPassword);
        user.setName(userDto.getName());
        user.setSurName(userDto.getSurname());
        user.setOrganization(userDto.getOrganization());
        user.setActive(false);
        user.setRole(Role.USER);

        userService.save(user);

        ActivationToken token = activationTokenService.createToken(user);

        // Pošalji mejl sa aktivacionim linkom
        emailService.sendActivationEmail(user.getEmail(), token.getToken());

        // frontend više ne dobija token, samo poruku
        return ResponseEntity.ok(Map.of(
                "message", "User registered successfully. Please check your email to activate your account."
        ));
    }


    @GetMapping("/activate/{token}")
    public ResponseEntity<?> activateAccount(@PathVariable String token) {
        boolean success = activationTokenService.activateUser(token);
        if (success) {
            return ResponseEntity.ok(Map.of("message", "Account activated successfully!"));
        }
        return ResponseEntity.badRequest().body(Map.of("message", "Activation link is invalid or expired"));
    }


}
