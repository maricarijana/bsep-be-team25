package com.example.bsep_team25.controller;

import com.example.bsep_team25.dto.UserDTO;
import com.example.bsep_team25.model.ActivationToken;
import com.example.bsep_team25.model.Role;
import com.example.bsep_team25.model.User;
import com.example.bsep_team25.service.ActivationTokenService;
import com.example.bsep_team25.service.EmailService;
import com.example.bsep_team25.service.UserService;
import com.example.bsep_team25.util.PasswordValidator;
import com.example.bsep_team25.util.TokenUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/auth")
public class AuthController {


    @Autowired
    private UserService userService;

    @Autowired
    private ActivationTokenService activationTokenService;

    @Autowired
    private EmailService emailService;

    @Autowired
    private TokenUtils tokenUtils;


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

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody UserDTO userDto) {
        User user = userService.findByEmail(userDto.getEmail());

        if (user == null) {
            return ResponseEntity.badRequest().body(Map.of("message", "Invalid email or password"));
        }

        // Ako nije aktiviran nalog
        if (!user.isActive()) {
            return ResponseEntity.badRequest().body(Map.of("message", "Account is not activated. Please check your email."));
        }

        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        if (!encoder.matches(userDto.getPassword(), user.getPassword())) {
            return ResponseEntity.badRequest().body(Map.of("message", "Invalid email or password"));
        }

        // GENERISANJE JWT tokena
        String jwt = tokenUtils.generateToken(user.getEmail(), user.getRole().toString());

        // Vrati token + podatke o korisniku
        return ResponseEntity.ok(Map.of(
                "message", "Login successful",
                "token", jwt,
                "email", user.getEmail(),
                "name", user.getName(),
                "surname", user.getSurname(),
                "organization", user.getOrganization(),
                "role", user.getRole().toString()
        ));
    }




}
