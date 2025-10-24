package com.example.bsep_team25.controller;

import com.example.bsep_team25.iservice.IPasswordResetTokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/password")
public class PasswordResetController {

    @Autowired
    private IPasswordResetTokenService passwordResetService;

    @PostMapping("/request-reset")
    public ResponseEntity<?> requestReset(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        passwordResetService.createPasswordResetToken(email);
        return ResponseEntity.ok(Map.of(
                "message", "If an account with that email exists, a reset link has been sent."
        ));
    }

    @PostMapping("/reset/{token}")
    public ResponseEntity<?> resetPassword(@PathVariable String token, @RequestBody Map<String, String> body) {
        String newPassword = body.get("password");
        boolean success = passwordResetService.resetPassword(token, newPassword);

        if (success)
            return ResponseEntity.ok(Map.of("message", "Password successfully reset!"));
        else
            return ResponseEntity.badRequest().body(Map.of("message", "Invalid or expired reset link."));
    }
}
