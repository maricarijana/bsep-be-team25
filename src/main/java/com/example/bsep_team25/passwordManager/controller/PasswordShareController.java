package com.example.bsep_team25.passwordManager.controller;

import com.example.bsep_team25.passwordManager.dto.SharePasswordRequest;
import com.example.bsep_team25.passwordManager.dto.SharePasswordResponse;
import com.example.bsep_team25.passwordManager.iservice.PasswordShareService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequiredArgsConstructor
@Validated
@PreAuthorize("isAuthenticated()")
@RequestMapping("/password-manager/shares")
public class PasswordShareController {

    private final PasswordShareService service;

    // Deli lozinku (samo vlasnik izvornog PasswordItem-a)
    @PostMapping
    public ResponseEntity<SharePasswordResponse> share(@Valid @RequestBody SharePasswordRequest req) {
        SharePasswordResponse saved = service.share(req);
        return ResponseEntity.status(HttpStatus.CREATED).body(saved);
    }

    // Lozinke podeljene MENI (primljene)
    @GetMapping("/received")
    public List<SharePasswordResponse> listReceived() {
        return service.listReceived();
    }

    // Lozinke koje sam JA podelio/la (poslate)
    @GetMapping("/sent")
    public List<SharePasswordResponse> listSent() {
        return service.listSent();
    }

    // Brisanje deljenja (dopušteno: onaj ko je podelio ILI onaj kome je podeljeno)
    @DeleteMapping("/{shareId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(@PathVariable Long shareId) {
        service.delete(shareId);
    }
    // Vraća DETAIL jednog share-a (sa ciphertextB64) - za primljene lozinke
    @GetMapping("/received/{shareId}")
    public ResponseEntity<SharePasswordResponse> getReceivedDetail(@PathVariable Long shareId) {
        SharePasswordResponse detail = service.getReceivedDetail(shareId);
        return ResponseEntity.ok(detail);
    }
}
