package com.example.bsep_team25.passwordManager.controller;

import com.example.bsep_team25.passwordManager.dto.CreatePasswordItemRequest;
import com.example.bsep_team25.passwordManager.dto.PasswordItemResponse;
import com.example.bsep_team25.passwordManager.iservice.PasswordItemService;
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
@RequestMapping("/password-manager/items")
public class PasswordItemsController {

    private final PasswordItemService service;

    // Kreira novu lozinku (FE šalje plaintext, BE enkriptuje javnim ključem VLASNIKA)
    @PostMapping
    public ResponseEntity<PasswordItemResponse> create(@Valid @RequestBody CreatePasswordItemRequest req) {
        PasswordItemResponse saved = service.create(req);
        return ResponseEntity.status(HttpStatus.CREATED).body(saved);
    }

    // Vraća moje lozinke (autentikovani korisnik)
    @GetMapping
    public List<PasswordItemResponse> listMine() {
        return service.listMine();
    }

    // Briše MOJU lozinku (samo vlasnik)
    @DeleteMapping("/{itemId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(@PathVariable Long itemId) {
        service.delete(itemId);
    }
    // Vraća DETAIL jedne lozinke (sa ciphertextB64) - za "Show password"
    @GetMapping("/{itemId}")
    public ResponseEntity<PasswordItemResponse> getDetail(@PathVariable Long itemId) {
        PasswordItemResponse detail = service.getDetail(itemId);
        return ResponseEntity.ok(detail);
    }
}
