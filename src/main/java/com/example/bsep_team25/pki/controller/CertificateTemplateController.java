package com.example.bsep_team25.pki.controller;
import com.example.bsep_team25.model.User;
import com.example.bsep_team25.pki.domain.CertificateTemplate;
import com.example.bsep_team25.pki.dto.CreateTemplateRequest;
import com.example.bsep_team25.pki.dto.TemplateResponse;
import com.example.bsep_team25.pki.service.CertificateTemplateService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/pki/templates")
@RequiredArgsConstructor
@Slf4j
public class CertificateTemplateController {

    private final CertificateTemplateService templateService;
    private final ObjectMapper objectMapper;

    /**
     * Kreiranje novog template-a (samo CA_USER i ADMIN)
     */
    @PostMapping
    @PreAuthorize("hasAuthority('CA_USER') or hasAuthority('ADMIN')")
    public ResponseEntity<?> createTemplate(
            @AuthenticationPrincipal User user,
            @Valid @RequestBody CreateTemplateRequest request) {
        try {
            CertificateTemplate template = templateService.createTemplate(user, request);
            return ResponseEntity.ok(Map.of(
                    "message", "Template created successfully",
                    "template", mapToResponse(template)
            ));
        } catch (SecurityException e) {
            log.error("Security error: ", e);
            return ResponseEntity.status(403).body(Map.of("error", e.getMessage()));
        } catch (IllegalArgumentException e) {
            log.error("Validation error: ", e);
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        } catch (Exception e) {
            log.error("Error creating template: ", e);
            return ResponseEntity.badRequest().body(Map.of("error", "Failed to create template: " + e.getMessage()));
        }
    }

    /**
     * Dobavi sve template-e
     */
    @GetMapping
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<List<TemplateResponse>> getAllTemplates() {
        List<CertificateTemplate> templates = templateService.getAllTemplates();
        return ResponseEntity.ok(
                templates.stream()
                        .map(this::mapToResponse)
                        .collect(Collectors.toList())
        );
    }

    /**
     * Dobavi template-e za određenog issuera (za dropdown pri izdavanju sertifikata)
     */
    @GetMapping("/by-issuer/{issuerSerial}")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<List<TemplateResponse>> getTemplatesByIssuer(
            @PathVariable String issuerSerial) {
        List<CertificateTemplate> templates = templateService.getTemplatesByIssuer(issuerSerial);
        return ResponseEntity.ok(
                templates.stream()
                        .map(this::mapToResponse)
                        .collect(Collectors.toList())
        );
    }

    /**
     * Dobavi template-e koje je kreirao trenutni korisnik
     */
    @GetMapping("/my")
    @PreAuthorize("hasAuthority('CA_USER') or hasAuthority('ADMIN')")
    public ResponseEntity<List<TemplateResponse>> getMyTemplates(
            @AuthenticationPrincipal User user) {
        List<CertificateTemplate> templates = templateService.getTemplatesByUser(user);
        return ResponseEntity.ok(
                templates.stream()
                        .map(this::mapToResponse)
                        .collect(Collectors.toList())
        );
    }

    /**
     * Dobavi jedan template po imenu
     */
    @GetMapping("/{name}")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> getTemplateByName(@PathVariable String name) {
        try {
            CertificateTemplate template = templateService.getTemplateByName(name);
            return ResponseEntity.ok(mapToResponse(template));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(404).body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * Obriši template (samo kreator ili admin)
     */
    @DeleteMapping("/{name}")
    @PreAuthorize("hasAuthority('CA_USER') or hasAuthority('ADMIN')")
    public ResponseEntity<?> deleteTemplate(
            @PathVariable String name,
            @AuthenticationPrincipal User user) {
        try {
            templateService.deleteTemplate(name, user);
            return ResponseEntity.ok(Map.of("message", "Template deleted successfully"));
        } catch (SecurityException e) {
            return ResponseEntity.status(403).body(Map.of("error", e.getMessage()));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(404).body(Map.of("error", e.getMessage()));
        }
    }

    // ==================== Helper Methods ====================

    private TemplateResponse mapToResponse(CertificateTemplate template) {
        return TemplateResponse.builder()
                .id(template.getId())
                .name(template.getName())
                .caIssuerSerialNumber(template.getCaIssuer().getSerialNumber())
                .caIssuerCommonName(template.getCaIssuer().getCommonName())
                .cnValidationRegex(template.getCnValidationRegex())
                .sanValidationRegex(template.getSanValidationRegex())
                .maxTTLDays(template.getMaxTTLDays())
                .keyUsage(parseJsonArray(template.getKeyUsage()))
                .extendedKeyUsage(parseJsonArray(template.getExtendedKeyUsage()))
                .createdByEmail(template.getCreatedBy().getEmail())
                .createdAt(template.getCreatedAt())
                .build();
    }

    private List<String> parseJsonArray(String json) {
        try {
            if (json == null || json.trim().isEmpty() || json.equals("[]")) {
                return List.of();
            }
            return objectMapper.readValue(json, new TypeReference<List<String>>() {});
        } catch (JsonProcessingException e) {
            log.error("Failed to parse JSON: {}", json);
            return List.of();
        }
    }
}
