package com.example.bsep_team25.pki.service;
import com.example.bsep_team25.model.Role;
import com.example.bsep_team25.model.User;
import com.example.bsep_team25.pki.domain.Certificate;
import com.example.bsep_team25.pki.domain.CertificateTemplate;
import com.example.bsep_team25.pki.dto.CreateCertificateRequest;
import com.example.bsep_team25.pki.dto.CreateTemplateRequest;
import com.example.bsep_team25.pki.repository.CertificateRepository;
import com.example.bsep_team25.pki.repository.CertificateTemplateRepository;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

@Service
@RequiredArgsConstructor
@Slf4j
public class CertificateTemplateService {

    private final CertificateTemplateRepository templateRepository;
    private final CertificateRepository certificateRepository;
    private final CertificateValidationService validationService;
    private final ObjectMapper objectMapper;

    /**
     * Kreira novi template (samo CA_USER i ADMIN)
     */
    @Transactional
    public CertificateTemplate createTemplate(User caUser, CreateTemplateRequest request) {
        // 1. Validacija korisnika
        if (caUser.getRole() != Role.CA_USER && caUser.getRole() != Role.ADMIN) {
            throw new SecurityException("Only CA users and admins can create templates");
        }

        // 2. Provera da li template već postoji
        if (templateRepository.existsByName(request.getName())) {
            throw new IllegalArgumentException("Template with name '" + request.getName() + "' already exists");
        }

        // 3. Validacija CA issuera
        Certificate caIssuer = certificateRepository.findBySerialNumber(request.getCaIssuerSerialNumber())
                .orElseThrow(() -> new IllegalArgumentException("CA issuer not found"));

        // Proveri da li je CA i da li je aktivan
        validationService.validateIssuerBeforeSigning(caIssuer);

        // 4. Validacija regex-a
        validateRegexPattern(request.getCnValidationRegex(), "CN validation regex");
        if (request.getSanValidationRegex() != null) {
            validateRegexPattern(request.getSanValidationRegex(), "SAN validation regex");
        }

        // 5. Validacija ekstenzija prema politici CA issuera
        validateExtensionsAgainstIssuerPolicy(
                caIssuer,
                request.getKeyUsage(),
                request.getExtendedKeyUsage()
        );

        // 6. Kreiranje template-a
        try {
            CertificateTemplate template = CertificateTemplate.builder()
                    .name(request.getName())
                    .caIssuer(caIssuer)
                    .cnValidationRegex(request.getCnValidationRegex())
                    .sanValidationRegex(request.getSanValidationRegex())
                    .maxTTLDays(request.getMaxTTLDays())
                    .keyUsage(serializeToJson(request.getKeyUsage()))
                    .extendedKeyUsage(serializeToJson(request.getExtendedKeyUsage()))
                    .createdBy(caUser)
                    .build();

            CertificateTemplate savedTemplate = templateRepository.save(template);
            log.info("Template '{}' created by user: {}", savedTemplate.getName(), caUser.getEmail());

            return savedTemplate;

        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("Failed to serialize extensions: " + e.getMessage());
        }
    }

    /**
     * Primenjuje template na zahtev za novi sertifikat
     */
    @Transactional
    public void applyTemplate(CreateCertificateRequest certRequest, String templateName) {
        CertificateTemplate template = templateRepository.findByName(templateName)
                .orElseThrow(() -> new IllegalArgumentException("Template not found: " + templateName));

        log.info("Applying template '{}' to certificate request", templateName);

        // 1. Validacija CN prema regex-u
        if (!validateAgainstRegex(certRequest.getCommonName(), template.getCnValidationRegex())) {
            throw new IllegalArgumentException(
                    String.format("Common Name '%s' does not match template regex: %s",
                            certRequest.getCommonName(), template.getCnValidationRegex())
            );
        }

        // 2. Validacija SAN prema regex-u
        if (certRequest.getSubjectAlternativeNames() != null && !certRequest.getSubjectAlternativeNames().isEmpty()) {
            if (template.getSanValidationRegex() != null) {
                for (String san : certRequest.getSubjectAlternativeNames()) {
                    String sanValue = extractSanValue(san); // Izvlači vrednost nakon "DNS:", "IP:", itd.
                    if (!validateAgainstRegex(sanValue, template.getSanValidationRegex())) {
                        throw new IllegalArgumentException(
                                String.format("SAN '%s' does not match template regex: %s",
                                        san, template.getSanValidationRegex())
                        );
                    }
                }
            }
        }

        // 3. Validacija TTL
        int requestedDays = certRequest.getValidityYears() * 365;
        if (requestedDays > template.getMaxTTLDays()) {
            throw new IllegalArgumentException(
                    String.format("Requested validity (%d days) exceeds template maximum: %d days",
                            requestedDays, template.getMaxTTLDays())
            );
        }

        // 4. Primeni default ekstenzije iz template-a (ako korisnik nije uneo svoje)
        List<String> templateKeyUsage = parseJsonArray(template.getKeyUsage());
        List<String> templateExtendedKeyUsage = parseJsonArray(template.getExtendedKeyUsage());

        // Merge template ekstenzija sa korisničkim (ako postoje)
        Set<String> finalKeyUsage = new HashSet<>();
        Set<String> finalExtendedKeyUsage = new HashSet<>();

        // Dodaj ekstenzije iz template-a
        if (templateKeyUsage != null) {
            finalKeyUsage.addAll(templateKeyUsage);
        }
        if (templateExtendedKeyUsage != null) {
            finalExtendedKeyUsage.addAll(templateExtendedKeyUsage);
        }

        // Dodaj korisničke ekstenzije (ako postoje)
        if (certRequest.getKeyUsage() != null && !certRequest.getKeyUsage().isEmpty()) {
            finalKeyUsage.addAll(certRequest.getKeyUsage());
        }
        if (certRequest.getExtendedKeyUsage() != null && !certRequest.getExtendedKeyUsage().isEmpty()) {
            finalExtendedKeyUsage.addAll(certRequest.getExtendedKeyUsage());
        }

        // 5. Validacija finalnih ekstenzija prema politici CA issuera
        validateExtensionsAgainstIssuerPolicy(
                template.getCaIssuer(),
                new ArrayList<>(finalKeyUsage),
                new ArrayList<>(finalExtendedKeyUsage)
        );

        // 6. Postavi finalne vrednosti u request
        certRequest.setKeyUsage(new ArrayList<>(finalKeyUsage));
        certRequest.setExtendedKeyUsage(new ArrayList<>(finalExtendedKeyUsage));
        certRequest.setIssuerSerialNumber(template.getCaIssuer().getSerialNumber());

        log.info("Template applied successfully. Final KeyUsage: {}, ExtendedKeyUsage: {}",
                finalKeyUsage, finalExtendedKeyUsage);
    }

    /**
     * Validira ekstenzije prema politici CA sertifikata
     */
    private void validateExtensionsAgainstIssuerPolicy(
            Certificate caIssuer,
            List<String> requestedKeyUsage,
            List<String> requestedExtendedKeyUsage) {

        // Parse ekstenzije CA issuera iz JSON-a
        List<String> issuerKeyUsage = extractKeyUsageFromCertificate(caIssuer);

        log.info("Validating extensions against CA issuer policy. CA has KeyUsage: {}", issuerKeyUsage);

        // Provera: CA mora imati keyCertSign da bi izdavao sertifikate
        if (issuerKeyUsage == null || !issuerKeyUsage.contains("keyCertSign")) {
            throw new IllegalArgumentException("CA issuer does not have keyCertSign permission");
        }

        // Dodatna validacija: EE sertifikati ne smeju imati keyCertSign
        if (requestedKeyUsage != null && requestedKeyUsage.contains("keyCertSign")) {
            throw new IllegalArgumentException("End-entity certificates cannot have keyCertSign extension");
        }

        // Provera: ako CA ima ograničenje na pathLength, proveriti da ne prekoračuje
        // (ovo je kompleksnije, ali može se implementirati ako treba)

        log.info("Extension validation passed");
    }

    /**
     * Izvlači KeyUsage iz Certificate extensions JSON-a
     */
    private List<String> extractKeyUsageFromCertificate(Certificate cert) {
        try {
            if (cert.getExtensions() == null || cert.getExtensions().isEmpty()) {
                return List.of();
            }

            // Parse JSON extensions
            var extensionsMap = objectMapper.readValue(cert.getExtensions(),
                    new TypeReference<java.util.Map<String, Object>>() {});

            Object keyUsageObj = extensionsMap.get("keyUsage");
            if (keyUsageObj instanceof List) {
                return (List<String>) keyUsageObj;
            }
            return List.of();

        } catch (Exception e) {
            log.warn("Failed to parse extensions from certificate: {}", e.getMessage());
            return List.of();
        }
    }

    /**
     * Izvlači vrednost iz SAN formata (npr. "DNS:example.com" -> "example.com")
     */
    private String extractSanValue(String san) {
        if (san.contains(":")) {
            return san.substring(san.indexOf(":") + 1);
        }
        return san;
    }

    /**
     * Validira string prema regex patternu
     */
    private boolean validateAgainstRegex(String value, String regex) {
        try {
            return Pattern.matches(regex, value);
        } catch (PatternSyntaxException e) {
            log.error("Invalid regex pattern: {}", regex);
            return false;
        }
    }

    /**
     * Validira da li je regex pattern ispravan
     */
    private void validateRegexPattern(String regex, String fieldName) {
        try {
            Pattern.compile(regex);
        } catch (PatternSyntaxException e) {
            throw new IllegalArgumentException(
                    String.format("Invalid %s: %s", fieldName, e.getMessage())
            );
        }
    }

    /**
     * Serijalizuje listu u JSON string
     */
    private String serializeToJson(List<String> list) throws JsonProcessingException {
        if (list == null || list.isEmpty()) {
            return "[]";
        }
        return objectMapper.writeValueAsString(list);
    }

    /**
     * Parsira JSON array u List<String>
     */
    private List<String> parseJsonArray(String json) {
        try {
            if (json == null || json.trim().isEmpty() || json.equals("[]")) {
                return List.of();
            }
            return objectMapper.readValue(json, new TypeReference<List<String>>() {});
        } catch (JsonProcessingException e) {
            log.error("Failed to parse JSON array: {}", json, e);
            return List.of();
        }
    }

    // ==================== CRUD Operacije ====================

    public List<CertificateTemplate> getAllTemplates() {
        return templateRepository.findAll();
    }

    public List<CertificateTemplate> getTemplatesByIssuer(String issuerSerial) {
        return templateRepository.findByCaIssuer_SerialNumber(issuerSerial);
    }

    public List<CertificateTemplate> getTemplatesByUser(User user) {
        return templateRepository.findByCreatedBy(user);
    }

    public CertificateTemplate getTemplateByName(String name) {
        return templateRepository.findByName(name)
                .orElseThrow(() -> new IllegalArgumentException("Template not found: " + name));
    }

    @Transactional
    public void deleteTemplate(String name, User user) {
        CertificateTemplate template = getTemplateByName(name);

        // Samo kreator ili admin može obrisati template
        if (!template.getCreatedBy().equals(user) && user.getRole() != Role.ADMIN) {
            throw new SecurityException("You don't have permission to delete this template");
        }

        templateRepository.delete(template);
        log.info("Template '{}' deleted by user: {}", name, user.getEmail());
    }

    /**
     * Validira CSR prema šablonu (za CSR upload scenario)
     */
    public void validateCSRAgainstTemplate(
            String templateName,
            String commonName,
            List<String> subjectAlternativeNames,
            Integer validityYears) {

        CertificateTemplate template = templateRepository.findByName(templateName)
                .orElseThrow(() -> new IllegalArgumentException("Template not found: " + templateName));

        log.info("Validating CSR against template '{}'", templateName);

        // 1. Validacija CN
        if (!validateAgainstRegex(commonName, template.getCnValidationRegex())) {
            throw new IllegalArgumentException(
                    String.format("CSR Common Name '%s' does not match template regex: %s",
                            commonName, template.getCnValidationRegex())
            );
        }

        // 2. Validacija SAN
        if (subjectAlternativeNames != null && !subjectAlternativeNames.isEmpty()) {
            if (template.getSanValidationRegex() != null) {
                for (String san : subjectAlternativeNames) {
                    String sanValue = extractSanValue(san);
                    if (!validateAgainstRegex(sanValue, template.getSanValidationRegex())) {
                        throw new IllegalArgumentException(
                                String.format("CSR SAN '%s' does not match template regex: %s",
                                        san, template.getSanValidationRegex())
                        );
                    }
                }
            }
        }

        // 3. Validacija TTL
        int requestedDays = validityYears * 365;
        if (requestedDays > template.getMaxTTLDays()) {
            throw new IllegalArgumentException(
                    String.format("CSR requested validity (%d days) exceeds template maximum: %d days",
                            requestedDays, template.getMaxTTLDays())
            );
        }

        log.info("CSR validation against template '{}' passed", templateName);
    }
}
