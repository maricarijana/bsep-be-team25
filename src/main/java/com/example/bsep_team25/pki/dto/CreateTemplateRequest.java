package com.example.bsep_team25.pki.dto;
import jakarta.validation.constraints.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class CreateTemplateRequest {

    @NotBlank(message = "Template name is required")
    private String name;

    @NotBlank(message = "CA issuer serial number is required")
    private String caIssuerSerialNumber;

    @NotBlank(message = "CN validation regex is required")
    private String cnValidationRegex; // npr. .*\.ftn\.com

    private String sanValidationRegex; // Opciono

    @NotNull(message = "Max TTL is required")
    @Min(value = 1, message = "TTL must be at least 1 day")
    @Max(value = 3650, message = "TTL cannot exceed 10 years")
    private Integer maxTTLDays;

    private List<String> keyUsage; // ["digitalSignature", "keyCertSign"]

    private List<String> extendedKeyUsage; // ["serverAuth", "clientAuth"]
}
