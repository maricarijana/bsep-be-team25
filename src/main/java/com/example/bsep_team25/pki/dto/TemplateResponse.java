package com.example.bsep_team25.pki.dto;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class TemplateResponse {

    private Long id;
    private String name;
    private String caIssuerSerialNumber;
    private String caIssuerCommonName;
    private String cnValidationRegex;
    private String sanValidationRegex;
    private Integer maxTTLDays;
    private List<String> keyUsage;
    private List<String> extendedKeyUsage;
    private String createdByEmail;
    private LocalDateTime createdAt;
}
