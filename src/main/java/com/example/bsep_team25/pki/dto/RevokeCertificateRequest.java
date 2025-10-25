package com.example.bsep_team25.pki.dto;

import lombok.Data;

@Data
public class RevokeCertificateRequest {
    private String serialNumber;
    private String reason;

}
