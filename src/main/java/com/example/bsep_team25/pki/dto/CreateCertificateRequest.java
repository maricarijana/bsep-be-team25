package com.example.bsep_team25.pki.dto;

import lombok.Data;

import java.util.List;

@Data
public class CreateCertificateRequest {

    private String commonName;
    private String organization;
    private String organizationalUnit;
    private String country;
    private String state;
    private String locality;
    private String email;

    // Validnost
    private Integer validityYears;

    // Issuer (za intermediate i EE)
    private String issuerSerialNumber;

    // BasicConstraints
    private Boolean isCA;
    private Integer pathLength;

    // Ekstenzije
    private List<String> keyUsage; // ["keyCertSign", "digitalSignature"]
    private List<String> extendedKeyUsage; // ["serverAuth", "clientAuth"]
    private List<String> subjectAlternativeNames; // ["DNS:example.com", "IP:192.168.1.1"]

    private Long ownerId;
    private String templateName;
}
