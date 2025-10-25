package com.example.bsep_team25.pki.domain;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.bouncycastle.asn1.x500.X500Name;

import java.security.PrivateKey;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class Issuer {

    private PrivateKey privateKey;
    private X500Name x500Name;

}
