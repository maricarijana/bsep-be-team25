package com.example.bsep_team25.pki.domain;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;

import java.security.PublicKey;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class Subject {

    private String commonName;
    private String organization;
    private String organizationalUnit;
    private String country;
    private String state;
    private String locality;
    private String email;
    private PublicKey publicKey;

    public X500Name toX500Name() {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);

        builder.addRDN(BCStyle.CN, commonName);
        builder.addRDN(BCStyle.O, organization);

        if (organizationalUnit != null && !organizationalUnit.isEmpty()) {
            builder.addRDN(BCStyle.OU, organizationalUnit);
        }
        if (country != null && !country.isEmpty()) {
            builder.addRDN(BCStyle.C, country);
        }
        if (state != null && !state.isEmpty()) {
            builder.addRDN(BCStyle.ST, state);
        }
        if (locality != null && !locality.isEmpty()) {
            builder.addRDN(BCStyle.L, locality);
        }
        if (email != null && !email.isEmpty()) {
            builder.addRDN(BCStyle.E, email);
        }

        return builder.build();
    }

}
