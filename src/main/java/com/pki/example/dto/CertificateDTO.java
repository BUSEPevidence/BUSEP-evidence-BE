package com.pki.example.dto;

import com.pki.example.data.Issuer;
import com.pki.example.data.Subject;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.security.cert.X509Certificate;
import java.util.Date;

@Getter
@Setter
@AllArgsConstructor
public class CertificateDTO {
    private String subjectName;
    private String issuerName;
    private String serialNumber;
    private Date startDate;
    private Date endDate;
    private String alias;

}
