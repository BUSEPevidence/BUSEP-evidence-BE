package com.pki.example.controller;

import com.pki.example.data.Certificate;
import com.pki.example.data.Issuer;
import com.pki.example.data.Subject;
import com.pki.example.service.AdminService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.PublicKey;

@RestController
@RequestMapping("/admin")
public class AdminController {

    @Autowired
    AdminService adminService = new AdminService();
    PublicKey publicKey;
    Issuer issuer;
    @GetMapping("/generate-certificate")
    public void genCA() throws Exception {
        Issuer issuer = adminService.generateIssuer("IT sluzba","sluzba","IT","UNS-FTN","Katedra za informatiku","RS","itsluzba@uns.ac.rs","654321");
        Subject subject = adminService.generateSubject("Ivana Kovacevic", "Kovacevic", "Ivana", "UNS-FTN", "Katedra za informatiku", "RS", "kovacevic.ivana@uns.ac.rs", "123456");
        com.pki.example.data.Certificate certificate = adminService.getEndEntityCertificate(issuer,subject,"2023-03-23","2028-03-23");
        //adminService.checkValidationOfSign("proba","certificate","123",certificate);
        adminService.generateCertificate("example","cert8","password",certificate);
        publicKey = issuer.getPublicKey();
    }
    @GetMapping("/certificate-validity")
    public void checkValidity() throws Exception {

        //Issuer issuer = adminService.generateIssuer("IT sluzba","sluzba","IT","UNS-FTN","Katedra za informatiku","RS","itsluzba@uns.ac.rs","654321");
        PublicKey pk = adminService.getIssuerFromKeyStore();
        //PublicKey pk = issuer.getPublicKey();
        Subject subject = adminService.generateSubject("Ivana Kovacevic", "Kovacevic", "Ivana", "UNS-FTN", "Katedra za informatiku", "RS", "kovacevic.ivana@uns.ac.rs", "123456");
        adminService.checkValidationOfSign("example","password","cert8",pk);


    }
}
