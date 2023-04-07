package com.pki.example.controller;

import com.pki.example.data.Issuer;
import com.pki.example.data.Subject;
import com.pki.example.service.AdminService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

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
        adminService.generateCertificate("example","certTest","password",certificate);
        publicKey = issuer.getPublicKey();
    }
    @GetMapping("/certificate-validity")
    public void checkValidity() throws Exception {

        //Issuer issuer = adminService.generateIssuer("IT sluzba","sluzba","IT","UNS-FTN","Katedra za informatiku","RS","itsluzba@uns.ac.rs","654321");
        //PublicKey pk = adminService.getIssuerFromKeyStore();
        //PublicKey pk = issuer.getPublicKey();
        PublicKey pk = adminService.readPublicKeyFromKeyStore();
        Subject subject = adminService.generateSubject("Ivana Kovacevic", "Kovacevic", "Ivana", "UNS-FTN", "Katedra za informatiku", "RS", "kovacevic.ivana@uns.ac.rs", "123456");
        adminService.checkValidationOfSign("example","password","ca",pk);


    }
    @GetMapping("/root")
    public void createRoot() throws Exception {
        KeyPair keyPair = adminService.generateKeyPair();
        X509Certificate certificate = adminService.createTrustAnchor(keyPair);
        adminService.generateCert("example","root","password",certificate,keyPair);
    }
    @GetMapping("/create-ca")
    public void createCA() throws Exception {
        KeyPair keyPair = adminService.generateKeyPair();
        Certificate certificate = adminService.readCertificateFromKeyStore("example","password","root");
        X509Certificate x509Certificate = (X509Certificate) certificate;
        PrivateKey key = adminService.readKeyFromKeyStore();
        X509Certificate cert = adminService.createCACertificate(x509Certificate,key, keyPair.getPublic(),5);
        adminService.generateCert("example","CA","password",cert,keyPair);
    }
}
