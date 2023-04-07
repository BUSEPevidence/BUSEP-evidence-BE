package com.pki.example.controller;

import com.pki.example.data.Issuer;
import com.pki.example.data.Subject;
import com.pki.example.keystores.KeyStoreReader;
import com.pki.example.service.AdminService;
import com.pki.example.service.CRLService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.security.*;
import java.security.cert.Certificate;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/admin")
public class AdminController {

    @Autowired
    AdminService adminService = new AdminService();
    @Autowired
    CRLService crlService = new CRLService();

    private static KeyStoreReader keyStoreReader;
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
        //Subject subject = adminService.generateSubject("Ivana Kovacevic", "Kovacevic", "Ivana", "UNS-FTN", "Katedra za informatiku", "RS", "kovacevic.ivana@uns.ac.rs", "123456");
        adminService.checkValidationOfSign("example","password","raca");


    }
    @GetMapping("/create-root")
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
        String signer = "root";
        PrivateKey key = adminService.readKeyFromKeyStore(signer);
        X509Certificate cert = adminService.createCACertificate(x509Certificate,key, keyPair.getPublic(),5);
        adminService.generateCert("example","maca","password",cert,keyPair);
    }
    @GetMapping("/create-end-entity")
    public void createEndEntity() throws Exception {
        KeyPair keyPair = adminService.generateKeyPair();
        Certificate certificate = adminService.readCertificateFromKeyStore("example","password","maca");
        X509Certificate x509Certificate = (X509Certificate) certificate;
        String signer = "ca";
        PrivateKey key = adminService.readKeyFromKeyStore(signer);
        X509Certificate cert = adminService.createEndEntity(x509Certificate,key,keyPair.getPublic());
        adminService.generateCert("example","raca","password",cert,keyPair);
    }

    @GetMapping("/revoke-certificate")
    public void revokeCertificate() throws Exception {
        keyStoreReader = new KeyStoreReader();
        //String alias = "ca";
        //String keyStoreFileName = "example";
        //String password = "password";
        Certificate loadedCertificate = keyStoreReader.readCertificate("src/main/resources/static/" + "example" + ".jks", "password", "maca");
        crlService.revokeCertificate("",(X509Certificate) loadedCertificate,generateKeyPair().getPrivate(),"SHA256WithRSAEncryption");
        Map<String, Certificate> certificatesMap = new HashMap<>();
        certificatesMap = adminService.getAllCertificatesSignBy((X509Certificate) loadedCertificate);
        certificatesMap.forEach((alias, cert) -> crlService.revCert("", (X509Certificate) cert,generateKeyPair().getPrivate(),"SHA256WithRSAEncryption"));

    }

    @GetMapping("/get-info")
    public void getCertificateInfo() throws Exception {
           }


    private KeyPair generateKeyPair() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
            keyGen.initialize(2048, random);
            return keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
        return null;
    }


}
