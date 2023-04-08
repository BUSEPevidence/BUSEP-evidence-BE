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
import java.util.List;
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
        String isValid = adminService.checkValidationOfSign("example","password","fourth");


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
        Certificate certificate = adminService.readCertificateFromKeyStore("example","password","one");
        String isValid = adminService.checkValidationOfSign("example","password","one");
        if(isValid.equals("")) {
            X509Certificate x509Certificate = (X509Certificate) certificate;
            String signer = "one";
            PrivateKey key = adminService.readKeyFromKeyStore(signer);
            X509Certificate cert = adminService.createCACertificate(x509Certificate, key, keyPair.getPublic(), 5);
            adminService.generateCert("example", "seven", "password", cert, keyPair);
        }
        else
        {
            System.out.println("Signer don't have valid certificate");
        }
    }
    @GetMapping("/create-end-entity")
    public void createEndEntity() throws Exception {
        KeyPair keyPair = adminService.generateKeyPair();
        Certificate certificate = adminService.readCertificateFromKeyStore("example","password","fifth");
        String isValid = adminService.checkValidationOfSign("example","password","one");
        if(isValid.equals("")) {
            X509Certificate x509Certificate = (X509Certificate) certificate;
            String signer = "fifth";
            PrivateKey key = adminService.readKeyFromKeyStore(signer);
            X509Certificate cert = adminService.createEndEntity(x509Certificate, key, keyPair.getPublic());
            adminService.generateCert("example", "six", "password", cert, keyPair);
        }
        else
        {
            System.out.println("Signer don't have valid certificate");
        }
    }

    @GetMapping("/revoke-certificate")
    public void revokeCertificate() throws Exception {
        keyStoreReader = new KeyStoreReader();
        //String alias = "ca";
        //String keyStoreFileName = "example";
        //String password = "password";
        Certificate loadedCertificate = keyStoreReader.readCertificate("src/main/resources/static/" + "example" + ".jks", "password", "one");
        crlService.revokeCertificate("",(X509Certificate) loadedCertificate,generateKeyPair().getPrivate(),"SHA256WithRSAEncryption");
        List<X509Certificate> listCert = adminService.getAllCertificatesSignedByCA("one","src/main/resources/static/" + "example" + ".jks","password");
        System.out.println(listCert.size() + " eo size liste");
        adminService.getAliases(listCert);
//        Map<String, Certificate> certificatesMap = new HashMap<>();
//        certificatesMap = adminService.getAllCertificatesSignBy((X509Certificate) loadedCertificate);
//        certificatesMap.forEach((alias, cert) -> crlService.revCert("", (X509Certificate) cert,generateKeyPair().getPrivate(),"SHA256WithRSAEncryption"));
        listCert.forEach(x -> crlService.revCert("",x,generateKeyPair().getPrivate(),"SHA256WithRSAEncryption"));
    }

    @GetMapping("/get-all-from-store")
    public void getCertificateInfo() throws Exception {
        Map<String, Certificate> certificatesMap = new HashMap<>();
        certificatesMap = adminService.getAllFromStore("example","password");
        certificatesMap.forEach((alias,certificate) -> System.out.println(alias + "\n Certificate: " + certificate));
    }
    @GetMapping("/get-bellow")
    public void getBellow() throws Exception {
        List<X509Certificate> listCert = adminService.getAllCertificatesSignedByCA("one","src/main/resources/static/" + "example" + ".jks","password");
        adminService.getAliases(listCert);
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
