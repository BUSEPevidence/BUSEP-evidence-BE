package com.pki.example.controller;

import com.pki.example.data.Issuer;
import com.pki.example.data.Subject;
import com.pki.example.dto.CAandEECertificateDTO;
import com.pki.example.dto.CertificateDTO;
import com.pki.example.keystores.KeyStoreReader;
import com.pki.example.service.AdminService;
import com.pki.example.service.CRLService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.*;
import java.security.cert.Certificate;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.*;

@RestController
@CrossOrigin(origins = "*", allowedHeaders = "*")
@RequestMapping("/admin")
public class AdminController {

    @Autowired
    AdminService adminService = new AdminService();
    @Autowired
    CRLService crlService = new CRLService();

    private static KeyStoreReader keyStoreReader;

    @GetMapping("/certificate-validity")
    public void checkValidity(@RequestParam("alias") String alias) throws Exception {
        String isValid = adminService.checkValidationOfSign("example","password",alias);
    }
    @PostMapping("/create-root")
    public void createRoot(@RequestParam("root") String root,@RequestParam("yearsOfValidity") Integer yearsOfValidity) throws Exception {
        KeyPair keyPair = adminService.generateKeyPair();
        X509Certificate certificate = adminService.createTrustAnchor(keyPair,root,yearsOfValidity);
        adminService.generateCert("example",root,"password",certificate,keyPair);
    }
    @PostMapping("/create-ca")
    public void createCA(@RequestParam("alias") String alias,@RequestParam("certName") String certName,@RequestBody CAandEECertificateDTO cAandEECertificateDTO) throws Exception {
        KeyPair keyPair = adminService.generateKeyPair();
        Certificate certificate = adminService.readCertificateFromKeyStore("example","password",alias);
        if(certificate == null) {
            System.out.println("There is no certificate with alias: " + alias);
            return;
        }
        String isValid = adminService.checkValidationOfSign("example","password",alias);
        if(isValid.equals("")) {
            X509Certificate x509Certificate = (X509Certificate) certificate;
            String signer = alias;
            PrivateKey key = adminService.readKeyFromKeyStore(signer);
            X509Certificate cert = adminService.createCACertificate(x509Certificate, key, keyPair.getPublic(), 5,cAandEECertificateDTO,certName);
            if(cert == null ) return;
            adminService.generateCert("example", certName, "password", cert, keyPair);
        }
        else
        {
            System.out.println("Signer don't have valid certificate");
        }
    }
    @PostMapping("/create-end-entity")
    public void createEndEntity(@RequestParam("alias") String alias,@RequestParam("certName") String certName,@RequestBody CAandEECertificateDTO cAandEECertificateDTO) throws Exception {
        KeyPair keyPair = adminService.generateKeyPair();
        Certificate certificate = adminService.readCertificateFromKeyStore("example","password",alias);
        if(certificate == null) {
            System.out.println("There is no certificate with alias: " + alias);
            return;
        }
        String isValid = adminService.checkValidationOfSign("example","password",alias);
        if(isValid.equals("")) {
            X509Certificate x509Certificate = (X509Certificate) certificate;
            String signer = alias;
            PrivateKey key = adminService.readKeyFromKeyStore(signer);
            X509Certificate cert = adminService.createEndEntity(x509Certificate, key, keyPair.getPublic(),cAandEECertificateDTO,certName);
            if(cert == null ) return;
            adminService.generateCert("example", certName, "password", cert, keyPair);
        }
        else
        {
            System.out.println("Signer don't have valid certificate");
        }
    }

    @PostMapping("/revoke-certificate")
    public void revokeCertificate(@RequestParam String alias) throws Exception {
        keyStoreReader = new KeyStoreReader();
        Certificate loadedCertificate = keyStoreReader.readCertificate("src/main/resources/static/" + "example" + ".jks", "password", alias);
        crlService.revokeCertificate("",(X509Certificate) loadedCertificate,generateKeyPair().getPrivate(),"SHA256WithRSAEncryption");
        List<X509Certificate> listCert = adminService.getAllCertificatesSignedByCA(alias,"src/main/resources/static/" + "example" + ".jks","password");
        System.out.println(listCert.size() + " eo size liste");
        adminService.getAliases(listCert);
        listCert.forEach(x -> crlService.revCert("",x,generateKeyPair().getPrivate(),"SHA256WithRSAEncryption"));
    }

    @GetMapping("/get-all-from-store")
    public ResponseEntity<ArrayList<CertificateDTO>> getCertificateInfo() throws Exception {
        ArrayList<CertificateDTO> certificateList = new ArrayList<CertificateDTO>();
        Map<String, Certificate> certificatesMap = new HashMap<>();
        certificatesMap = adminService.getAllFromStore("example","password");
        certificatesMap.forEach((alias, certificate) -> {
            String issuerName = adminService.extractIssuerCN((X509Certificate)certificate);
            String subjectName = adminService.extractSubjectCN((X509Certificate)certificate);
            String serialNumber = ((X509Certificate) certificate).getSerialNumber().toString();
            Date startDate = ((X509Certificate) certificate).getNotBefore();
            Date endDate = ((X509Certificate) certificate).getNotAfter();

            certificateList.add(new CertificateDTO(subjectName, issuerName, serialNumber, startDate, endDate, alias));
        });
        return new ResponseEntity<>(certificateList, HttpStatus.OK);
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
