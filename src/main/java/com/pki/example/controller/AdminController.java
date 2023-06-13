package com.pki.example.controller;

import ch.qos.logback.classic.Logger;
import com.pki.example.auth.AuthenticationService;
import com.pki.example.dto.*;
import com.pki.example.keystores.KeyStoreReader;
import com.pki.example.model.Permission;
import com.pki.example.model.PermissionEnum;
import com.pki.example.model.RoleEnum;
import com.pki.example.model.User;
import com.pki.example.service.AdminService;
import com.pki.example.service.CRLService;
import com.pki.example.service.UserService;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;


import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

@RestController
@CrossOrigin(origins = "*", allowedHeaders = "*")
@RequestMapping("/admin")
public class AdminController {

    @Autowired
    AdminService adminService = new AdminService();

    @Autowired
    AuthenticationService authenticationService = new AuthenticationService();

    @Autowired
    CRLService crlService = new CRLService();

    @Autowired
    UserService userService = new UserService();




    private static KeyStoreReader keyStoreReader;

    @GetMapping("/certificate-validity")
    public ResponseEntity<String> checkValidity(@RequestParam("alias") String alias) throws Exception {
        String isValid = adminService.checkValidationOfSign("example","password",alias);
        return ResponseEntity.ok().body(isValid);
    }
    @PostMapping("/create-root")
    public ResponseEntity<String> createRoot(@RequestBody RootCertificateDTO dto) throws Exception {
        KeyPair keyPair = adminService.generateKeyPair();
        X509Certificate certificate = adminService.createTrustAnchor(keyPair, dto);
        if (certificate == null) {
            return ResponseEntity.ok().body("Alias is already in use.");
        }
        adminService.generateCert("example",dto.rootName,"password",certificate,keyPair);
        return ResponseEntity.ok().body("Root certificate successfully created.");
    }
    @PostMapping("/create-ca")
    public ResponseEntity<?> createCA(@RequestParam("alias") String alias,@RequestParam("certName") String certName,@RequestBody CAandEECertificateDTO cAandEECertificateDTO) throws Exception {
        KeyPair keyPair = adminService.generateKeyPair();
        Certificate certificate = adminService.readCertificateFromKeyStore("example","password",alias);
        if(certificate == null) {
            System.out.println("There is no certificate with alias: " + alias);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("There is no certificate with alias: " + alias);
        }
        String isValid = adminService.checkValidationOfSign("example","password",alias);
        if(isValid.equals("Certificate is valid.")) {
            X509Certificate x509Certificate = (X509Certificate) certificate;
            String signer = alias;
            PrivateKey key = adminService.readKeyFromKeyStore(signer);
            X509Certificate cert = adminService.createCACertificate(x509Certificate, key, keyPair.getPublic(), 5,cAandEECertificateDTO,certName);
            if(cert == null ) {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Alias is already taken");
            }
            adminService.generateCert("example", certName, "password", cert, keyPair);
        }
        else
        {
            System.out.println("Signer don't have valid certificate");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Singer certificate is not valid");
        }
        return ResponseEntity.ok("Created successfully");
    }
    @PostMapping("/create-end-entity")
    public ResponseEntity<?> createEndEntity(@RequestParam("alias") String alias,@RequestParam("certName") String certName,@RequestBody CAandEECertificateDTO cAandEECertificateDTO) throws Exception {
        KeyPair keyPair = adminService.generateKeyPair();
        Certificate certificate = adminService.readCertificateFromKeyStore("example","password",alias);
        if(certificate == null) {
            System.out.println("There is no certificate with alias: " + alias);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("There is no certificate with alias: " + alias);
        }
        String isValid = adminService.checkValidationOfSign("example","password",alias);
        if(isValid.equals("Certificate is valid.")) {
            X509Certificate x509Certificate = (X509Certificate) certificate;
            String signer = alias;
            PrivateKey key = adminService.readKeyFromKeyStore(signer);
            X509Certificate cert = adminService.createEndEntity(x509Certificate, key, keyPair.getPublic(),cAandEECertificateDTO,certName);
            if(cert == null ) {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Alias is already taken");
            }
            adminService.generateCert("example", certName, "password", cert, keyPair);
        }
        else
        {
            System.out.println("Signer don't have valid certificate");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Singer certificate is not valid");
        }
        return ResponseEntity.ok("Created successfully");
    }

    @PostMapping("/revoke-certificate")
    public ResponseEntity<String> revokeCertificate(@RequestBody String alias) throws Exception {
        keyStoreReader = new KeyStoreReader();
        Certificate loadedCertificate = keyStoreReader.readCertificate("src/main/resources/static/" + "example" + ".jks", "password", alias);
        String revokedString = crlService.revokeCertificate("",(X509Certificate) loadedCertificate,generateKeyPair().getPrivate(),"SHA256WithRSAEncryption");
        List<X509Certificate> listCert = adminService.getAllCertificatesSignedByCA(alias,"src/main/resources/static/" + "example" + ".jks","password");
        adminService.getAliases(listCert);
        listCert.forEach(x -> crlService.revCert("",x,generateKeyPair().getPrivate(),"SHA256WithRSAEncryption"));
        return ResponseEntity.ok().body(revokedString);
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
    @GetMapping("/get-all-childs")
    public ResponseEntity<ArrayList<CertificateDTO>> getChilds() throws Exception {
        String alias = "ca1";
        ArrayList<CertificateDTO> certificateList = new ArrayList<CertificateDTO>();
        List<X509Certificate> childList = new ArrayList<X509Certificate>();
        FileInputStream fis = new FileInputStream("src/main/resources/static/" + "example" + ".jks");
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(fis, "password".toCharArray());
        fis.close();
        Map<String, Certificate> certificatesMap = new HashMap<>();
        childList = adminService.getAllCertificatesSignedByCA(alias,"src/main/resources/static/" + "example" + ".jks","password");
        childList.forEach((certificate) -> {
            String foundAlias="";
            try {
                foundAlias = keystore.getCertificateAlias(certificate);
            } catch (KeyStoreException e) {
                throw new RuntimeException(e);
            }
            if(!foundAlias.equals(alias)) {

                String issuerName = adminService.extractIssuerCN(certificate);
                String subjectName = adminService.extractSubjectCN(certificate);
                String serialNumber = certificate.getSerialNumber().toString();
                Date startDate = certificate.getNotBefore();
                Date endDate = certificate.getNotAfter();

                certificateList.add(new CertificateDTO(subjectName, issuerName, serialNumber, startDate, endDate, foundAlias));
            }
        });
        return new ResponseEntity<>(certificateList, HttpStatus.OK);
    }
    @GetMapping("/get-bellow")
    public void getBellow() throws Exception {
        List<X509Certificate> listCert = adminService.getAllCertificatesSignedByCA("one","src/main/resources/static/" + "example" + ".jks","password");
        adminService.getAliases(listCert);
    }
    @PostMapping("/download-certificate") // Endpoint za preuzimanje sertifikata po alias-u
    public ResponseEntity<DownloadDTO> downloadCertificate(@RequestBody DownloadDTO downloadDTO) throws Exception {
        System.out.println("usao");
        System.out.println(downloadDTO.getPath() + " " + downloadDTO.getAlias());
        X509Certificate certificate = adminService.findCertificateByAlias("ca1"); // Your X509Certificate object
        byte[] certBytes = certificate.getEncoded();
        String fileName = "ca1" + ".crt"; // Desired file name
        String filePath = "src\\main\\resources\\downloaded-certificates\\" + fileName; // Desired file path
        FileOutputStream fileOutputStream = new FileOutputStream(filePath);
        fileOutputStream.write(certBytes);
        fileOutputStream.close();
        return new ResponseEntity<>(downloadDTO, HttpStatus.OK);

    }
    @GetMapping("/get-trusted")
    public ArrayList<String> getTrusted() throws Exception {
        return adminService.getTrustedAliases();
    }
    @GetMapping("/first-login")
    public ResponseEntity<String> firstLogin(@RequestParam("id") String id) throws Exception {
        User user = authenticationService.getUserByUsername(id);
        adminService.FlagUp(user.getId());
        return ResponseEntity.ok().body("{\"Result\": \"" + "flag up!" + "\"}");
    }

    @GetMapping("/check-time")
    public ResponseEntity<Boolean> checkTime(@RequestParam("username") String username) throws Exception {
        boolean valid = adminService.checkTime(username);
        return ResponseEntity.ok(valid);
    }
    @PostMapping("/password")
    public ResponseEntity<String> changePassword(@RequestBody LoginDTO loginDTO) throws Exception {
        System.out.println(loginDTO.getUsername() + " " + loginDTO.getPassword());
        userService.changePassword(loginDTO.getUsername(),loginDTO.getPassword());
        return ResponseEntity.ok().body("{\"Result\": \"" + "password changed!" + "\"}");
    }

    @PostMapping("/block")
    public ResponseEntity<String> blockUser(@RequestParam("username") String username) throws Exception {
        adminService.BlockUser(username);
        return ResponseEntity.ok().body("{\"Result\": \"" + "user blocked!" + "\"}");
    }

    @GetMapping("/get-requests")
    public List<User> getRequests() throws Exception {
        return adminService.GetAllRegisterRequests();
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
    @PostMapping("/add-role-permission")
    public void addPermissionToRole(@RequestBody RolePermDTO rolePerm) throws Exception {
        int id = 0;
        if(RoleEnum.ROLE_ADMIN.toString().equals(rolePerm.getRole()))
        {
            id = RoleEnum.ROLE_ADMIN.ordinal();
        }
        else if (RoleEnum.ROLE_HR.toString().equals(rolePerm.getRole()))
        {
            id = RoleEnum.ROLE_HR.ordinal();
        }
        else if (RoleEnum.ROLE_ENGINEER.toString().equals(rolePerm.getRole()))
        {
            id = RoleEnum.ROLE_ENGINEER.ordinal();
        }
        else if (RoleEnum.ROLE_MANAGER.toString().equals(rolePerm.getRole()))
        {
            id = RoleEnum.ROLE_MANAGER.ordinal();
        }
        else
        {
            id = 0;
        }
        id++;
        Permission perm;
        int permId = 0;
        for(PermissionEnum p : PermissionEnum.values())
        {
            System.out.println(p);
            System.out.println(rolePerm.getPermission());
            if(p.toString().equals(rolePerm.getPermission()))
            {
                System.out.println(p.ordinal() + " ordinal");
                permId = p.ordinal() + 1;
            }

        }
        System.out.println(permId + " permid");

        perm = adminService.FindPermission(permId);
        System.out.println(perm.getName() + " nameizcont");
        adminService.AddRolePermissions(id,perm);
    }

    @PostMapping("/delete-role-permission")
    public void deletePermissionToRole(@RequestBody RolePermDTO rolePerm) throws Exception {
        int id = 0;
        if(RoleEnum.ROLE_ADMIN.toString().equals(rolePerm.getRole()))
        {
            id = RoleEnum.ROLE_ADMIN.ordinal();
        }
        else if (RoleEnum.ROLE_HR.toString().equals(rolePerm.getRole()))
        {
            id = RoleEnum.ROLE_HR.ordinal();
        }
        else if (RoleEnum.ROLE_ENGINEER.toString().equals(rolePerm.getRole()))
        {
            id = RoleEnum.ROLE_ENGINEER.ordinal();
        }
        else if (RoleEnum.ROLE_MANAGER.toString().equals(rolePerm.getRole()))
        {
            id = RoleEnum.ROLE_MANAGER.ordinal();
        }
        else
        {
            id = 0;
        }
        id++;
        Permission perm;
        int permId = 0;
        for(PermissionEnum p : PermissionEnum.values())
        {
            System.out.println(p);
            System.out.println(rolePerm.getPermission());
            if(p.toString().equals(rolePerm.getPermission()))
            {
                System.out.println(p.ordinal() + " ordinal");
                permId = p.ordinal() + 1;
            }

        }
        System.out.println(permId + " permid");

        perm = adminService.FindPermission(permId);
        System.out.println(perm.getName() + " nameizcont");
        adminService.DeleteRolePermission(id,perm);
    }


}
