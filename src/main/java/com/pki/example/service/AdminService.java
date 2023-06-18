package com.pki.example.service;

import ch.qos.logback.classic.Logger;
import com.pki.example.ExampleApplication;
import com.pki.example.certificates.CertificateExample;
import com.pki.example.certificates.CertificateGenerator;
import com.pki.example.controller.AdminController;
import com.pki.example.data.Issuer;
import com.pki.example.data.Subject;
import com.pki.example.dto.CAandEECertificateDTO;
import com.pki.example.dto.RootCertificateDTO;
import com.pki.example.email.model.EmailDetails;
import com.pki.example.email.service.IEmailService;
import com.pki.example.keystores.KeyStoreReader;
import com.pki.example.keystores.KeyStoreWriter;
import com.pki.example.model.AdminLogins;
import com.pki.example.model.Permission;
import com.pki.example.model.Role;
import com.pki.example.model.User;
import com.pki.example.repo.AdminRepository;
import com.pki.example.repo.PermissionRepository;
import com.pki.example.repo.RoleRepository;
import com.pki.example.repo.UserRepository;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.*;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.oer.its.EndEntityType;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.context.ApplicationContext;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;
import javax.servlet.http.HttpServletRequest;
import java.io.*;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;

import static org.postgresql.shaded.com.ongres.scram.common.ScramStringFormatting.base64Decode;
import static org.postgresql.shaded.com.ongres.scram.common.ScramStringFormatting.base64Encode;

@Service
public class AdminService {
    private static CertificateExample certExample;

    @Autowired
    private IEmailService emailService;

    private static KeyStoreReader keyStoreReader;

    private static KeyStoreWriter keyStoreWriter;

    private static ApplicationContext context;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private AdminRepository adminRepository;

    @Autowired
    private PermissionRepository permissionRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private CRLService crlService = new CRLService();

    @Autowired
    SimpMessagingTemplate simpMessagingTemplate;
    private static final Logger logger = (Logger) LoggerFactory.getLogger(AdminController.class);

    @Value("${custom.nameKey}")
    String nameKey;

    @Value("${custom.surnameKey}")
    String surnameKey;

    @Value("${custom.addressKey}")
    String addressKey;

    @Value("${custom.phoneKey}")
    String phoneKey;


    public User encryptUser(User user) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        String keyString = nameKey;
        byte[] bytes = keyString.getBytes(StandardCharsets.UTF_8);
        Key namKey = new SecretKeySpec(bytes, "AES");

        String surKey = surnameKey;
        byte[] surByt = surKey.getBytes(StandardCharsets.UTF_8);
        Key surnKey = new SecretKeySpec(surByt, "AES");

        String addrKey = addressKey;
        byte[] addByt = addrKey.getBytes(StandardCharsets.UTF_8);
        Key addKey = new SecretKeySpec(addByt, "AES");

        String phoKey = phoneKey;
        byte[] phoByt = phoKey.getBytes(StandardCharsets.UTF_8);
        Key phoneKey = new SecretKeySpec(phoByt, "AES");

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, namKey);
        byte[] EncryptedString = cipher.doFinal(user.getFirstname().getBytes(StandardCharsets.UTF_8));
        String encryptedName = base64Encode(EncryptedString);
        user.setFirstname(encryptedName);

        Cipher cipherr = Cipher.getInstance("AES");
        cipherr.init(Cipher.ENCRYPT_MODE, surnKey);
        byte[] EncBytSur = cipherr.doFinal(user.getLastname().getBytes(StandardCharsets.UTF_8));
        String encSurname = base64Encode(EncBytSur);
        user.setLastname(encSurname);

        Cipher cipherrr = Cipher.getInstance("AES");
        cipherrr.init(Cipher.ENCRYPT_MODE, surnKey);
        byte[] EncBytAddr = cipherrr.doFinal(user.getAddress().getBytes(StandardCharsets.UTF_8));
        String encAddr = base64Encode(EncBytAddr);
        user.setAddress(encAddr);

        Cipher cipherrrr = Cipher.getInstance("AES");
        cipherrrr.init(Cipher.ENCRYPT_MODE, phoneKey);
        byte[] EncBytPhone = cipherrrr.doFinal(user.getNumber().getBytes(StandardCharsets.UTF_8));
        String encPhone = base64Encode(EncBytPhone);
        user.setNumber(encPhone);


        return user;
    }
    public User decryptUser(User user) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        String keyString = nameKey;
        byte[] bytes = keyString.getBytes(StandardCharsets.UTF_8);
        Key namKey = new SecretKeySpec(bytes, "AES");

        String surKey = surnameKey;
        byte[] surByt = surKey.getBytes(StandardCharsets.UTF_8);
        Key surnKey = new SecretKeySpec(surByt, "AES");

        String addrKey = addressKey;
        byte[] addByt = addrKey.getBytes(StandardCharsets.UTF_8);
        Key addKey = new SecretKeySpec(addByt, "AES");

        String phoKey = phoneKey;
        byte[] phoByt = phoKey.getBytes(StandardCharsets.UTF_8);
        Key phoneKey = new SecretKeySpec(phoByt, "AES");


        byte[] decodedBytes = base64Decode(user.getFirstname());
        System.out.println("Proso1");
        Cipher cipher = Cipher.getInstance("AES");
        System.out.println("Proso2");System.out.println("Proso1");
        cipher.init(Cipher.DECRYPT_MODE, namKey);
        System.out.println("Proso3");
        byte[] decryptedName = cipher.doFinal(decodedBytes);
        System.out.println("Proso4");
        String encryptedName = new String(decryptedName);
        System.out.println("Proso5");
        user.setFirstname(encryptedName);
        System.out.println("Proso6");

        byte[] decodedBytesSurname = base64Decode(user.getLastname());
        Cipher cipherr = Cipher.getInstance("AES");
        cipherr.init(Cipher.DECRYPT_MODE, surnKey);
        byte[] decryptedSurname = cipherr.doFinal(decodedBytesSurname);
        String encSurname = new String(decryptedSurname);
        user.setLastname(encSurname);
        System.out.println("Proso7");


        byte[] decodedBytesAddress = base64Decode(user.getAddress());
        Cipher cipherrr = Cipher.getInstance("AES");
        cipherrr.init(Cipher.DECRYPT_MODE, surnKey);
        byte[] decryptedAddress = cipherrr.doFinal(decodedBytesAddress);
        String encAddr = new String(decryptedAddress);
        user.setAddress(encAddr);

        byte[] decodedBytesNumber = base64Decode(user.getNumber());
        Cipher cipherrrr = Cipher.getInstance("AES");
        cipherrrr.init(Cipher.DECRYPT_MODE, phoneKey);
        byte[] decryptedPhone = cipherrrr.doFinal(decodedBytesNumber);
        String encPhone = new String(decryptedPhone);
        user.setNumber(encPhone);
        System.out.println("Proso9");


        return user;
    }


    public X509Certificate generateCert(String keyStoreFileName,String certificateName,String keyStorePassword,X509Certificate cert,KeyPair keyPair)
    {
        keyStoreReader = new KeyStoreReader();
        keyStoreWriter = new KeyStoreWriter();

        System.out.println("Novi sertifikat:");
        System.out.println(cert);

        // Inicijalizacija fajla za cuvanje sertifikata
        System.out.println("Cuvanje certifikata u jks fajl:");
        keyStoreWriter.loadKeyStore("src/main/resources/static/" + keyStoreFileName + ".jks",  keyStorePassword.toCharArray());
        PrivateKey pk = keyPair.getPrivate();
        keyStoreWriter.write(certificateName, pk, keyStorePassword.toCharArray(), cert);
        keyStoreWriter.saveKeyStore("src/main/resources/static/"  + keyStoreFileName + ".jks",  keyStorePassword.toCharArray());
        System.out.println("Cuvanje certifikata u jks fajl zavrseno.");
        return cert;
    }

    public PrivateKey readKeyFromKeyStore(String signer) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException, UnrecoverableKeyException {
        keyStoreReader = new KeyStoreReader();
        keyStoreWriter = new KeyStoreWriter();

        KeyStore keystore = KeyStore.getInstance("JKS");
        BufferedInputStream in = new BufferedInputStream(new FileInputStream("src/main/resources/static/example.jks"));
        keystore.load(in, "password".toCharArray());
        Key key = keystore.getKey(signer, "password".toCharArray());
        if (key instanceof PrivateKey) {
            return (PrivateKey) key;
        } else {
            throw new IllegalStateException("Private key not found in keystore");
        }
    }
    public Certificate readCertificateFromKeyStore(String keyStoreFileName,String password,String alias)
    {
        keyStoreReader = new KeyStoreReader();
        keyStoreWriter = new KeyStoreWriter();

        System.out.println("Ucitavanje sertifikata iz jks fajla:");
        Certificate loadedCertificate = keyStoreReader.readCertificate("src/main/resources/static/" + keyStoreFileName + ".jks", password, alias);
        System.out.println(loadedCertificate);

        return loadedCertificate;
    }

    public String checkValidationOfSign(String keyStoreFileName,String password,String alias)
    {
        keyStoreReader = new KeyStoreReader();
        keyStoreWriter = new KeyStoreWriter();;
       // com.pki.example.data.Certificate certificate = certificatte;
        Certificate loadedCertificate = keyStoreReader.readCertificate("src/main/resources/static/" + keyStoreFileName + ".jks", password, alias);
        if(loadedCertificate == null) return null;
        System.out.println(loadedCertificate);
        System.out.println("Provera potpisa:");
        // to do
        try {
            if(crlService.getCRL("src/main/resources/static/CRL.jks")
                    .getRevokedCertificate(((X509Certificate)loadedCertificate).getSerialNumber()) != null) {
                System.out.println("CERTIFICATE IS REVOKED!");
                return "CERTIFICATE IS REVOKED!";
            }
            PublicKey pubK = loadedCertificate.getPublicKey();
            byte[] signatureValue = ((X509Certificate)loadedCertificate).getSignature();
            Signature signature = Signature.getInstance("SHA256WithRSAEncryption");
            signature.initVerify(pubK);
            signature.update(((X509Certificate)loadedCertificate).getTBSCertificate());
            signature.verify(signatureValue);


            ((X509Certificate) loadedCertificate).checkValidity();
            System.out.println("Certificate is valid.");
        } catch (CertificateExpiredException e) {
            System.out.println("Certificate has expired.");
            return "Certificate has expired.";
        } catch (CertificateNotYetValidException e) {
            System.out.println("Certificate is not yet valid.");
            return "Certificate is not yet valid.";
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
        catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new RuntimeException(e.getMessage());
        }
        return "Certificate is valid.";
    }
    public KeyPair generateKeyPair() {
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

    private static long serialNumberBase = System.currentTimeMillis();


    /**
     * Calculate a serial number using a monotonically increasing value.
     *
     * @return a BigInteger representing the next serial number in the sequence.
     */
    public static synchronized BigInteger calculateSerialNumber()
    {
        return BigInteger.valueOf(serialNumberBase++);
    }
    public static X509Certificate createTrustAnchor(KeyPair keyPair, RootCertificateDTO dto)
            throws OperatorCreationException, CertificateException {
        if(isAliasUsed(dto.rootName)){
            System.out.println("Alias is used choose another!");
            return null;
        }
        //X500Name name = new X500Name("CN=" + rootName);
        //Umjesto x500Name napravim x500Principal subject-a
        X500Principal subject = new X500Principal("CN=" + dto.rootName + "," + "O=" + dto.organization + ","
                + "OU=" + dto.orgainzationUnit + "," + "C=" + dto.country);

        Calendar calendar = Calendar.getInstance();
        Date currentDate = new Date();
        calendar.setTime(currentDate);
        calendar.add(Calendar.YEAR,dto.yearsOfValidity);
        Date dateOfExpirement = calendar.getTime();

        //Umjesto name proslijedim subjecta
        X509v1CertificateBuilder certBldr = new JcaX509v1CertificateBuilder(
                subject,
                calculateSerialNumber(),
                new Date(),
                dateOfExpirement,
                subject,
                keyPair.getPublic());

        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption")
                .setProvider("BC").build(keyPair.getPrivate());

        JcaX509CertificateConverter converter = new JcaX509CertificateConverter().setProvider("BC");

        return converter.getCertificate(certBldr.build(signer));
    }
    public static X509Certificate createEndEntity(X509Certificate signerCert, PrivateKey signerKey, PublicKey certKey, CAandEECertificateDTO cAandEECertificateDTO, String certName) throws CertIOException, OperatorCreationException, CertificateException {

        if (isEndEntity(signerCert)) {
            System.out.println("You cannot create an end-entity certificate because the parent certificate is an end-entity!");
            return null;
        }

        if (isAliasUsed(certName)) {
            System.out.println("Alias is already used. Please choose another!");
            return null;
        }

        X500Principal subject = new X500Principal("CN=" + cAandEECertificateDTO.subjectName + "," + "O=" + cAandEECertificateDTO.organization + ","
                + "OU=" + cAandEECertificateDTO.orgainzationUnit + "," + "C=" + cAandEECertificateDTO.country);

        Calendar calendar = Calendar.getInstance();
        Date currentDate = new Date();
        calendar.setTime(currentDate);
        calendar.add(Calendar.YEAR, cAandEECertificateDTO.yearsOfValidity);
        Date dateOfExpiration = calendar.getTime();

        X509v3CertificateBuilder certBldr = new JcaX509v3CertificateBuilder(
                signerCert.getSubjectX500Principal(),
                calculateSerialNumber(),
                new Date(),
                dateOfExpiration,
                subject,
                certKey);

        // Add Basic Constraints extension
        certBldr.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

        // Add Key Usage extension for SSL/TLS
        certBldr.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));

        // Add Extended Key Usage extension for SSL/TLS server authentication
        KeyPurposeId[] keyPurposeIds = { KeyPurposeId.id_kp_serverAuth };
        certBldr.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(keyPurposeIds));

        // Add Subject Alternative Name (SAN) extension
        GeneralName[] sanNames = { new GeneralName(GeneralName.dNSName, "localhost") };
        GeneralNames san = new GeneralNames(sanNames);
        certBldr.addExtension(Extension.subjectAlternativeName, false, san);

        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption").setProvider("BC").build(signerKey);
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter().setProvider("BC");

        return converter.getCertificate(certBldr.build(signer));
    }

    public static X509Certificate createCACertificate(
            X509Certificate signerCert, PrivateKey signerKey,
            PublicKey certKey, int followingCACerts, CAandEECertificateDTO cAandEECertificateDTO,String certName)
            throws GeneralSecurityException,
            OperatorCreationException, IOException
    {

        if(isEndEntity(signerCert) ){
            System.out.println("You cannot create End-entity certificate because parent certificate is End-entity!");
            return null;
        }

        if(isAliasUsed(certName)){
            System.out.println("Alias is used choose another!");
            return null;
        }
        X500Principal subject = new X500Principal("CN=" + cAandEECertificateDTO.subjectName + "," + "O=" + cAandEECertificateDTO.organization + ","
                + "OU=" + cAandEECertificateDTO.orgainzationUnit + "," + "C=" + cAandEECertificateDTO.country);

        Calendar calendar = Calendar.getInstance();
        Date currentDate = new Date();
        calendar.setTime(currentDate);
        calendar.add(Calendar.YEAR,cAandEECertificateDTO.yearsOfValidity);
        Date dateOfExpirement = calendar.getTime();

        X509v3CertificateBuilder certBldr = new JcaX509v3CertificateBuilder(
                signerCert.getSubjectX500Principal(),
                calculateSerialNumber(),
                new Date(),
                dateOfExpirement,
                subject,
                certKey);


        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        GeneralNames subjectAltNames = new GeneralNames(new GeneralName(GeneralName.dNSName, "localhost"));
        Extension sanExtension = new Extension(Extension.subjectAlternativeName, true, subjectAltNames.getEncoded());

        certBldr.addExtension(org.bouncycastle.asn1.x509.Extension.basicConstraints,
                        true, new BasicConstraints(followingCACerts))
                .addExtension(org.bouncycastle.asn1.x509.Extension.keyUsage,
                        true, new KeyUsage(KeyUsage.keyCertSign
                                | KeyUsage.cRLSign
                                | KeyUsage.keyEncipherment
                                | KeyUsage.digitalSignature))
                .addExtension(sanExtension);


        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption")
                .setProvider("BC").build(signerKey);


        JcaX509CertificateConverter converter = new JcaX509CertificateConverter().setProvider("BC");


        return converter.getCertificate(certBldr.build(signer));
    }
    public X509Certificate printCertificateInfo(X509Certificate xcertificate) {
        Map<String, Certificate> certificatesMap = new HashMap<>();
        try {
            // Load the keystore

            KeyStoreReader keyStoreReader = new KeyStoreReader();
            KeyStore keystore = KeyStore.getInstance("JKS");
            keystore.load(new FileInputStream("src/main/resources/static/example.jks"), "password".toCharArray());

            // Retrieve all certificates from the keystore
            String issuerCN = extractSubjectCN(xcertificate);
            Enumeration<String> aliases = keystore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                Certificate certificate = keystore.getCertificate(alias);
                certificatesMap.put(alias, certificate);
                System.out.println("Alias: " + alias);
                System.out.println("Certificate: " + certificate);
                X509Certificate keyStoreX509Certificate = (X509Certificate)certificate;
                if(issuerCN.equals(extractIssuerCN(keyStoreX509Certificate)))
                {
                    Certificate loadedCertificate = keyStoreReader.readCertificate("src/main/resources/static/" + "example" + ".jks", "password", alias);
                    crlService.revCert("", (X509Certificate) loadedCertificate,generateKeyPair().getPrivate(),"SHA256WithRSAEncryption");
                    System.out.println("Nasao issuera " + extractIssuerCN(keyStoreX509Certificate) + " == " + issuerCN);
                    return keyStoreX509Certificate;
                }
                else
                {
                    continue;
                }

            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
    public static boolean isAliasUsed(String checkCertName) {
        keyStoreReader = new KeyStoreReader();
       if(keyStoreReader.readCertificate("src/main/resources/static/example.jks", "password", checkCertName) == null)
           return false;
       return true;
    }

    public boolean checkTime(String username) {
        System.out.println(username + " evo username");
        User user = userRepository.findOneByUsername(username);
        System.out.println(user.getId() + " eo id");
        System.out.println(user.getFirstname() + " eo name");
        AdminLogins adminLogins = adminRepository.findOneByUserId(user.getId());
        if(adminLogins == null) return true;
        if(adminLogins.getChangedPassword())return true;
        return false;
    }
    public Map getAllFromStore(String store,String password) {
        Map<String, Certificate> certificatesMap = new HashMap<>();
        try {
            // Load the keystore

            KeyStoreReader keyStoreReader = new KeyStoreReader();
            KeyStore keystore = KeyStore.getInstance("JKS");
            keystore.load(new FileInputStream("src/main/resources/static/"+ store +".jks"), password.toCharArray());

            // Retrieve all certificates from the keystore
            Enumeration<String> aliases = keystore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                Certificate certificate = keystore.getCertificate(alias);
                //System.out.println("Alias: " + alias);
                //System.out.println("Certificate: " + certificate);
                certificatesMap.put(alias, certificate);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return certificatesMap;
    }
public static List<X509Certificate> getAllCertificatesSignedByCA(String caAlias, String keyStorePath, String keyStorePassword) throws Exception {
    List<X509Certificate> certificates = new ArrayList<>();
    List<X509Certificate> newCertificates = new ArrayList<>();
    certificates.addAll(getCertificatesSignedByCA(caAlias, keyStorePath, keyStorePassword));

    for (int i = 0; i < certificates.size(); i++) {
        X509Certificate certificate = certificates.get(i);
        String alias = certificate.getSubjectX500Principal().getName();
        List<X509Certificate> signedCertificates = getAllCertificatesSignedByCA(alias, keyStorePath, keyStorePassword);
        for (X509Certificate signedCertificate : signedCertificates) {
            if (!certificates.contains(signedCertificate) && !newCertificates.contains(signedCertificate)) {
                newCertificates.add(signedCertificate);
            }
        }
    }

    certificates.addAll(newCertificates);

    return certificates;
}

    public static List<X509Certificate> getCertificatesSignedByCA(String caAlias, String keyStorePath, String keyStorePassword) throws Exception {
        List<X509Certificate> certificates = new ArrayList<>();
        try (InputStream is = new FileInputStream(keyStorePath)) {
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(is, keyStorePassword.toCharArray());

            X509Certificate caCertificate = (X509Certificate) keyStore.getCertificate(caAlias);
            if (caCertificate != null) {
                certificates.add(caCertificate); // Add the CA certificate to the list
                List<X509Certificate> signedCertificates = getSignedCertificates(caCertificate, keyStore);
                certificates.addAll(signedCertificates);
            }
        }

        return certificates;
    }

    public static List<X509Certificate> getSignedCertificates(X509Certificate certificate, KeyStore keyStore) throws Exception {
        List<X509Certificate> signedCertificates = new ArrayList<>();
        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            Certificate cert = keyStore.getCertificate(alias);
            if (cert instanceof X509Certificate) {
                X509Certificate x509Certificate = (X509Certificate) cert;
                if (!x509Certificate.equals(certificate) && isSignedBy(x509Certificate, certificate)) {
                    signedCertificates.add(x509Certificate);
                    signedCertificates.addAll(getSignedCertificates(x509Certificate, keyStore));
                }
            }
        }
        return signedCertificates;
    }

    public static boolean isSignedBy(X509Certificate certificate, X509Certificate caCertificate) {
        try {
            certificate.verify(caCertificate.getPublicKey());
            return true;
        } catch (Exception e) {
            return false;
        }
    }
    public static String extractIssuerCN(X509Certificate certificate) {
        // Get the issuer distinguished name (DN) from the certificate
        String issuerDN = certificate.getIssuerDN().getName();

        // Split the issuer DN into individual attribute-value pairs
        String[] issuerAttrs = issuerDN.split(",");

        // Loop through the attribute-value pairs to find the Common Name (CN)
        for (String attr : issuerAttrs) {
            if (attr.trim().startsWith("CN=")) {
                // Extract the CN value by removing the "CN=" prefix
                return attr.trim().substring(3);
            }
        }

        // If CN is not found, return null
        return null;
    }
    public static String extractSubjectCN(X509Certificate certificate) {
        // Get the subject distinguished name (DN) from the certificate
        String subjectDN = certificate.getSubjectDN().getName();

        // Split the subject DN into individual attribute-value pairs
        String[] subjectAttrs = subjectDN.split(",");

        // Loop through the attribute-value pairs to find the Common Name (CN)
        for (String attr : subjectAttrs) {
            if (attr.trim().startsWith("CN=")) {
                // Extract the CN value by removing the "CN=" prefix
                return attr.trim().substring(3);
            }
        }

        // If CN is not found, return null
        return null;
    }

    public X509Certificate findCertificateByAlias(String alias) throws Exception {
        // Check if the alias exists in the keystore
        String keystoreFile = "src/main/resources/static/example.jks";
        String keystorePassword = "password";
        KeyStore keyStore = KeyStore.getInstance("JKS");
        FileInputStream fis = new FileInputStream(keystoreFile);
        keyStore.load(fis, keystorePassword.toCharArray());
        fis.close();
        if (keyStore.containsAlias(alias)) {
            Certificate certificate = keyStore.getCertificate(alias);
            if (certificate instanceof X509Certificate) {
                return (X509Certificate) certificate;
            } else {
                throw new Exception("Certificate with alias " + alias + " is not an X509Certificate");
            }
        } else {
            throw new Exception("Certificate with alias " + alias + " not found in keystore");
        }
    }
    public void getAliases(List<X509Certificate> certs) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        String keystoreFile = "src/main/resources/static/example.jks";
        String keystorePassword = "password";
        KeyStore keyStoree = KeyStore.getInstance("JKS");
        FileInputStream fis = new FileInputStream(keystoreFile);
        keyStoree.load(fis, keystorePassword.toCharArray());
        fis.close();
        List<X509Certificate> certificates = certs; // List of X509Certificate objects
        KeyStore keyStore = keyStoree; // Your KeyStore object

        List<String> aliases = new ArrayList<>();

        try {
            for (X509Certificate certificate : certificates) {
                Enumeration<String> keyAliases = keyStore.aliases();
                while (keyAliases.hasMoreElements()) {
                    String alias = keyAliases.nextElement();
                    Certificate cert = keyStore.getCertificate(alias);
                    if (cert instanceof X509Certificate && certificate.equals(cert)) {
                        System.out.println(alias + " alias");
                        aliases.add(alias);
                        break; // Exit the inner loop once a matching alias is found
                    }
                }
            }
        } catch (KeyStoreException e) {
            // Handle KeyStoreException as needed
        }
    }

    public static boolean isEndEntity(X509Certificate cert) {
        try {
            // Verify that the certificate has the digitalSignature or keyEncipherment bit set in the KeyUsage extension
            boolean[] keyUsage = cert.getKeyUsage();
            if (keyUsage != null && (keyUsage[0] || keyUsage[2])) {
                // The digitalSignature or keyEncipherment bit is set, which means this is an end-entity certificate
                return true;
            }

            // Verify that the certificate does not have the cA bit set in the basicConstraints extension
            BasicConstraints basicConstraints = BasicConstraints.getInstance(cert.getExtensionValue("2.5.29.19"));
            if (basicConstraints != null && basicConstraints.isCA()) {
                // The certificate is a CA or root certificate, not an end-entity certificate
                return false;
            }

            // If the key usage extension is not present and the basic constraints extension is present but the CA flag is not set,
            // we consider this to be an end-entity certificate as well.
            if (keyUsage == null && basicConstraints != null && !basicConstraints.isCA()) {
                return true;
            }

            // If we reach this point, the certificate is not an end-entity certificate
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    public ArrayList<String> getTrustedAliases() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException{
        String keystoreFile = "src/main/resources/static/example.jks";
        String keystorePassword = "password";
        ArrayList<String> aliases = new ArrayList<String>();
        FileInputStream fis = new FileInputStream(keystoreFile);
        KeyStore keystore = KeyStore.getInstance("JKS");
        keystore.load(fis, keystorePassword.toCharArray());
        Enumeration<String> aliasEnum = keystore.aliases();
        while (aliasEnum.hasMoreElements()) {
            String alias = aliasEnum.nextElement();
            Certificate cert = keystore.getCertificate(alias);
            if (cert instanceof X509Certificate) {
                X509Certificate x509cert = (X509Certificate) cert;
                X500Principal issuer = x509cert.getIssuerX500Principal();
                X500Principal subject = x509cert.getSubjectX500Principal();
                if (x509cert.getKeyUsage() != null && x509cert.getKeyUsage().length > 5 && x509cert.getKeyUsage()[5]) {
                    String isValid = checkValidationOfSign("example","password",alias);
                    if(isValid.equals("Certificate is valid.")){
                        aliases.add(alias);
                    }
                }
                if (issuer.equals(subject)){
                    System.out.println(alias);
                    String isValid = checkValidationOfSign("example","password",alias);
                    if(alias.equals("mycert")) aliases.add(alias);
                    if(!alias.equals("mycert") && isValid.equals("Certificate is valid.") ){
                        aliases.add(alias);
                    }
                }
            }
        }
        fis.close();
        return aliases;
    }
    public Permission FindPermission(int Id)
    {
        Permission permission = permissionRepository.findOneById(Id);


        return permission;
    }
    public String AddRolePermissions(int id,Permission permission)
    {

        Role role = roleRepository.findOneById(id);
        System.out.println(role.getName() + " dajemo " + permission.getName());
        List<Permission> permissionList = role.getPermissions();
        permissionList.add(permission);
        role.setPermissions(permissionList);
        roleRepository.save(role);


        return "Added";
    }
    public void FlagUp(int user_id)
    {
       AdminLogins adminLogins = adminRepository.findOneByUserId(user_id);
       adminLogins.setChangedPassword(true);
       adminRepository.save(adminLogins);
    }
    public String DeleteRolePermission(int id,Permission permission)
    {

        List<Permission> permList = new ArrayList<>();
        Role role = roleRepository.findOneById(id);
        System.out.println(role.getName() + " dajemo " + permission.getName());
        List<Permission> permissionList = role.getPermissions();
        for(Permission p : permissionList)
        {
            if(p.getId() != permission.getId())
            {
                permList.add(p);
            }
        }
        permissionList.add(permission);
        role.setPermissions(permList);
        roleRepository.save(role);


        return "Added";
    }
    public String BlockUser(String username)
    {

        User user = userRepository.findOneByUsername(username);
        logger.info("Block failed: ");
        user.setRefreshToken("");
        user.setBlocked(true);
        userRepository.save(user);

        return "Blocked";
    }
    public String SendAdminsEmail(String problem)
    {

        List<User> users = userRepository.findAll();
        for(User user : users)
        {
            for(Role role : user.getRoles()){
                if(role.getName().equals("\"ROLE_ADMIN\"")){
                    EmailDetails emailDetails = new EmailDetails();
                    emailDetails.setMsgBody("Critical!<br/>" +
                            "Critical:" + "there are suspicious actions on application: " + problem + "</h2> <br/>");
                    emailDetails.setSubject("Welcome email");
                    emailDetails.setRecipient(user.getUsername());
                    emailService.sendWelcomeMail(emailDetails);

                }
            }

        }

        return "Email sent";
    }
    public List<User> GetAllRegisterRequests() throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
         String tmp = "";
         List<User> users = userRepository.findAll();
         List<User> retUsers = new ArrayList<>();
         for(User user : users)
         {
             if(!user.isAdminApprove()) {
                 for (Role role : user.getRoles()) {
                     tmp += role.getName() + ",";
                 }
                 if (tmp.length() != 0)
                     tmp = tmp.substring(0, tmp.length() - 1);
                 user.setPassword(tmp);
                 tmp = "";
                 User tmpUser = decryptUser(user);
                 retUsers.add(tmpUser);

             }

         }

        System.out.println(retUsers.size() + " eo velicina");
        return retUsers;
    }

}
