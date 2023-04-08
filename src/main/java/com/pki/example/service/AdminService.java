package com.pki.example.service;

import com.pki.example.ExampleApplication;
import com.pki.example.certificates.CertificateExample;
import com.pki.example.certificates.CertificateGenerator;
import com.pki.example.data.Issuer;
import com.pki.example.data.Subject;
import com.pki.example.keystores.KeyStoreReader;
import com.pki.example.keystores.KeyStoreWriter;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.*;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.context.ApplicationContext;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import javax.security.auth.x500.X500Principal;
import javax.servlet.http.HttpServletRequest;
import java.io.*;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;

@Service
public class AdminService {
    private static CertificateExample certExample;

    private static KeyStoreReader keyStoreReader;

    private static KeyStoreWriter keyStoreWriter;

    private static ApplicationContext context;

    @Autowired
    private CRLService crlService = new CRLService();


    public com.pki.example.data.Certificate generateCertificate(String keyStoreFileName,String certificateName,String keyStorePassword,com.pki.example.data.Certificate cert)
    {
        keyStoreReader = new KeyStoreReader();
        keyStoreWriter = new KeyStoreWriter();
        //certExample = (CertificateExample) context.getBean("certificateExample");

        com.pki.example.data.Certificate certificate = cert;
        System.out.println("Novi sertifikat:");
        System.out.println(certificate.getX509Certificate());

        // Inicijalizacija fajla za cuvanje sertifikata
        System.out.println("Cuvanje certifikata u jks fajl:");
        keyStoreWriter.loadKeyStore("src/main/resources/static/" + keyStoreFileName + ".jks",  keyStorePassword.toCharArray());
        PrivateKey pk = certificate.getIssuer().getPrivateKey();
        keyStoreWriter.write(certificateName, pk, keyStorePassword.toCharArray(), certificate.getX509Certificate());
        keyStoreWriter.saveKeyStore("src/main/resources/static/"  + keyStoreFileName + ".jks",  keyStorePassword.toCharArray());
        System.out.println("Cuvanje certifikata u jks fajl zavrseno.");
        return certificate;



    }
    public X509Certificate generateCert(String keyStoreFileName,String certificateName,String keyStorePassword,X509Certificate cert,KeyPair keyPair)
    {
        keyStoreReader = new KeyStoreReader();
        keyStoreWriter = new KeyStoreWriter();
        //certExample = (CertificateExample) context.getBean("certificateExample");

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
    public PublicKey readPublicKeyFromKeyStore() throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException, UnrecoverableKeyException {
        KeyStoreReader keyStoreReader = new KeyStoreReader();

        KeyStore keystore = KeyStore.getInstance("JKS");
        BufferedInputStream in = new BufferedInputStream(new FileInputStream("src/main/resources/static/example.jks"));
        keystore.load(in, "password".toCharArray());

        // Get the certificate from the keystore using the alias
        Certificate cert = keystore.getCertificate("ca");
        if (cert != null) {
            // Extract the public key from the certificate
            PublicKey publicKey = cert.getPublicKey();
            return publicKey;
        } else {
            throw new IllegalStateException("Certificate not found in keystore");
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
        return "";
    }
    public Subject generateSubject(String CN,String Surname,String Name,String O,String OU,String C,String Email,String UID) {
        KeyPair keyPairSubject = generateKeyPair();

        //klasa X500NameBuilder pravi X500Name objekat koji predstavlja podatke o vlasniku
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.CN, CN);
        builder.addRDN(BCStyle.SURNAME, Surname);
        builder.addRDN(BCStyle.GIVENNAME, Name);
        builder.addRDN(BCStyle.O, O);
        builder.addRDN(BCStyle.OU, OU);
        builder.addRDN(BCStyle.C, C);
        builder.addRDN(BCStyle.E, Email);
        //UID (USER ID) je ID korisnika
        builder.addRDN(BCStyle.UID, UID);

        return new Subject(keyPairSubject.getPublic(), builder.build());
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
    public Issuer generateIssuer(String CN,String Surname,String Name,String O,String OU,String C,String Email,String UID) {
        KeyPair kp = generateKeyPair();
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.CN, CN);
        builder.addRDN(BCStyle.SURNAME, Surname);
        builder.addRDN(BCStyle.GIVENNAME, Name);
        builder.addRDN(BCStyle.O, O);
        builder.addRDN(BCStyle.OU, OU);
        builder.addRDN(BCStyle.C, C);
        builder.addRDN(BCStyle.E, Email);
        //UID (USER ID) je ID korisnika
        builder.addRDN(BCStyle.UID, UID);
        //Kreiraju se podaci za issuer-a, sto u ovom slucaju ukljucuje:
        // - privatni kljuc koji ce se koristiti da potpise sertifikat koji se izdaje
        // - podatke o vlasniku sertifikata koji izdaje nov sertifikat
        return new Issuer(kp.getPrivate(), kp.getPublic(), builder.build());
    }
    public com.pki.example.data.Certificate getEndEntityCertificate(Issuer issuerData,Subject subjectData,String startValidDate,String endValidDate) {

        try {
            Issuer issuer = issuerData;
            Subject subject = subjectData;

            //Datumi od kad do kad vazi sertifikat
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
            Date startDate = sdf.parse(startValidDate);
            Date endDate = sdf.parse(endValidDate);

            X509Certificate certificate = CertificateGenerator.generateCertificate(subject,
                    issuer, startDate, endDate, "1");

            return new com.pki.example.data.Certificate(subject, issuer,
                    "1", startDate, endDate, certificate);
        } catch (ParseException e) {
            e.printStackTrace();
        }

        return null;
    }
    public com.pki.example.data.Certificate getSelfSignedCertificate(Issuer issuerData,String startValidDate,String endValidDate) {

        try {
            Issuer issuer = issuerData;
            Subject subject = new Subject();

            //Datumi od kad do kad vazi sertifikat
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
            Date startDate = sdf.parse(startValidDate);
            Date endDate = sdf.parse(endValidDate);

            X509Certificate certificate = CertificateGenerator.generateCertificate(subject,
                    issuer, startDate, endDate, "1");

            return new com.pki.example.data.Certificate(subject, issuer,
                    "1", startDate, endDate, certificate);
        } catch (ParseException e) {
            e.printStackTrace();
        }

        return null;
    }
    public static Date calculateDate(int hoursInFuture)
    {
        long secs = System.currentTimeMillis() / 1000;


        return new Date((secs + (hoursInFuture * 60 * 60)) * 1000);
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
    public static X509Certificate createTrustAnchor(
            KeyPair keyPair)
            throws OperatorCreationException, CertificateException
    {
        X500Name name = new X500Name("CN=Trust Anchor");


        X509v1CertificateBuilder certBldr = new JcaX509v1CertificateBuilder(
                name,
                calculateSerialNumber(),
                calculateDate(0),
                calculateDate(24 * 365),
                name,
                keyPair.getPublic());


        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption")
                .setProvider("BC").build(keyPair.getPrivate());


        JcaX509CertificateConverter converter = new JcaX509CertificateConverter().setProvider("BC");


        return converter.getCertificate(certBldr.build(signer));
    }
    public static X509Certificate createEndEntity(
            X509Certificate signerCert, PrivateKey signerKey,
            PublicKey certKey)
            throws CertIOException, OperatorCreationException, CertificateException
    {
        X500Principal subject = new X500Principal("CN=End Entity");


        X509v3CertificateBuilder  certBldr = new JcaX509v3CertificateBuilder(
                signerCert.getSubjectX500Principal(),
                calculateSerialNumber(),
                calculateDate(0),
                calculateDate(24 * 31),
                subject,
                certKey);


        certBldr.addExtension(org.bouncycastle.asn1.x509.Extension.basicConstraints,
                        true, new BasicConstraints(false))
                .addExtension(org.bouncycastle.asn1.x509.Extension.keyUsage,
                        true, new KeyUsage(KeyUsage.digitalSignature));


        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption")
                .setProvider("BC").build(signerKey);


        JcaX509CertificateConverter converter = new JcaX509CertificateConverter().setProvider("BC");


        return converter.getCertificate(certBldr.build(signer));
    }

    public static X509Certificate createCACertificate(
            X509Certificate signerCert, PrivateKey signerKey,
             PublicKey certKey, int followingCACerts)
            throws GeneralSecurityException,
            OperatorCreationException, CertIOException
    {
        X500Principal subject = new X500Principal("CN=Certificate Authority");


        X509v3CertificateBuilder certBldr = new JcaX509v3CertificateBuilder(
                signerCert.getSubjectX500Principal(),
                calculateSerialNumber(),
                calculateDate(0),
                calculateDate(24 * 60),
                subject,
                certKey);


        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();


        certBldr.addExtension(org.bouncycastle.asn1.x509.Extension.basicConstraints,
                        true, new BasicConstraints(followingCACerts))
                .addExtension(org.bouncycastle.asn1.x509.Extension.keyUsage,
                        true, new KeyUsage(KeyUsage.keyCertSign
                                | KeyUsage.cRLSign));


        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption")
                .setProvider("BC").build(signerKey);


        JcaX509CertificateConverter converter = new JcaX509CertificateConverter().setProvider("BC");


        return converter.getCertificate(certBldr.build(signer));
    }
    public PublicKey getIssuerFromKeyStore() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        InputStream inputStream = new FileInputStream("src/main/resources/static/example.jks"); // replace with your KeyStore source
        String password = "password"; // replace with your KeyStore password
        keyStore.load(inputStream, password.toCharArray());
        String alias = "cert8"; // replace with the alias of the certificate for which you want to get issuer information
        Certificate certificate = keyStore.getCertificate(alias);
        PublicKey issuerPublicKey = null;
        if (certificate instanceof X509Certificate) {
            X509Certificate x509Certificate = (X509Certificate) certificate;
            X500Principal issuerPrincipal = x509Certificate.getIssuerX500Principal();

            // Retrieve the issuer's public key from the KeyStore
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String keyStoreAlias = aliases.nextElement();
                Certificate keyStoreCertificate = keyStore.getCertificate(keyStoreAlias);
                if (keyStoreCertificate instanceof X509Certificate) {
                    X509Certificate keyStoreX509Certificate = (X509Certificate) keyStoreCertificate;
                    X500Principal keyStoreIssuerPrincipal = keyStoreX509Certificate.getIssuerX500Principal();
                    if (issuerPrincipal.equals(keyStoreIssuerPrincipal)) {
                        issuerPublicKey = keyStoreX509Certificate.getPublicKey();
                        break;
                    }
                }
            }


        }
        return issuerPublicKey;
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
    public Map getAllCertificatesSignBy(X509Certificate xcertificate) {
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

                System.out.println("Alias: " + alias);
                System.out.println("Certificate: " + certificate);
                X509Certificate keyStoreX509Certificate = (X509Certificate)certificate;
                if(issuerCN.equals(extractIssuerCN(keyStoreX509Certificate)))
                {
                    certificatesMap.put(alias, certificate);
                }

            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return certificatesMap;
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
                System.out.println("Alias: " + alias);
                System.out.println("Certificate: " + certificate);
                certificatesMap.put(alias, certificate);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return certificatesMap;
    }
//    public static List<X509Certificate> getAllCertificatesSignedByCA(String caAlias, String keyStorePath, String keyStorePassword) throws Exception {
//        List<X509Certificate> certificates = new ArrayList<>();
//        List<X509Certificate> newCertificates = new ArrayList<>(); // New list to hold newly discovered certificates
//        certificates.addAll(getCertificatesSignedByCA(caAlias, keyStorePath, keyStorePassword));
//
//        for (X509Certificate certificate : certificates) {
//            String alias = certificate.getSubjectX500Principal().getName();
//            List<X509Certificate> signedCertificates = getAllCertificatesSignedByCA(alias, keyStorePath, keyStorePassword);
//            if (signedCertificates != null && !signedCertificates.isEmpty()) {
//                newCertificates.addAll(signedCertificates); // Add newly discovered certificates to the new list
//            }
//        }
//
//        certificates.addAll(newCertificates); // Add all newly discovered certificates to the certificates list
//
//        return certificates;
//    }
//public static List<X509Certificate> getAllCertificatesSignedByCA(String caAlias, String keyStorePath, String keyStorePassword) throws Exception {
//    List<X509Certificate> certificates = new ArrayList<>();
//    List<X509Certificate> newCertificates = new ArrayList<>();
//
//    certificates.addAll(getCertificatesSignedByCA(caAlias, keyStorePath, keyStorePassword));
//
//    int index = 0;
//    while (index < certificates.size()) {
//        X509Certificate certificate = certificates.get(index);
//        String alias = certificate.getSubjectX500Principal().getName();
//        List<X509Certificate> signedCertificates = getCertificatesSignedByCA(alias, keyStorePath, keyStorePassword);
//        if (signedCertificates != null && !signedCertificates.isEmpty()) {
//            for (X509Certificate signedCertificate : signedCertificates) {
//                if (!certificates.contains(signedCertificate) && !newCertificates.contains(signedCertificate)) {
//                    newCertificates.add(signedCertificate);
//                }
//            }
//        }
//        index++;
//        if (index >= certificates.size() && !newCertificates.isEmpty()) {
//            certificates.addAll(newCertificates);
//            index = 0;
//            newCertificates.clear();
//        }
//    }
//
//    return certificates;
//}
//    public static List<X509Certificate> getCertificatesSignedByCA(String caAlias, String keyStorePath, String keyStorePassword) throws Exception {
//        List<X509Certificate> certificates = new ArrayList<>();
//        try (InputStream is = new FileInputStream(keyStorePath)) {
//            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
//            keyStore.load(is, keyStorePassword.toCharArray());
//
//            X509Certificate caCertificate = (X509Certificate) keyStore.getCertificate(caAlias);
//            Enumeration<String> aliases = keyStore.aliases();
//            while (aliases.hasMoreElements()) {
//                String alias = aliases.nextElement();
//                Certificate certificate = keyStore.getCertificate(alias);
//                if (certificate instanceof X509Certificate) {
//                    X509Certificate x509Certificate = (X509Certificate) certificate;
//                    if (isSignedBy(x509Certificate, caCertificate)) {
//                        certificates.add(x509Certificate);
//                    }
//                }
//            }
//        }
//
//        return certificates;
//    }
//
//    /**
//     * Checks if a certificate is signed by a given CA certificate.
//     *
//     * @param certificate The certificate to check
//     * @param caCertificate The CA certificate to verify against
//     * @return true if the certificate is signed by the given CA certificate, false otherwise
//     */
//    public static boolean isSignedBy(X509Certificate certificate, X509Certificate caCertificate) {
//        try {
//            certificate.verify(caCertificate.getPublicKey());
//            return true;
//        } catch (Exception e) {
//            return false;
//        }
//    }
//
public static List<X509Certificate> getAllCertificatesSignedByCA(String caAlias, String keyStorePath, String keyStorePassword) throws Exception {
    List<X509Certificate> certificates = new ArrayList<>();
    List<X509Certificate> newCertificates = new ArrayList<>();
    certificates.addAll(getCertificatesSignedByCA(caAlias, keyStorePath, keyStorePassword));

    for (int i = 0; i < certificates.size(); i++) {
        X509Certificate certificate = certificates.get(i);
        String alias = certificate.getSubjectX500Principal().getName();
        List<X509Certificate> signedCertificates = getAllCertificatesSignedByCA(alias, keyStorePath, keyStorePassword);
        for (X509Certificate signedCertificate : signedCertificates) {
            if (!certificates.contains(signedCertificate)) {
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
                if (isSignedBy(x509Certificate, certificate)) {
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
}
